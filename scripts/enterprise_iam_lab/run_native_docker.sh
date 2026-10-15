#!/usr/bin/env bash
# Disposable NATIVE-APPROVED synthetic IAM consume -> real Docker mTLS target.
# No production credentials, durable native service, cloud provider or customer IAM.
set -Eeuo pipefail
cd "$(dirname "$0")/../.."

command -v docker >/dev/null
command -v openssl >/dev/null
command -v python3 >/dev/null
umask 077

# #2375 baseline stays memory-only. PostgreSQL is explicitly opt-in.
if [[ "${LAB_NATIVE_DURABLE_PG:-0}" == "1" ]]; then
  [[ "${VERITAS_DATABASE_URL:-}" == postgresql://* || "${VERITAS_DATABASE_URL:-}" == postgresql+psycopg://* ]] ||
    { echo "REAL_NATIVE_POSTGRES_REQUIRED" >&2; exit 2; }
  IAM_NATIVE_ISSUE_ARGS=(--durable-postgres)
  IAM_NATIVE_VERIFY_ARGS=(--require-native-postgres)
elif [[ "${LAB_NATIVE_DURABLE_PG:-0}" == "0" ]]; then
  IAM_NATIVE_ISSUE_ARGS=()
  IAM_NATIVE_VERIFY_ARGS=()
else
  echo "INVALID_NATIVE_CONSUMPTION_MODE" >&2
  exit 2
fi

export LAB_UID="$(id -u)"
export LAB_GID="$(id -g)"
export LAB_PROJECT="veritas-iam-native-$(date +%s)-${BASHPID}"
LAB_TMP="$(mktemp -d)"
export LAB_CERT_DIR="$LAB_TMP/certs"
export LAB_STATE_DIR="$LAB_TMP/state"
export LAB_TRUST_DIR="$LAB_TMP/trust"
export LAB_PERMIT_DIR="$LAB_TMP/permits"
export LAB_ISSUER_DIR="$LAB_TMP/native-issuer-private"
REPORT_DIR="${LAB_REPORT_DIR:-artifacts/isolated-enterprise-iam-native-docker/latest}"
if [[ "${LAB_NATIVE_DURABLE_PG:-0}" == "1" ]]; then
  [[ -n "${LAB_REPORT_DIR:-}" ]] ||
    { echo "DEDICATED_DURABLE_EVIDENCE_DIR_REQUIRED" >&2; exit 2; }
fi
mkdir -p "$LAB_CERT_DIR"/{server,scoped,unscoped,public} \
  "$LAB_STATE_DIR" "$LAB_TRUST_DIR" "$LAB_PERMIT_DIR" "$LAB_ISSUER_DIR" "$REPORT_DIR"
chmod 0700 "$LAB_TMP" "$LAB_CERT_DIR" "$LAB_STATE_DIR" "$LAB_TRUST_DIR" "$LAB_PERMIT_DIR" "$LAB_ISSUER_DIR" "$LAB_CERT_DIR"/{server,scoped,unscoped,public}

COMPOSE=(docker compose -f compose.enterprise-iam-permit-transport.yml -p "$LAB_PROJECT")
cleanup() {
  "${COMPOSE[@]}" --profile probes down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$LAB_TMP"
}
trap cleanup EXIT

# The ephemeral NATIVE issuer key is stored ONLY in a private host tempdir,
# never mounted on the agent, executor, or IAM target. Target gets public PEM.
python3 scripts/enterprise_iam_lab/native_docker_issuer.py \
  --phase prepare --issuer-dir "$LAB_ISSUER_DIR" --trust-dir "$LAB_TRUST_DIR" \
  > "$REPORT_DIR/native_issuer_prepare.json"

# Disposable TLS CA and leaf credentials. CA PRIVATE KEY is never mounted.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$LAB_TMP/ca.key" -out "$LAB_TMP/ca.crt" \
  -subj "/CN=VERITAS disposable synthetic IAM permit transport CA" >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -keyout "$LAB_CERT_DIR/server/server.key" \
  -out "$LAB_TMP/server.csr" -subj "/CN=iam-target" >/dev/null 2>&1
printf 'subjectAltName=DNS:iam-target\nextendedKeyUsage=serverAuth\n' > "$LAB_TMP/server.ext"
openssl x509 -req -days 1 -in "$LAB_TMP/server.csr" -CA "$LAB_TMP/ca.crt" \
  -CAkey "$LAB_TMP/ca.key" -CAcreateserial -out "$LAB_CERT_DIR/server/server.crt" \
  -extfile "$LAB_TMP/server.ext" >/dev/null 2>&1

for actor in scoped-executor unscoped-probe; do
  leaf=scoped
  if [[ "$actor" == unscoped-probe ]]; then leaf=unscoped; fi
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$LAB_CERT_DIR/$leaf/client.key" -out "$LAB_TMP/$leaf.csr" \
    -subj "/CN=$actor" >/dev/null 2>&1
  printf 'extendedKeyUsage=clientAuth\n' > "$LAB_TMP/$leaf.ext"
  openssl x509 -req -days 1 -in "$LAB_TMP/$leaf.csr" \
    -CA "$LAB_TMP/ca.crt" -CAkey "$LAB_TMP/ca.key" -CAcreateserial \
    -out "$LAB_CERT_DIR/$leaf/client.crt" \
    -extfile "$LAB_TMP/$leaf.ext" >/dev/null 2>&1
done
for leaf in server scoped unscoped public; do
  cp "$LAB_TMP/ca.crt" "$LAB_CERT_DIR/$leaf/ca.crt"
done
chmod 0600 "$LAB_TMP/ca.key" "$LAB_CERT_DIR/server/server.key" \
  "$LAB_CERT_DIR/scoped/client.key" "$LAB_CERT_DIR/unscoped/client.key"
chmod 0644 "$LAB_TRUST_DIR/permit-public.pem"

"${COMPOSE[@]}" --profile probes config --format json > "$LAB_TMP/config.json"
python3 scripts/enterprise_iam_lab/verify_transport.py \
  --phase topology --compose "$LAB_TMP/config.json" \
  --report-dir "$REPORT_DIR"

# Only Docker build needs network to retrieve a pinned public package.
# Runtime containers attach ONLY to 'internal: true' Docker networks.
"${COMPOSE[@]}" build --pull iam-target
"${COMPOSE[@]}" up -d --wait --timeout 120 iam-target
TARGET_CID="$("${COMPOSE[@]}" ps -q iam-target)"
test -n "$TARGET_CID"
docker inspect "$TARGET_CID" > "$LAB_TMP/inspect.json"
export LAB_TARGET_IP
LAB_TARGET_IP="$(python3 - "$LAB_TMP/inspect.json" <<'PY'
import json, sys
container = json.load(open(sys.argv[1], encoding="utf-8"))[0]
nets = container["NetworkSettings"]["Networks"]
assert len(nets) == 1
name, data = next(iter(nets.items()))
assert name.endswith("_effect_net") and data["IPAddress"]
assert not container["HostConfig"]["PortBindings"]
print(data["IPAddress"])
PY
)"

# A scoped request WITHOUT any permit must be rejected, while zero target
# effects and zero consumptions remain present before genuine native issuance.
LAB_CASE=missing-permit "${COMPOSE[@]}" --profile probes run --rm --no-deps -T scoped-executor \
  > "$REPORT_DIR/missing_permit.json"
"${COMPOSE[@]}" --profile probes run --rm --no-deps -T agent-direct \
  > "$REPORT_DIR/agent_direct.json"

python3 scripts/enterprise_iam_lab/verify_native_docker.py \
  --phase pre-native --compose "$LAB_TMP/config.json" \
  --database "$LAB_STATE_DIR/iam.sqlite3" --report-dir "$REPORT_DIR" \
  "${IAM_NATIVE_VERIFY_ARGS[@]}"

# CRITICAL: issue native signed approval + consume ONLY when Docker target is
# healthy and scoped executor is ready; native authorization has a tiny
# real-clock validity window. Issuer and signer are NOT a Docker service.
python3 scripts/enterprise_iam_lab/native_docker_issuer.py \
  --phase issue --issuer-dir "$LAB_ISSUER_DIR" --trust-dir "$LAB_TRUST_DIR" \
  --permit-dir "$LAB_PERMIT_DIR" --evidence-dir "$REPORT_DIR" \
  "${IAM_NATIVE_ISSUE_ARGS[@]}" \
  > "$REPORT_DIR/native_issuer_run.json"

# Keep ALLOW and replay IMMEDIATELY after native consume, before secondary
# probes, to avoid substituting a longer-lived synthetic permit.
LAB_CASE=allow "${COMPOSE[@]}" --profile probes run --rm --no-deps -T scoped-executor \
  > "$REPORT_DIR/allow.json"
LAB_CASE=replay "${COMPOSE[@]}" --profile probes run --rm --no-deps -T scoped-executor \
  > "$REPORT_DIR/replay.json"

LAB_CASE=tamper "${COMPOSE[@]}" --profile probes run --rm --no-deps -T scoped-executor \
  > "$REPORT_DIR/tampered.json"
LAB_CASE=wrong-signer "${COMPOSE[@]}" --profile probes run --rm --no-deps -T scoped-executor \
  > "$REPORT_DIR/wrong_signer.json"
"${COMPOSE[@]}" --profile probes run --rm --no-deps -T tls-probe \
  > "$REPORT_DIR/no_client_cert.json"
"${COMPOSE[@]}" --profile probes run --rm --no-deps -T unscoped-probe \
  > "$REPORT_DIR/unscoped.json"

python3 scripts/enterprise_iam_lab/verify_native_docker.py \
  --phase post-native --compose "$LAB_TMP/config.json" \
  --database "$LAB_STATE_DIR/iam.sqlite3" \
  --trust-dir "$LAB_TRUST_DIR" --permit-dir "$LAB_PERMIT_DIR" \
  --report-dir "$REPORT_DIR" \
  --source-sha "$(git rev-parse HEAD)" \
  --expected-sha "${GITHUB_SHA:-$(git rev-parse HEAD)}" \
  "${IAM_NATIVE_VERIFY_ARGS[@]}"
