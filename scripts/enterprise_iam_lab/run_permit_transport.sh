#!/usr/bin/env bash
# Strict disposable TRANSPORT-ONLY IAM permit execution against real Docker mTLS.
# No production credentials, native issuer, customer IAM, or outbound provider APIs.
set -Eeuo pipefail
cd "$(dirname "$0")/../.."

command -v docker >/dev/null
command -v openssl >/dev/null
command -v python3 >/dev/null
umask 077

export LAB_UID="$(id -u)"
export LAB_GID="$(id -g)"
export LAB_PROJECT="veritas-iam-permit-$(date +%s)-$$"
LAB_TMP="$(mktemp -d)"
export LAB_CERT_DIR="$LAB_TMP/certs"
export LAB_STATE_DIR="$LAB_TMP/state"
export LAB_TRUST_DIR="$LAB_TMP/trust"
export LAB_PERMIT_DIR="$LAB_TMP/permits"
REPORT_DIR="${LAB_REPORT_DIR:-artifacts/isolated-enterprise-iam-permit-transport/latest}"
mkdir -p "$LAB_CERT_DIR"/{server,scoped,unscoped,public} \
  "$LAB_STATE_DIR" "$LAB_TRUST_DIR" "$LAB_PERMIT_DIR" "$REPORT_DIR"
chmod 0700 "$LAB_TMP" "$LAB_CERT_DIR" "$LAB_STATE_DIR" "$LAB_TRUST_DIR" "$LAB_PERMIT_DIR" "$LAB_CERT_DIR"/{server,scoped,unscoped,public}

COMPOSE=(docker compose -f compose.enterprise-iam-permit-transport.yml -p "$LAB_PROJECT")
cleanup() {
  "${COMPOSE[@]}" --profile probes down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$LAB_TMP"
}
trap cleanup EXIT

# In-memory-only ephemeral Ed25519 permit signing key.
python3 scripts/enterprise_iam_lab/transport_fixture.py \
  --trust-directory "$LAB_TRUST_DIR" --permit-directory "$LAB_PERMIT_DIR" \
  > "$REPORT_DIR/synthetic_issuer.json"

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
chmod 0644 "$LAB_TRUST_DIR/permit-public.pem" "$LAB_PERMIT_DIR"/*.json

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

# These real effect_net clients probe a LIVE healthy IAM target.
LAB_CASE=missing-permit "${COMPOSE[@]}" --profile probes run --rm --no-deps -T scoped-executor \
  > "$REPORT_DIR/missing_permit.json"
LAB_CASE=tamper "${COMPOSE[@]}" --profile probes run --rm --no-deps -T scoped-executor \
  > "$REPORT_DIR/tampered.json"
LAB_CASE=wrong-signer "${COMPOSE[@]}" --profile probes run --rm --no-deps -T scoped-executor \
  > "$REPORT_DIR/wrong_signer.json"
"${COMPOSE[@]}" --profile probes run --rm --no-deps -T unscoped-probe \
  > "$REPORT_DIR/unscoped.json"
"${COMPOSE[@]}" --profile probes run --rm --no-deps -T tls-probe \
  > "$REPORT_DIR/no_client_cert.json"
"${COMPOSE[@]}" --profile probes run --rm --no-deps -T agent-direct \
  > "$REPORT_DIR/agent_direct.json"

python3 scripts/enterprise_iam_lab/verify_transport.py \
  --phase pre-allow --compose "$LAB_TMP/config.json" \
  --database "$LAB_STATE_DIR/iam.sqlite3" --report-dir "$REPORT_DIR"

# A real scoped mTLS client, holding a valid synthetically signed permit,
# causes ONE target-owned grant transaction. A repeat MUST be refused.
LAB_CASE=allow "${COMPOSE[@]}" --profile probes run --rm --no-deps -T scoped-executor \
  > "$REPORT_DIR/allow.json"
LAB_CASE=replay "${COMPOSE[@]}" --profile probes run --rm --no-deps -T scoped-executor \
  > "$REPORT_DIR/replay.json"

python3 scripts/enterprise_iam_lab/verify_transport.py \
  --phase post-allow --compose "$LAB_TMP/config.json" \
  --database "$LAB_STATE_DIR/iam.sqlite3" --report-dir "$REPORT_DIR" \
  --source-sha "$(git rev-parse HEAD)" \
  --expected-sha "${GITHUB_SHA:-$(git rev-parse HEAD)}"
