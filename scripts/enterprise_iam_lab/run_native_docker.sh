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

# Lost-ack proof requires the durable PostgreSQL path, and is opt-in only.
# Baseline #2375 and #2376 execution remain unchanged.
if [[ "${LAB_NATIVE_LOST_ACK:-0}" == "1" ]]; then
  [[ "${LAB_NATIVE_DURABLE_PG:-0}" == "1" ]] ||
    { echo "LOST_ACK_REQUIRES_NATIVE_POSTGRES" >&2; exit 2; }
  IAM_NATIVE_ISSUE_ARGS+=(--persist-effect-in-flight)
  IAM_NATIVE_VERIFY_ARGS+=(--lost-ack-recovery)
elif [[ "${LAB_NATIVE_LOST_ACK:-0}" != "0" ]]; then
  echo "INVALID_LOST_ACK_MODE" >&2
  exit 2
fi

# #2378 is a separate, explicit, disposable process-crash experiment.
if [[ "${LAB_NATIVE_PROCESS_RESTART:-0}" == "1" ]]; then
  [[ "${LAB_NATIVE_DURABLE_PG:-0}" == "1" && "${LAB_NATIVE_LOST_ACK:-0}" == "1" ]] ||
    { echo "RESTART_REQUIRES_DURABLE_LOST_ACK" >&2; exit 2; }
  IAM_NATIVE_VERIFY_ARGS+=(--process-restart-recovery)
elif [[ "${LAB_NATIVE_PROCESS_RESTART:-0}" != "0" ]]; then
  echo "INVALID_PROCESS_RESTART_MODE" >&2
  exit 2
fi

IAM_FRESHNESS_ARGS=()
# #2381: opt-in request-bound signed target evidence, NEVER a generic
# authenticated receipt freshness or production replay-prevention claim.
if [[ "${LAB_TARGET_ACK_FRESHNESS:-0}" == "1" ]]; then
  [[ "${LAB_NATIVE_DURABLE_PG:-0}" == "1" &&
     "${LAB_NATIVE_LOST_ACK:-0}" == "1" &&
     "${LAB_TARGET_READONLY_ACK:-0}" == "1" &&
     "${LAB_NATIVE_SIGNED_ACK_RECONCILE:-0}" == "1" &&
     "${LAB_NATIVE_PROCESS_RESTART:-0}" == "0" ]] ||
    { echo "CHALLENGE_BOUND_ACK_REQUIRES_REAL_PG_LOST_ACK_SIGNED_MTLS_CAS" >&2; exit 2; }
  IAM_NATIVE_VERIFY_ARGS+=(--ack-freshness)
  IAM_FRESHNESS_ARGS=(--freshness-challenge)
elif [[ "${LAB_TARGET_ACK_FRESHNESS:-0}" != "0" ]]; then
  echo "INVALID_ACK_FRESHNESS_MODE" >&2
  exit 2
fi

# #2379's known-response read-only mode stays unchanged by default.
# #2380 alone may combine it with #2377's genuine lost-ACK/UNKNOWN flow.
if [[ "${LAB_NATIVE_SIGNED_ACK_RECONCILE:-0}" == "1" ]]; then
  [[ "${LAB_TARGET_READONLY_ACK:-0}" == "1" &&
     "${LAB_NATIVE_DURABLE_PG:-0}" == "1" &&
     "${LAB_NATIVE_LOST_ACK:-0}" == "1" &&
     "${LAB_NATIVE_PROCESS_RESTART:-0}" == "0" ]] ||
    { echo "SIGNED_ACK_RECONCILIATION_REQUIRES_DURABLE_LOST_ACK_AND_READONLY_MTLS" >&2; exit 2; }
  IAM_NATIVE_VERIFY_ARGS+=(--signed-ack-reconciliation)
elif [[ "${LAB_NATIVE_SIGNED_ACK_RECONCILE:-0}" != "0" ]]; then
  echo "INVALID_SIGNED_ACK_RECONCILIATION_MODE" >&2
  exit 2
fi

if [[ "${LAB_TARGET_READONLY_ACK:-0}" == "1" ]]; then
  [[ "${LAB_NATIVE_DURABLE_PG:-0}" == "1" &&
     "${LAB_NATIVE_PROCESS_RESTART:-0}" == "0" ]] ||
    { echo "READONLY_ACK_REQUIRES_DURABLE_AND_NO_PROCESS_RESTART" >&2; exit 2; }
  if [[ "${LAB_NATIVE_LOST_ACK:-0}" == "1" ]]; then
    [[ "${LAB_NATIVE_SIGNED_ACK_RECONCILE:-0}" == "1" ]] ||
      { echo "READONLY_LOST_ACK_REQUIRES_SIGNED_ACK_RECONCILIATION" >&2; exit 2; }
  else
    [[ "${LAB_NATIVE_SIGNED_ACK_RECONCILE:-0}" == "0" ]] ||
      { echo "READONLY_KNOWN_RESPONSE_NOT_RECONCILIATION" >&2; exit 2; }
  fi
elif [[ "${LAB_TARGET_READONLY_ACK:-0}" != "0" ]]; then
  echo "INVALID_READONLY_ACK_MODE" >&2
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

if [[ "${LAB_TARGET_READONLY_ACK:-0}" == "1" ]]; then
  export LAB_READONLY_SIGNER_DIR="$LAB_TMP/ack-private"
  export LAB_READONLY_REF_DIR="$LAB_TMP/readonly-refs"
  mkdir -p "$LAB_READONLY_SIGNER_DIR" "$LAB_READONLY_REF_DIR" "$LAB_CERT_DIR/reader"
  chmod 0700 "$LAB_READONLY_SIGNER_DIR" "$LAB_READONLY_REF_DIR" "$LAB_CERT_DIR/reader"
  python3 scripts/enterprise_iam_lab/target_readonly_receipt.py --generate \
    --private "$LAB_READONLY_SIGNER_DIR/target-private.pem" \
    --public "$LAB_READONLY_REF_DIR/target-ack-public.pem" \
    > "$REPORT_DIR/target_readonly_signer_setup.json"
  COMPOSE=(docker compose -f compose.enterprise-iam-permit-transport.yml \
    -f compose.enterprise-iam-readonly-ack-2379.override.yml -p "$LAB_PROJECT")
else
  COMPOSE=(docker compose -f compose.enterprise-iam-permit-transport.yml -p "$LAB_PROJECT")
fi
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
if [[ "${LAB_TARGET_READONLY_ACK:-0}" == "1" ]]; then
  # Reader identity is separate from scoped-executor mutation identity.
  openssl req -newkey rsa:2048 -nodes -keyout "$LAB_CERT_DIR/reader/client.key" \
    -out "$LAB_TMP/reader.csr" -subj "/CN=reconciliation-reader" >/dev/null 2>&1
  printf 'extendedKeyUsage=clientAuth\n' > "$LAB_TMP/reader.ext"
  openssl x509 -req -days 1 -in "$LAB_TMP/reader.csr" \
    -CA "$LAB_TMP/ca.crt" -CAkey "$LAB_TMP/ca.key" -CAcreateserial \
    -out "$LAB_CERT_DIR/reader/client.crt" -extfile "$LAB_TMP/reader.ext" >/dev/null 2>&1
  chmod 0600 "$LAB_CERT_DIR/reader/client.key"
  cp "$LAB_TMP/ca.crt" "$LAB_CERT_DIR/reader/ca.crt"
fi
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
if [[ "${LAB_NATIVE_LOST_ACK:-0}" == "1" ]]; then
  # One genuine mTLS POST, then deliberately close before reading its reply.
  # Success is NOT inferred from this step. Never retry the mutation.
  LAB_CASE=allow-no-ack "${COMPOSE[@]}" --profile probes run --rm --no-deps -T scoped-executor \
    > "$REPORT_DIR/allow_lost_ack.json"
  # Separate Python interpreter/process: persist a fail-closed UNKNOWN from
  # existing durable IN_FLIGHT, never from the expected success text.
  python3 -m scripts.enterprise_iam_lab.reconcile_native_lost_ack \
    --phase mark-unknown --report-dir "$REPORT_DIR" \
    --trust-dir "$LAB_TRUST_DIR" --permit-dir "$LAB_PERMIT_DIR" \
    --target-database "$LAB_STATE_DIR/iam.sqlite3"
else
  LAB_CASE=allow "${COMPOSE[@]}" --profile probes run --rm --no-deps -T scoped-executor \
    > "$REPORT_DIR/allow.json"
fi
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

if [[ "${LAB_TARGET_READONLY_ACK:-0}" == "1" ]]; then
  # Only the non-authorizing hashed operation reference is mounted on
  # the reader. No signed execution Permit or SQLite file is shared.
  python3 - "$REPORT_DIR/native_issuer_receipt.json" "$LAB_READONLY_REF_DIR/lookup.json" <<'PY'
import json
from pathlib import Path
import sys
receipt = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
Path(sys.argv[2]).write_text(
    json.dumps({"permit_id": receipt["permit_id"]}, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
  if [[ "${LAB_TARGET_ACK_FRESHNESS:-0}" == "1" ]]; then
    # The verifier-side host registers one non-authorizing, random challenge
    # AFTER real native EFFECT_UNKNOWN persistence and BEFORE target GET.
    # This is NOT an authorization, execution token, or proof of global
    # single-use; the signed target observation must match this exact nonce.
    python3 - "$REPORT_DIR/native_issuer_receipt.json" \
        "$REPORT_DIR/iam_reconciliation_mark_unknown.json" \
        "$REPORT_DIR/iam_freshness_challenge.json" \
        "$LAB_READONLY_REF_DIR/challenge.json" <<'PY2381'
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
import sys
receipt = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
unknown = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
assert unknown["effect_state"] == "EFFECT_UNKNOWN"
assert unknown["operation_id"] == receipt["consumption_id"]
payload = {
    "schema": "iam-2381-host-challenge/v1",
    "permit_id": receipt["permit_id"],
    "target_status_before_lookup": "EFFECT_UNKNOWN",
    "challenge": secrets.token_hex(32),
    "issued_at": datetime.now(timezone.utc).isoformat(),
}
for name in sys.argv[3:]:
    Path(name).write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
PY2381
  fi
  LAB_READONLY_CASE=valid "${COMPOSE[@]}" --profile probes run --rm --no-deps -T reconciliation-reader \
    > "$REPORT_DIR/readonly_valid.json"
  LAB_READONLY_CASE=missing "${COMPOSE[@]}" --profile probes run --rm --no-deps -T reconciliation-reader \
    > "$REPORT_DIR/readonly_missing.json"
  "${COMPOSE[@]}" --profile probes run --rm --no-deps -T reconciliation-wrong-scope \
    > "$REPORT_DIR/readonly_wrong_scope.json"
  "${COMPOSE[@]}" --profile probes run --rm --no-deps -T reconciliation-no-cert \
    > "$REPORT_DIR/readonly_no_certificate.json"
  if [[ "${LAB_NATIVE_SIGNED_ACK_RECONCILE:-0}" == "0" ]]; then
    # #2379: known-response receipt-only proof stays strict and unchanged.
    python3 -m scripts.enterprise_iam_lab.verify_readonly_ack \
      --report-dir "$REPORT_DIR" --trust-dir "$LAB_TRUST_DIR" \
      --permit-dir "$LAB_PERMIT_DIR" \
      --target-public-key "$LAB_READONLY_REF_DIR/target-ack-public.pem" \
      --compose-config "$LAB_TMP/config.json"
  fi
fi

if [[ "${LAB_NATIVE_PROCESS_RESTART:-0}" == "1" ]]; then
  # Actual failure injection, NOT a normal exit: an independent Python
  # reconciliation worker checks genuine PostgreSQL UNKNOWN, writes an
  # fsynced checkpoint, then SIGKILLs itself before ANY target lookup.
  if python3 -m scripts.enterprise_iam_lab.native_process_restart_probe \
    --phase sigkill-before-lookup --report-dir "$REPORT_DIR" \
    --trust-dir "$LAB_TRUST_DIR" --permit-dir "$LAB_PERMIT_DIR" \
    --target-database "$LAB_STATE_DIR/iam.sqlite3" \
    --checkpoint "$REPORT_DIR/iam_sigkill_checkpoint.json"; then
    echo "EXPECTED_RECONCILIATION_WORKER_SIGKILL_NOT_OBSERVED" >&2
    exit 2
  else
    IAM_WORKER_EXIT=$?
  fi
  [[ "$IAM_WORKER_EXIT" == "137" ]] ||
    { echo "UNEXPECTED_WORKER_EXIT_NOT_SIGKILL" >&2; exit 2; }
  python3 - "$REPORT_DIR/iam_sigkill_observation.json" "$IAM_WORKER_EXIT" <<'PY'
import json
from pathlib import Path
import sys
assert int(sys.argv[2]) == 137
Path(sys.argv[1]).write_text(json.dumps({
    "observed_exit_code": int(sys.argv[2]),
    "expected_termination_signal": "SIGKILL",
    "production_claim": False
}, sort_keys=True) + "\n", encoding="utf-8")
PY

  # Abruptly stop the ACTUAL target Python process. Start the SAME container
  # with the SAME bind-mounted SQLite, so no replacement execution is needed.
  docker inspect "$TARGET_CID" > "$LAB_TMP/target_before_restart.json"
  docker kill "$TARGET_CID" > /dev/null
  [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET_CID")" == "false" ]] ||
    { echo "TARGET_PROCESS_NOT_STOPPED" >&2; exit 2; }
  docker start "$TARGET_CID" > /dev/null
  "${COMPOSE[@]}" up -d --wait --timeout 120 iam-target
  [[ "$("${COMPOSE[@]}" ps -q iam-target)" == "$TARGET_CID" ]] ||
    { echo "TARGET_CONTAINER_ID_CHANGED_ON_RESTART" >&2; exit 2; }
  docker inspect "$TARGET_CID" > "$LAB_TMP/target_after_restart.json"

  # Fresh process checks the durable UNKNOWN still exists and that original
  # target-owned committed evidence survived SIGKILL and Docker restart.
  # No POST, permit re-issuance or authoritative no-effect assumption.
  python3 -m scripts.enterprise_iam_lab.native_process_restart_probe \
    --phase verify-restart --report-dir "$REPORT_DIR" \
    --trust-dir "$LAB_TRUST_DIR" --permit-dir "$LAB_PERMIT_DIR" \
    --target-database "$LAB_STATE_DIR/iam.sqlite3" \
    --checkpoint "$REPORT_DIR/iam_sigkill_checkpoint.json" \
    --kill-observation "$REPORT_DIR/iam_sigkill_observation.json" \
    --before-inspect "$LAB_TMP/target_before_restart.json" \
    --after-inspect "$LAB_TMP/target_after_restart.json"
fi

if [[ "${LAB_NATIVE_SIGNED_ACK_RECONCILE:-0}" == "1" ]]; then
  # #2380: one fresh reconciliation process uses ONLY the target-signed
  # result obtained via separate mTLS reader; no SQLite path is supplied.
  # Existing native PostgreSQL CAS is the sole durable state transition.
  python3 -m scripts.enterprise_iam_lab.reconcile_signed_target_ack \
    --report-dir "$REPORT_DIR" --trust-dir "$LAB_TRUST_DIR" \
    --permit-dir "$LAB_PERMIT_DIR" \
    --target-public-key "$LAB_READONLY_REF_DIR/target-ack-public.pem" \
    --compose-config "$LAB_TMP/config.json" \
    "${IAM_FRESHNESS_ARGS[@]}"
elif [[ "${LAB_NATIVE_LOST_ACK:-0}" == "1" ]]; then
  # Legacy #2377/#2378 separate-process same-host SQLite reconciliation.
  python3 -m scripts.enterprise_iam_lab.reconcile_native_lost_ack \
    --phase reconcile --report-dir "$REPORT_DIR" \
    --trust-dir "$LAB_TRUST_DIR" --permit-dir "$LAB_PERMIT_DIR" \
    --target-database "$LAB_STATE_DIR/iam.sqlite3"
fi

python3 scripts/enterprise_iam_lab/verify_native_docker.py \
  --phase post-native --compose "$LAB_TMP/config.json" \
  --database "$LAB_STATE_DIR/iam.sqlite3" \
  --trust-dir "$LAB_TRUST_DIR" --permit-dir "$LAB_PERMIT_DIR" \
  --report-dir "$REPORT_DIR" \
  --source-sha "$(git rev-parse HEAD)" \
  --expected-sha "${GITHUB_SHA:-$(git rev-parse HEAD)}" \
  "${IAM_NATIVE_VERIFY_ARGS[@]}"
