#!/usr/bin/env bash
# Disposable infrastructure-only bypass probes. Does not call any provider API.
set -Eeuo pipefail
cd "$(dirname "$0")/../.."

command -v docker >/dev/null
command -v openssl >/dev/null
command -v python3 >/dev/null

export LAB_UID="$(id -u)"
export LAB_GID="$(id -g)"
export LAB_PROJECT="veritas-iam-$(date +%s)-$$"
LAB_TMP="$(mktemp -d)"
export LAB_CERT_DIR="$LAB_TMP/certs"
export LAB_STATE_DIR="$LAB_TMP/state"
REPORT_DIR="${LAB_REPORT_DIR:-artifacts/isolated-enterprise-iam-infra/latest}"
mkdir -p "$LAB_CERT_DIR"/{server,public,unscoped} "$LAB_STATE_DIR" "$REPORT_DIR"
chmod 0700 "$LAB_TMP" "$LAB_CERT_DIR" "$LAB_CERT_DIR"/{server,public,unscoped} "$LAB_STATE_DIR"
COMPOSE=(docker compose -f compose.enterprise-iam-lab.yml -p "$LAB_PROJECT")
cleanup() {
  "${COMPOSE[@]}" --profile probes down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$LAB_TMP"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$LAB_TMP/ca.key" -out "$LAB_TMP/ca.crt" \
  -subj "/CN=VERITAS disposable synthetic IAM lab CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$LAB_CERT_DIR/server/server.key" \
  -out "$LAB_TMP/server.csr" -subj "/CN=iam-target" >/dev/null 2>&1
printf 'subjectAltName=DNS:iam-target\nextendedKeyUsage=serverAuth\n' > "$LAB_TMP/server.ext"
openssl x509 -req -days 1 -in "$LAB_TMP/server.csr" \
  -CA "$LAB_TMP/ca.crt" -CAkey "$LAB_TMP/ca.key" -CAcreateserial \
  -out "$LAB_CERT_DIR/server/server.crt" \
  -extfile "$LAB_TMP/server.ext" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$LAB_CERT_DIR/unscoped/client.key" -out "$LAB_TMP/client.csr" \
  -subj "/CN=unscoped-probe" >/dev/null 2>&1
printf 'extendedKeyUsage=clientAuth\n' > "$LAB_TMP/client.ext"
openssl x509 -req -days 1 -in "$LAB_TMP/client.csr" \
  -CA "$LAB_TMP/ca.crt" -CAkey "$LAB_TMP/ca.key" -CAcreateserial \
  -out "$LAB_CERT_DIR/unscoped/client.crt" -extfile "$LAB_TMP/client.ext" >/dev/null 2>&1
cp "$LAB_TMP/ca.crt" "$LAB_CERT_DIR/server/ca.crt"
cp "$LAB_TMP/ca.crt" "$LAB_CERT_DIR/public/ca.crt"
cp "$LAB_TMP/ca.crt" "$LAB_CERT_DIR/unscoped/ca.crt"
chmod 0600 "$LAB_TMP/ca.key" "$LAB_CERT_DIR/server/server.key" "$LAB_CERT_DIR/unscoped/client.key"

"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" up -d --wait --timeout 120 iam-target
TARGET_CID="$("${COMPOSE[@]}" ps -q iam-target)"
test -n "$TARGET_CID"
docker inspect "$TARGET_CID" > "$LAB_TMP/target-inspect.json"
"${COMPOSE[@]}" --profile probes config --format json > "$LAB_TMP/config.json"
export LAB_TARGET_IP
LAB_TARGET_IP="$(python3 - "$LAB_TMP/target-inspect.json" <<'PY'
import json, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))[0]
networks = record["NetworkSettings"]["Networks"]
ips = [entry["IPAddress"] for name, entry in networks.items() if name.endswith("_effect_net")]
assert len(ips) == 1 and ips[0]
print(ips[0])
PY
)"
python3 - "$LAB_TMP/config.json" "$LAB_TMP/target-inspect.json" "$REPORT_DIR/topology.json" <<'PY'
import json, sys
config = json.load(open(sys.argv[1], encoding="utf-8"))
info = json.load(open(sys.argv[2], encoding="utf-8"))[0]
services = config["services"]
def networks(service):
    value = services[service]["networks"]
    return sorted(value if isinstance(value, list) else value.keys())
assert networks("iam-target") == ["effect_net"]
assert networks("agent-direct") == ["agent_net"]
assert networks("tls-probe") == ["effect_net"]
assert networks("unscoped-probe") == ["effect_net"]
assert not services["iam-target"].get("ports")
assert services["iam-target"]["environment"]["LAB_ALLOW_MUTATIONS"] == "0"
assert set(info["NetworkSettings"]["Networks"]) == {
    name for name in info["NetworkSettings"]["Networks"] if name.endswith("_effect_net")
}
payload = {
    "target_no_host_published_ports": True,
    "agent_networks": networks("agent-direct"),
    "target_networks": networks("iam-target"),
    "tls_probe_networks": networks("tls-probe"),
    "rbac_probe_networks": networks("unscoped-probe"),
    "network_internal": {
        name: bool(config["networks"][name]["internal"]) for name in ("agent_net", "effect_net")
    },
    "mutations_enabled": False,
    "same_target_container": info["Id"][:12],
}
with open(sys.argv[3], "w", encoding="utf-8") as fd:
    json.dump(payload, fd, sort_keys=True, indent=2)
PY

# First prove that the target is reachable with a trusted but UNscoped
# certificate, before judging TCP errors as network or TLS denials.
"${COMPOSE[@]}" --profile probes run --rm --no-deps -T unscoped-probe > "$REPORT_DIR/deny_04.json"
"${COMPOSE[@]}" --profile probes run --rm --no-deps -T tls-probe > "$REPORT_DIR/deny_03.json"
"${COMPOSE[@]}" --profile probes run --rm --no-deps -T agent-direct > "$REPORT_DIR/deny_02.json"

python3 scripts/enterprise_iam_lab/verify_infra.py \
  --evidence-dir "$REPORT_DIR" --database "$LAB_STATE_DIR/iam.sqlite3" \
  --source-sha "$(git rev-parse HEAD)" \
  --expected-sha "${GITHUB_SHA:-$(git rev-parse HEAD)}"
