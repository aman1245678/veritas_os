#!/usr/bin/env python3
"""Strict, sanitized verifier for real isolated Docker permit transport evidence.

A claimed HTTP 201 alone is insufficient. This verifier checks network
config, negative observations, SQLite atomic state and source SHA. It does
NOT verify native authorization and must never claim ALLOW_01 PROVEN.
"""
from __future__ import annotations

import argparse
import errno
import json
from pathlib import Path
import re
import sqlite3

PATH = "/v1/iam/users/contractor-001/roles"
EXPECTED_NETWORKS = {
    "iam-target": ["effect_net"],
    "scoped-executor": ["effect_net"],
    "unscoped-probe": ["effect_net"],
    "tls-probe": ["effect_net"],
    "agent-direct": ["agent_net"],
}
NEGATIVES = {
    "missing_permit.json": ("missing-permit", 400, "invalid_mutation"),
    "tampered.json": ("tamper", 403, "permit_denied"),
    "wrong_signer.json": ("wrong-signer", 403, "permit_denied"),
    "unscoped.json": ("unscoped", 403, "target_scope_denied"),
}
POSITIVES = {
    "allow.json": ("allow", 201, "committed"),
    "replay.json": ("replay", 409, "permit_replayed"),
}


def _load(path: Path) -> dict:
    result = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(result, dict), "observation must be a JSON object"
    return result


def _networks(service: dict) -> list[str]:
    value = service["networks"]
    return sorted(value if isinstance(value, list) else value.keys())


def verify_topology(config: dict) -> dict:
    services = config["services"]
    assert set(EXPECTED_NETWORKS).issubset(set(services))
    assert all(
        _networks(services[name]) == expected
        for name, expected in EXPECTED_NETWORKS.items()
    ), "unwanted target/agent adjacency"
    assert all(
        config["networks"][network]["internal"] is True
        for network in ("agent_net", "effect_net")
    )
    assert all(not services[name].get("ports") for name in EXPECTED_NETWORKS)
    assert all(
        services[name].get("read_only") is True
        and "ALL" in services[name].get("cap_drop", [])
        and "no-new-privileges:true" in services[name].get("security_opt", [])
        for name in EXPECTED_NETWORKS
    )
    target = services["iam-target"]
    assert target["environment"]["LAB_ALLOW_MUTATIONS"] == "1"
    assert target["environment"]["LAB_TEST_PERMIT_GATE"] == "1"
    assert target["environment"]["LAB_PERMIT_VERIFIER_PEM"] == "/run/lab/trust/permit-public.pem"
    mounts = {
        name: {v["target"] for v in services[name]["volumes"]}
        for name in EXPECTED_NETWORKS
    }
    assert "/run/lab/trust" in mounts["iam-target"]
    assert "/run/lab/trust" not in mounts["scoped-executor"]
    assert "/run/lab/certs" in mounts["scoped-executor"]
    assert "/run/lab/permits" in mounts["scoped-executor"]
    assert "/run/lab/certs" not in mounts["agent-direct"]
    assert "/run/lab/permits" not in mounts["agent-direct"]
    assert "/run/lab/trust" not in mounts["agent-direct"]
    assert "/run/lab/state" not in mounts["scoped-executor"]
    assert "/run/lab/state" not in mounts["agent-direct"]
    for name in ("scoped-executor", "unscoped-probe", "tls-probe", "agent-direct"):
        assert all(v.get("read_only", True) for v in services[name].get("volumes", []))
    return {
        "result": "PASS", "phase": "topology",
        "target_no_host_ports": True,
        "agent_networks": _networks(services["agent-direct"]),
        "target_networks": _networks(target),
        "all_runtime_networks_internal": True,
        "target_verifier_key_not_mounted_on_executor_or_agent": True,
        "scoped_client_credential_not_mounted_on_agent": True,
        "native_veritas_authorization_exercised": False,
        "production_claim": False,
    }


def _require_http(observation: dict, case: str, status: int, reason: str) -> None:
    assert observation["case_id"] == case
    assert observation["result"] == "PASS"
    assert observation["observed_failure_kind"] == "TARGET_HTTP_RESPONSE"
    assert (observation["observed_http_status"], observation["observed_reason"]) == (
        status, reason
    )
    assert observation["target_path"] == PATH
    assert observation["real_tls_socket"] is True
    assert observation["native_veritas_authorization_exercised"] is False
    assert observation["production_claim"] is False


def verify_denials(folder: Path) -> None:
    for filename, (case, status, reason) in NEGATIVES.items():
        _require_http(_load(folder / filename), case, status, reason)
    certless = _load(folder / "no_client_cert.json")
    assert certless["case_id"] == "no-client-cert"
    assert certless["result"] == "PASS"
    assert certless["observed_failure_kind"] == "TLS_CLIENT_CERT_REJECTED"
    assert certless["observed_http_status"] is None
    assert certless["real_tls_socket"] is True
    assert certless["production_claim"] is False

    agent = _load(folder / "agent_direct.json")
    assert agent["case_id"] == "agent-direct"
    assert agent["result"] == "PASS"
    assert agent["observed_http_status"] is None
    assert agent["real_tls_socket"] is False
    assert agent["target_port"] == 8443
    assert agent["socket_errno"] in (
        errno.ENETUNREACH, errno.EHOSTUNREACH,
        errno.EACCES, errno.EPERM, errno.ETIMEDOUT,
    )
    assert agent["socket_errno_name"] == errno.errorcode[agent["socket_errno"]]


def _target_state(database: Path) -> dict:
    assert database.is_file(), "target SQLite database not found"
    # Read with sqlite3 read-only URI; do not accidentally create a DB.
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as conn:
        grants = conn.execute("SELECT user_id, role FROM grants ORDER BY user_id").fetchall()
        uses = conn.execute(
            "SELECT permit_id, authorization_id, execution_intent_id,"
            "request_id, actor, audit_id FROM permit_consumptions"
        ).fetchall()
        audit = conn.execute(
            "SELECT id, actor, status, reason FROM audit ORDER BY id"
        ).fetchall()
    return {"grants": grants, "consumptions": uses, "audit": audit}


def verify(folder: Path, config: dict, database: Path | None,
           phase: str, source_sha: str = "", expected_sha: str = "") -> dict:
    topology = verify_topology(config)
    if phase == "topology":
        return topology

    assert database is not None
    verify_denials(folder)
    state = _target_state(database)
    if phase == "pre-allow":
        assert state["grants"] == []
        assert state["consumptions"] == []
        assert not any(x[2] == 201 for x in state["audit"])
        return {
            "result": "PASS", "phase": phase, "observed_iam_grants": 0,
            "target_denials_observed": True, "native_veritas_authorization_exercised": False,
            "production_claim": False,
        }

    assert phase == "post-allow"
    assert re.fullmatch(r"[0-9a-f]{40}", source_sha)
    assert source_sha == expected_sha, "source / expected CI SHA mismatch"
    for filename, (case, status, reason) in POSITIVES.items():
        _require_http(_load(folder / filename), case, status, reason)

    assert state["grants"] == [("contractor-001", "admin")]
    assert len(state["consumptions"]) == 1
    use = state["consumptions"][0]
    assert use[0].startswith("transport-only:permit:")
    assert use[1].startswith("transport-only:authorization:")
    assert use[2].startswith("transport-only:intent:")
    assert use[3].startswith("transport-only:request:")
    assert use[4] == "scoped-executor"
    successes = [row for row in state["audit"] if row[2] == 201]
    assert successes == [(use[5], "scoped-executor", 201, "committed")]
    assert len([row for row in state["audit"] if row[2] == 409]) == 1
    assert ("unscoped-probe", 403, "target_scope_denied") in [
        row[1:] for row in state["audit"]
    ]
    assert len([row for row in state["audit"] if row[2] == 403 and row[3] == "permit_denied"]) == 2
    assert len([row for row in state["audit"] if row[2] == 400 and row[3] == "invalid_mutation"]) == 1

    return {
        "result": "PASS",
        "phase": phase,
        "proof_status": "REAL_DOCKER_MTLS_TRANSPORT_ONLY_NOT_NATIVE_IAM_ALLOW_PROOF",
        "source_sha": source_sha,
        "expected_sha": expected_sha,
        "real_mtls_allowed_exactly_once": True,
        "replay_rejected": True,
        "agent_direct_ip_network_denied": True,
        "client_cert_required": True,
        "unscoped_mtls_denied": True,
        "tampered_or_untrusted_permit_denied": True,
        "observed_iam_grants": 1,
        "observed_permit_consumptions": 1,
        "observed_success_audit_count": len(successes),
        "native_veritas_authorization_exercised": False,
        "production_claim": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("topology", "pre-allow", "post-allow"), required=True)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--source-sha", default="")
    parser.add_argument("--expected-sha", default="")
    args = parser.parse_args()
    result = verify(
        args.report_dir, _load(args.compose), args.database,
        args.phase, args.source_sha, args.expected_sha,
    )
    path = args.report_dir / ("verification_" + args.phase.replace("-", "_") + ".json")
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
