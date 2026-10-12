#!/usr/bin/env python3
"""Independent, fail-closed verifier for infrastructure-only denial probes."""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
from pathlib import Path
import re
import sqlite3


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path.name}")
    return value


def verify(directory: Path, database: Path, source_sha: str, expected_sha: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha) or source_sha != expected_sha:
        raise ValueError("checkout SHA mismatches expected source")
    topology = load(directory / "topology.json")
    assert topology["target_no_host_published_ports"] is True
    assert topology["agent_networks"] == ["agent_net"]
    assert topology["target_networks"] == ["effect_net"]
    assert topology["tls_probe_networks"] == ["effect_net"]
    assert topology["rbac_probe_networks"] == ["effect_net"]
    assert topology["network_internal"] == {"agent_net": True, "effect_net": True}
    assert topology["mutations_enabled"] is False
    assert len(topology["same_target_container"]) == 12

    expected = {
        "deny_02.json": ("DENY_02", "TCP", None),
        "deny_03.json": ("DENY_03", "TLS_CLIENT_IDENTITY_REJECTED", None),
        "deny_04.json": ("DENY_04", "TARGET_POLICY_403", 403),
    }
    cases = []
    for filename, (case_id, failure_kind, http_code) in expected.items():
        data = load(directory / filename)
        assert data["case_id"] == case_id
        assert data["result"] == "PASS" and data["observed"] == "DENIED"
        assert data["production_claim"] is False
        assert data["veritas_authorization_exercised"] is False
        assert data["target"] == "/v1/iam/users/contractor-001/roles"
        assert data["observed_http_status"] == http_code
        if case_id == "DENY_02":
            assert data["observed_failure_kind"] in {"OSError", "TimeoutError", "PermissionError"}
            assert data["socket_errno"] in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM, errno.ETIMEDOUT}
            if data["observed_failure_kind"] == "TimeoutError":
                assert data["socket_errno"] == errno.ETIMEDOUT
            if data["observed_failure_kind"] == "PermissionError":
                assert data["socket_errno"] in {errno.EACCES, errno.EPERM}
            assert data["socket_errno_name"] == errno.errorcode[data["socket_errno"]]
            assert data["target_port"] == 8443
            assert isinstance(data["target_ip"], str) and data["target_ip"]
        else:
            assert data["observed_failure_kind"] == failure_kind
            if case_id == "DENY_03":
                assert data["tls_exception_type"] in {"SSLError", "SSLEOFError", "RemoteDisconnected", "ConnectionResetError"}
                assert "tls_reason" in data and "tls_errno" in data
        cases.append({"case_id": case_id, "result": "PASS", "denial": data["observed_failure_kind"]})

    # Read the target-owned DB directly, not the requester's returned JSON.
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        grants = connection.execute("SELECT user_id, role FROM grants ORDER BY user_id").fetchall()
        audit = connection.execute("SELECT id, actor, status, reason FROM audit ORDER BY id").fetchall()
    assert grants == [], "denial cases must never create IAM effects"
    assert len(audit) == 1, "exactly one network-reachable policy denial should be audited"
    assert audit[0][1:] == ("unscoped-probe", 403, "target_scope_denied")
    (directory / "independent_target_snapshot.json").write_text(
        json.dumps({"grants": grants, "grant_count": 0, "audit_count": len(audit)}, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    (directory / "target_audit.jsonl").write_text(
        "\n".join(json.dumps({"id": row[0], "actor": row[1], "status": row[2], "reason": row[3]}, sort_keys=True)
                  for row in audit) + "\n",
        encoding="utf-8",
    )

    report = {
        "proof": "ISOLATED_IAM_INFRA_EXTERNAL_DENIALS_V1",
        "result": "PASS",
        "proof_status": "INFRA_DENIALS_ONLY_NOT_FULL_VERITAS_PROOF",
        "tested_sha": source_sha,
        "production_claim": False,
        "veritas_authorization_exercised": False,
        "external_api_calls": 0,
        "observed_case_count": len(cases),
        "observed_iam_grants": len(grants),
        "cases": cases,
        "unproven_contract_cases": ["ALLOW_01", "DENY_01", "DENY_05", "DENY_06", "RECON_01"],
    }
    (directory / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    hashed_paths = sorted(directory.glob("*.json")) + [directory / "target_audit.jsonl"]
    manifest = "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in hashed_paths
    )
    (directory / "manifest.sha256").write_text(manifest, encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--expected-sha", required=True)
    args = parser.parse_args()
    report = verify(args.evidence_dir, args.database, args.source_sha, args.expected_sha)
    print(json.dumps({"result": report["result"], "proof": report["proof"], "case_count": report["observed_case_count"], "full_proof": False}, sort_keys=True))


if __name__ == "__main__":
    main()
