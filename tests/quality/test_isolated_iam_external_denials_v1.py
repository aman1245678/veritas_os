"""Negative verification tests for the NOT-YET-FULL-VERITAS IAM infrastructure proof."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.enterprise_iam_lab import target_service
from scripts.enterprise_iam_lab.verify_infra import verify

SHA = "a" * 40


def _write(folder: Path, filename: str, obj: dict) -> None:
    (folder / filename).write_text(json.dumps(obj), encoding="utf-8")


def _fixture(tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
    database = tmp_path / "db.sqlite3"
    monkeypatch.setattr(target_service, "DB_PATH", database)
    target_service.init_db()
    target_service.record("unscoped-probe", 403, "target_scope_denied")
    _write(tmp_path, "topology.json", {
        "target_no_host_published_ports": True,
        "agent_networks": ["agent_net"],
        "target_networks": ["effect_net"],
        "tls_probe_networks": ["effect_net"],
        "rbac_probe_networks": ["effect_net"],
        "network_internal": {"agent_net": True, "effect_net": True},
        "mutations_enabled": False,
        "same_target_container": "123456789abc",
    })
    for name, case, kind, http in [
        ("deny_02.json", "DENY_02", "TimeoutError", None),
        ("deny_03.json", "DENY_03", "TLS_CLIENT_IDENTITY_REJECTED", None),
        ("deny_04.json", "DENY_04", "TARGET_POLICY_403", 403),
    ]:
        _write(tmp_path, name, {
            "case_id": case, "result": "PASS", "observed": "DENIED",
            "observed_failure_kind": kind, "observed_http_status": http,
            "target": target_service.TARGET_PATH, "production_claim": False,
            "veritas_authorization_exercised": False,
        })
    return tmp_path, database


def test_no_scope_has_no_grant_authority() -> None:
    assert not target_service.scope_allows("unscoped-probe")
    assert not target_service.scope_allows("")
    assert not target_service.scope_allows("unknown")
    assert target_service.scope_allows("scoped-executor")
    assert target_service.client_cn({"subject": ((("commonName", "unscoped-probe"),),)}) == "unscoped-probe"


def test_good_fixture_can_only_claim_three_infrastructure_denials(tmp_path, monkeypatch) -> None:
    folder, db = _fixture(tmp_path, monkeypatch)
    result = verify(folder, db, SHA, SHA)
    assert result["result"] == "PASS"
    assert result["proof_status"] == "INFRA_DENIALS_ONLY_NOT_FULL_VERITAS_PROOF"
    assert result["veritas_authorization_exercised"] is False
    assert result["production_claim"] is False
    assert result["observed_iam_grants"] == 0
    assert len(result["unproven_contract_cases"]) == 5


def test_forged_network_denial_is_rejected(tmp_path, monkeypatch) -> None:
    folder, db = _fixture(tmp_path, monkeypatch)
    payload = json.loads((folder / "deny_02.json").read_text())
    payload["observed_failure_kind"] = "TCP_CONNECTED"
    _write(folder, "deny_02.json", payload)
    with pytest.raises(AssertionError):
        verify(folder, db, SHA, SHA)


def test_missing_target_policy_audit_fails_closed(tmp_path, monkeypatch) -> None:
    folder, db = _fixture(tmp_path, monkeypatch)
    with target_service.sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM audit")
    with pytest.raises(AssertionError):
        verify(folder, db, SHA, SHA)


def test_unexpected_target_mutation_fails_closed(tmp_path, monkeypatch) -> None:
    folder, db = _fixture(tmp_path, monkeypatch)
    with target_service.sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO grants (user_id, role) VALUES (?, ?)", ("contractor-001", "admin"))
    with pytest.raises(AssertionError):
        verify(folder, db, SHA, SHA)


def test_mismatched_sha_and_topology_fail_closed(tmp_path, monkeypatch) -> None:
    folder, db = _fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="SHA"):
        verify(folder, db, SHA, "b" * 40)
    topology = json.loads((folder / "topology.json").read_text())
    topology["agent_networks"] = ["agent_net", "effect_net"]
    _write(folder, "topology.json", topology)
    with pytest.raises(AssertionError):
        verify(folder, db, SHA, SHA)
