"""Schema-lite stability guard for the NOT-YET-EXECUTED enterprise IAM bypass proof.

This is a contract consistency test, NOT runtime bypass-resistance evidence.
"""

from __future__ import annotations

import json
from pathlib import Path


CONTRACT = (
    Path(__file__).resolve().parents[2]
    / "contracts"
    / "isolated-enterprise-iam-bypass-v1.json"
)


def _load() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


def test_contract_cannot_be_misreported_as_executed_proof() -> None:
    contract = _load()
    assert contract["contract_id"] == "ISOLATED_ENTERPRISE_IAM_BYPASS_V1"
    assert contract["status"] == "SPECIFICATION_ONLY_NOT_EXECUTED"
    assert contract["production_claim"] is False
    assert contract["external_api_calls_allowed"] is False
    assert contract["rule_of_one"] == (
        "EXTERNAL_ENFORCEMENT_DENIES_UNGOVERNED_IAM_MUTATION"
    )


def test_single_frozen_mutation_and_distinct_negative_enforcement_layers() -> None:
    contract = _load()
    assert contract["action"] == {
        "method": "POST",
        "path": "/v1/iam/users/contractor-001/roles",
        "body": {"role": "admin"},
        "scope": "saas:grant_admin",
        "target": "synthetic-user:contractor-001",
        "effect": "synthetic IAM role grant persisted in an isolated target-owned database",
    }

    cases = contract["case_matrix"]
    ids = [case["case_id"] for case in cases]
    assert len(ids) == len(set(ids)) == 8
    assert ids == [
        "ALLOW_01",
        "DENY_01",
        "DENY_02",
        "DENY_03",
        "DENY_04",
        "DENY_05",
        "DENY_06",
        "RECON_01",
    ]
    assert sum(case["expected_effect_delta"] for case in cases) == 1
    assert cases[0]["expected_boundary"] == "TARGET_COMMIT"
    assert cases[0]["expected_effect_delta"] == 1
    assert all(case["expected_effect_delta"] == 0 for case in cases[1:])
    assert {
        case["expected_boundary"] for case in cases
    } >= {
        "NETWORK_UNREACHABLE",
        "TLS_CLIENT_IDENTITY_REJECTED",
        "TARGET_POLICY_403",
        "VERITAS_PRE_DISPATCH_DENY",
        "VERITAS_REPLAY_DENY",
        "VERITAS_BIND_MISMATCH_DENY",
        "EXACTLY_ONE_TARGET_EFFECT_CONFIRMED",
    }


def test_agent_cannot_borrow_trusted_executor_capabilities_in_contract() -> None:
    contract = _load()
    actors = contract["actors"]
    assert actors["agent"]["networks"] == ["agent_net"]
    assert actors["agent"]["effect_credentials"] is False
    assert actors["agent"]["docker_socket"] is False
    assert actors["agent"]["can_resolve_effect_service"] is False
    assert actors["governed_executor"]["must_consume_veritas_authorization"] is True
    assert "effect_net" in actors["governed_executor"]["networks"]
    assert actors["effect_service"]["host_published_ports"] is False
    assert actors["effect_service"]["verifies_client_identity"] is True
    assert actors["effect_service"]["verifies_scoped_authority"] is True


def test_independent_evidence_and_provenance_are_mandatory() -> None:
    contract = _load()
    assert len(contract["frozen_base_sha"]) == 40
    assert "tested_sha" in contract["must_capture"]
    assert "resolved_network_topology_digest" in contract["must_capture"]
    assert "target_state_after_digest" in contract["must_capture"]
    assert "target_audit_event_id" in contract["must_capture"]
    assert "probe_exit_status_or_http_status" in contract["must_capture"]
    assert "artifact_manifest_sha256" in contract["must_capture"]
    assert len(contract["proof_conjunction"]) == len(
        set(contract["proof_conjunction"])
    )
    assert "independent_target_state_records_exactly_one_grant" in contract[
        "proof_conjunction"
    ]
    assert "no_secret_material_in_artifacts" in contract["proof_conjunction"]
    assert "independent_target_snapshot.json" in contract[
        "required_runtime_artifacts"
    ]
    assert "third-party reproduction" in contract["completion_requires"]
