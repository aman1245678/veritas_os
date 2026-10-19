"""Six synthetic boundary cases; no partner ZIP, keys, provider calls, or effects."""

from __future__ import annotations

import json

import pytest

from veritas_os.governance.evolve_trustledger_m1 import (
    _canonical_claims,
    _sha256,
    evaluate_synthetic_case,
)


def _raw(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _baseline() -> tuple[dict, dict]:
    receipt = {
        "receipt_schema_version": "2.0",
        "issuer": "evolve-edge-ai",
        "receipt_id": "synthetic-001",
        "organization_id": "org-test",
        "assessment_id": "assessment-test",
        "verdict": "ADOPT",
        "authorization_events": [{"decision": "APPROVE", "actor_id": "fixture-actor"}],
        "issued_at": "2026-09-18T23:00:00Z",
    }
    receipt["receipt_claims_hash"] = _sha256(_canonical_claims(receipt))
    receipt["canonical_claims_input"] = _canonical_claims(receipt).decode("utf-8")
    state = {
        "evaluation_timestamp": "2026-09-19T10:00:00Z",
        "evaluation_context": {
            "organization_id": "org-test",
            "assessment_id": "assessment-test",
        },
        "authority_state": {
            "authorization_window_start": "2026-09-18T22:00:00Z",
            "authorization_window_end": "2026-09-19T22:00:00Z",
            "authorization_window_expired": False,
        },
    }
    return receipt, state


@pytest.mark.parametrize(
    ("number", "change", "layer1", "layer2", "failure"),
    [
        (1, "none", "SYNTHETIC_FIXTURE_RECOGNIZED",
         "SYNTHETIC_CONSISTENT_NOT_AUTHENTICATED", "independent_veritas_authority_missing"),
        (2, "tamper", "SYNTHETIC_FIXTURE_RECOGNIZED", "REJECTED", "claims_hash_mismatch"),
        (3, "stale", "SYNTHETIC_FIXTURE_RECOGNIZED", "REJECTED", "freshness_expired"),
        (4, "context", "SYNTHETIC_FIXTURE_RECOGNIZED", "REJECTED", "context_binding_mismatch"),
        (5, "issuer", "REJECTED", "NOT_REACHED", "issuer_not_recognized"),
        (6, "schema", "REJECTED", "NOT_REACHED", "schema_version_unrecognized"),
    ],
)
def test_six_boundary_cases(number, change, layer1, layer2, failure, monkeypatch):
    monkeypatch.setenv("VERITAS_POSTURE", "dev")
    receipt, state = _baseline()
    if change == "tamper":
        receipt["authorization_events"][0]["decision"] = "DENY"
    elif change == "stale":
        state["evaluation_timestamp"] = "2026-09-20T10:00:00Z"
        state["authority_state"]["authorization_window_expired"] = True
    elif change == "context":
        state["evaluation_context"]["organization_id"] = "other-org"
    elif change == "issuer":
        receipt["issuer"] = "UNKNOWN_ISSUER"
        receipt.pop("receipt_claims_hash")
    elif change == "schema":
        receipt["receipt_schema_version"] = "99.0"
        receipt["issuer"] = "unknown-issuer-xyz"
    result = evaluate_synthetic_case(_raw(receipt), _raw(state))
    assert result["layer_1"] == layer1, number
    assert result["layer_2"] == layer2, number
    assert result["first_failure"] == failure, number
    assert result["layer_3"] in {"NOT_REACHED", "BLOCK", "REFUSE", "ESCALATE"}
    assert result["issuer_authenticity_verified"] is False
    assert result["authority_evidence_created"] is False
    assert result["human_approval_created"] is False
    assert result["bind_authorization_created"] is False
    assert result["network_dispatch_performed"] is False
    assert result["external_effect_performed"] is False


def test_extra_receipt_field_is_not_silently_excluded():
    receipt, state = _baseline()
    receipt["_unrecognized_note"] = "changes claims"
    result = evaluate_synthetic_case(_raw(receipt), _raw(state))
    assert result["first_failure"] == "claims_hash_mismatch"


def test_claims_input_cannot_replace_received_claims():
    receipt, state = _baseline()
    receipt["authorization_events"][0]["decision"] = "DENY"
    assert evaluate_synthetic_case(_raw(receipt), _raw(state))["first_failure"] == "claims_hash_mismatch"


def test_missing_claims_hash_is_not_trusted():
    receipt, state = _baseline()
    receipt.pop("receipt_claims_hash")
    assert evaluate_synthetic_case(_raw(receipt), _raw(state))["first_failure"] == "claims_hash_missing_or_invalid"


def test_duplicate_keys_fail_closed():
    _, state = _baseline()
    raw = b'{"issuer":"evolve-edge-ai","issuer":"evolve-edge-ai"}'
    assert evaluate_synthetic_case(raw, _raw(state))["first_failure"] == "invalid_json"


def test_partner_claimed_adopt_never_grants_authority(monkeypatch):
    monkeypatch.setenv("VERITAS_POSTURE", "dev")
    receipt, state = _baseline()
    partner = {
        "input_fingerprints": {
            "receipt_sha256": _sha256(_raw(receipt)),
            "live_state_sha256": _sha256(_raw(state)),
        },
        "adoption_gate": {"gate_decision": "ADOPT"},
    }
    result = evaluate_synthetic_case(
        _raw(receipt), _raw(state), evolve_output_raw=_raw(partner)
    )
    assert result["partner_gate_claim"] == "ADOPT"
    assert result["layer_3"] != "COMMIT"
    assert result["authority_evidence_created"] is False
    assert result["bind_authorization_created"] is False


def test_canonical_claims_uses_literal_unicode_and_sorted_keys():
    receipt = {"z": "é", "a": [{"b": 2, "a": 1}]}
    assert _canonical_claims(receipt) == '{"a":[{"a":1,"b":2}],"z":"é"}'.encode("utf-8")
