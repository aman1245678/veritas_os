"""Six synthetic boundary cases; no partner ZIP, keys, provider calls, or effects."""

from __future__ import annotations

import json
import zipfile

import pytest

from veritas_os.governance.evolve_trustledger_m1 import (
    _canonical_claims,
    _sha256,
    evaluate_synthetic_case,
    evaluate_synthetic_zip,
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


def _write_six_case_zip(
    path, *, tamper_manifest=False, extra_member=False,
    inconsistent_timestamp=False, unreached_boolean=False,
):
    """Create partner-shaped ZIP entirely from synthetic in-test data."""
    contents = {}
    for number in range(1, 7):
        receipt, state = _baseline()
        if number == 2:
            receipt["authorization_events"][0]["decision"] = "DENY"
        elif number == 3:
            state["evaluation_timestamp"] = "2026-09-20T10:00:00Z"
            state["authority_state"]["authorization_window_expired"] = True
            if inconsistent_timestamp:
                state["evaluation_timestamp"] = "2026-10-06T10:00:00Z"
        elif number == 4:
            state["evaluation_context"]["organization_id"] = "wrong-org"
        elif number == 5:
            receipt["issuer"] = "UNKNOWN_ISSUER"
            receipt.pop("receipt_claims_hash")
            receipt.pop("canonical_claims_input")
        elif number == 6:
            receipt["receipt_schema_version"] = "99.0"
            receipt["issuer"] = "unknown-issuer-xyz"
            receipt.pop("receipt_claims_hash")
            receipt.pop("canonical_claims_input")
        receipt_raw, state_raw = _raw(receipt), _raw(state)
        expected_time = (
            "2026-09-20T10:00:00Z" if number == 3
            else state["evaluation_timestamp"]
        )
        partner = {
            "input_fingerprints": {
                "receipt_sha256": _sha256(receipt_raw),
                "live_state_sha256": _sha256(state_raw),
                "evaluation_timestamp": expected_time,
            },
            "freshness_check": {
                "freshness_pass": "not_evaluated" if number >= 5 else number != 3,
                "evaluation_timestamp": expected_time,
            },
            "context_binding_check": {
                "context_binding_pass": "not_evaluated" if number >= 5 else number != 4,
                "interpretation": "not evaluated" if number >= 5 else "evaluated",
            },
            "adoption_gate": {
                "gate_decision": "ADOPT" if number == 1 else "INELIGIBLE",
                "reason": "Evaluation timestamp " + expected_time,
            },
            "three_state_result": {
                "layer_2_provenance_verification": {
                    "result": "NOT_REACHED" if number >= 5 else "PASSED",
                    "subchecks": (
                        {"hash_integrity": "not_evaluated",
                         "freshness": "not_evaluated",
                         "context_binding": "not_evaluated"}
                        if number >= 5 else {}
                    ),
                },
            },
        }
        if unreached_boolean and number == 5:
            partner["freshness_check"]["freshness_pass"] = True
        case_meta = {
            "case_id": "case-" + str(number),
            "evaluation_context": "Evaluation timestamp " + expected_time,
        }
        files = {
            "receipt.json": receipt_raw,
            "live_state.json": state_raw,
            "evolve_output.json": _raw(partner),
            "case_meta.json": _raw(case_meta),
        }
        for name, raw in files.items():
            contents[f"case-{number}/{name}"] = raw
    for script in ("build_cases.py", "build_cases_fixed.py", "evolve_runner_v2.py"):
        contents[script] = b"# Inert test data; never executed.\n"
    manifest = {
        "manifest_schema_version": "1.0",
        "files": [
            {"path": name, "sha256": _sha256(raw)}
            for name, raw in sorted(contents.items())
        ],
    }
    if tamper_manifest:
        contents["case-1/receipt.json"] += b" "
    if extra_member:
        contents["unexpected.py"] = b"print('never execute')\n"
    with zipfile.ZipFile(path, "w") as archive:
        for name, raw in contents.items():
            archive.writestr(name.replace("/", chr(92)), raw)
        archive.writestr("MANIFEST.json", _raw(manifest))


def test_real_partner_manifest_shape_and_six_cases(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_POSTURE", "dev")
    path = tmp_path / "partner-shaped.zip"
    _write_six_case_zip(path)
    report = evaluate_synthetic_zip(path)
    assert report["manifest_integrity_pass"] is True
    assert report["manifest_mismatches"] == []
    assert report["unlisted_zip_members"] == []
    assert len(report["cases"]) == 6
    assert all(case["input_fingerprints_match"] for case in report["cases"])
    assert [case["first_failure"] for case in report["cases"]] == [
        "independent_veritas_authority_missing",
        "claims_hash_mismatch",
        "freshness_expired",
        "context_binding_mismatch",
        "issuer_not_recognized",
        "schema_version_unrecognized",
    ]
    assert report["records_reconciled"] is True
    assert report["frozen_baseline_approved"] is False
    assert report["external_effect_performed"] is False


@pytest.mark.parametrize("variant", ["tamper_manifest", "extra_member"])
def test_partner_manifest_must_cover_actual_bytes_and_all_members(
    tmp_path, monkeypatch, variant,
):
    monkeypatch.setenv("VERITAS_POSTURE", "dev")
    path = tmp_path / "altered.zip"
    _write_six_case_zip(path, **{variant: True})
    report = evaluate_synthetic_zip(path)
    assert report["manifest_integrity_pass"] is False
    assert report["records_reconciled"] is False


def test_actual_oct19_style_record_inconsistencies_are_detected(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("VERITAS_POSTURE", "dev")
    path = tmp_path / "inconsistent.zip"
    _write_six_case_zip(
        path, inconsistent_timestamp=True, unreached_boolean=True,
    )
    report = evaluate_synthetic_zip(path)
    assert report["manifest_integrity_pass"] is True
    assert "timestamp_mismatch:live_state_vs_fingerprint" in (
        report["cases"][2]["record_warnings"]
    )
    assert "unreached_subcheck_boolean:freshness_pass" in (
        report["cases"][4]["record_warnings"]
    )
    assert report["records_reconciled"] is False
