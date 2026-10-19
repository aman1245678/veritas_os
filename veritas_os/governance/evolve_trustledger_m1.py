"""Evolve TrustLedger M1: synthetic, non-executing boundary research harness.

This is NOT a production issuer verifier or an authorization adapter.
No TrustLedger verdict is ever converted into VERITAS authority.
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from veritas_os.governance.commit_boundary import CommitBoundaryEvaluator

# Frozen synthetic fixture profile only; NOT a deployment-controlled trust store.
_FIXTURE_ISSUER = "evolve-edge-ai"
_FIXTURE_SCHEMA = "2.0"
_CLAIMS_EXCLUDED = frozenset({
    "receipt_issuer_authentication",
    "timestamp_proof",
    "receipt_claims_hash",
    "canonical_claims_input",
    "_unknown_field_policy_note",
})
_TIMESTAMP_RE = re.compile(r"20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non_finite_json_number")


def _parse_json(raw: bytes) -> dict[str, Any]:
    obj = json.loads(
        raw.decode("utf-8-sig"),
        object_pairs_hook=_no_duplicates,
        parse_constant=_reject_constant,
    )
    if not isinstance(obj, dict):
        raise ValueError("json_object_required")
    return obj


def _canonical_claims(receipt: dict[str, Any]) -> bytes:
    claims = {k: v for k, v in receipt.items() if k not in _CLAIMS_EXCLUDED}
    return json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp_missing")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timezone_required")
    return parsed


def evaluate_synthetic_case(
    receipt_raw: bytes,
    live_state_raw: bytes,
    *,
    evolve_output_raw: bytes | None = None,
    case_meta_raw: bytes | None = None,
) -> dict[str, Any]:
    """Evaluate receipt bytes independently; partner output is only for reconciliation.

    L1 issuer recognition is a SYNTHETIC fixture check, not signature authenticity.
    L2 proves local claims integrity, time and context consistency, not trust.
    L3 uses VERITAS CommitBoundaryEvaluator with NO independently issued authority.
    """
    result: dict[str, Any] = {
        "scope": "synthetic_fixture_only",
        "receipt_sha256": _sha256(receipt_raw),
        "live_state_sha256": _sha256(live_state_raw),
        "layer_1": "REJECTED",
        "layer_2": "NOT_REACHED",
        "layer_3": "NOT_REACHED",
        "first_failure": None,
        "claims_hash_matches": None,
        "record_warnings": [],
        "issuer_authenticity_verified": False,
        "authority_evidence_created": False,
        "human_approval_created": False,
        "bind_authorization_created": False,
        "network_dispatch_performed": False,
        "external_effect_performed": False,
    }
    try:
        receipt = _parse_json(receipt_raw)
        state = _parse_json(live_state_raw)
    except (ValueError, UnicodeError, TypeError):
        result["first_failure"] = "invalid_json"
        return result

    if receipt.get("receipt_schema_version") != _FIXTURE_SCHEMA:
        result["first_failure"] = "schema_version_unrecognized"
        return result
    if receipt.get("issuer") != _FIXTURE_ISSUER:
        result["first_failure"] = "issuer_not_recognized"
        return result
    result["layer_1"] = "SYNTHETIC_FIXTURE_RECOGNIZED"

    embedded = receipt.get("receipt_claims_hash")
    if not isinstance(embedded, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", embedded):
        result["layer_2"] = "REJECTED"
        result["first_failure"] = "claims_hash_missing_or_invalid"
        return result
    computed = _sha256(_canonical_claims(receipt))
    result["recomputed_claims_hash"] = computed
    result["claims_hash_matches"] = embedded == computed
    if embedded != computed:
        result["layer_2"] = "REJECTED"
        result["first_failure"] = "claims_hash_mismatch"
        return result
    if receipt.get("canonical_claims_input") != _canonical_claims(receipt).decode("utf-8"):
        result["layer_2"] = "REJECTED"
        result["first_failure"] = "canonical_claims_input_mismatch"
        return result

    authority = state.get("authority_state")
    context = state.get("evaluation_context")
    if not isinstance(authority, dict) or not isinstance(context, dict):
        result["layer_2"] = "REJECTED"
        result["first_failure"] = "state_or_context_missing"
        return result
    try:
        now = _time(state.get("evaluation_timestamp"))
        start = _time(authority.get("authorization_window_start"))
        end = _time(authority.get("authorization_window_end"))
    except (ValueError, TypeError):
        result["layer_2"] = "REJECTED"
        result["first_failure"] = "freshness_input_invalid"
        return result
    if not (start <= now <= end) or authority.get("authorization_window_expired") is True:
        result["layer_2"] = "REJECTED"
        result["first_failure"] = "freshness_expired"
        return result
    if (receipt.get("organization_id") != context.get("organization_id")
            or receipt.get("assessment_id") != context.get("assessment_id")
            or not context.get("organization_id") or not context.get("assessment_id")):
        result["layer_2"] = "REJECTED"
        result["first_failure"] = "context_binding_mismatch"
        return result
    result["layer_2"] = "SYNTHETIC_CONSISTENT_NOT_AUTHENTICATED"

    # Real VERITAS evaluator; deliberately NO ActionClassContract, AuthorityEvidence,
    # HumanApproval, policy grant or bind. A TrustLedger ADOPT must not supply them.
    boundary = CommitBoundaryEvaluator().evaluate(
        execution_intent="synthetic_m1_no_effect",
        action_contract=None,
        authority_evidence=None,
        requested_scope=[],
        required_evidence_metadata={},
        evidence_freshness_metadata={},
        policy_snapshot_id=None,
        actor_identity=None,
        human_approval_state={},
        bind_context_metadata={},
        now=now,
    )
    result["layer_3"] = boundary.commit_boundary_result.upper()
    result["authority_validation_status"] = boundary.authority_validation_status
    if boundary.commit_boundary_result == "commit":
        raise AssertionError("synthetic_external_receipt_elevated_authority")
    result["first_failure"] = "independent_veritas_authority_missing"

    # Reconcile partner reports without trusting their gate result as authority.
    if evolve_output_raw is not None:
        partner = _parse_json(evolve_output_raw)
        fp = partner.get("input_fingerprints", {})
        if (fp.get("receipt_sha256") != result["receipt_sha256"]
                or fp.get("live_state_sha256") != result["live_state_sha256"]):
            result["record_warnings"].append("partner_input_fingerprint_mismatch")
        gate = partner.get("adoption_gate", {})
        if isinstance(gate, dict):
            result["partner_gate_claim"] = gate.get("gate_decision")
    if case_meta_raw is not None:
        meta = _parse_json(case_meta_raw)
        result["case_id"] = meta.get("case_id")
    return result


def evaluate_synthetic_zip(path: str | Path) -> dict[str, Any]:
    """Read six cases from a local ZIP; never execute bundled scripts."""
    output: dict[str, Any] = {
        "scope": "offline_synthetic_m1",
        "zip_sha256": _sha256(Path(path).read_bytes()),
        "cases": [],
        "frozen_baseline_approved": False,
        "real_signature_verification": False,
        "external_effect_performed": False,
    }
    with zipfile.ZipFile(path) as archive:
        manifest_raw = archive.read("MANIFEST.json")
        manifest = _parse_json(manifest_raw)
        output["manifest_sha256"] = _sha256(manifest_raw)
        output["manifest_mismatches"] = []
        declared = manifest.get("files")
        if not isinstance(declared, list) or not declared:
            raise ValueError("manifest_files_must_be_nonempty_list")
        archive_names = archive.namelist()
        if len(archive_names) != len(set(archive_names)):
            raise ValueError("duplicate_zip_members")
        expected_paths: set[str] = set()
        for item in declared:
            if not isinstance(item, dict):
                raise ValueError("manifest_file_entry_invalid")
            declared_path = item.get("path")
            expected = item.get("sha256")
            if (not isinstance(declared_path, str)
                    or not isinstance(expected, str)
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected)):
                raise ValueError("manifest_file_path_or_digest_invalid")
            # The partner manifest uses POSIX-style paths; the ZIP uses
            # literal backslashes as member-name separators.
            if (declared_path.startswith("/")
                    or "\\\\" in declared_path
                    or any(part in {"", ".", ".."} for part in declared_path.split("/"))):
                raise ValueError("unsafe_manifest_path")
            member = declared_path.replace("/", "\\\\")
            if member in expected_paths or member == "MANIFEST.json":
                raise ValueError("duplicate_or_self_referential_manifest_entry")
            expected_paths.add(member)
            try:
                actual = _sha256(archive.read(member))
            except KeyError:
                actual = "MISSING"
            if actual != expected:
                output["manifest_mismatches"].append(declared_path)
        actual_paths = set(archive_names) - {"MANIFEST.json"}
        output["unlisted_zip_members"] = sorted(actual_paths - expected_paths)
        output["missing_zip_members"] = sorted(expected_paths - actual_paths)
        output["manifest_integrity_pass"] = (
            not output["manifest_mismatches"]
            and not output["unlisted_zip_members"]
            and not output["missing_zip_members"]
        )
        for number in range(1, 7):
            prefix = f"case-{number}\\"
            args = {
                "receipt_raw": archive.read(prefix + "receipt.json"),
                "live_state_raw": archive.read(prefix + "live_state.json"),
                "evolve_output_raw": archive.read(prefix + "evolve_output.json"),
                "case_meta_raw": archive.read(prefix + "case_meta.json"),
            }
            case = evaluate_synthetic_case(**args)
            # Every case must be fingerprint-checked, including L1/L2 rejections.
            partner = _parse_json(args["evolve_output_raw"])
            fp = partner.get("input_fingerprints", {})
            case["input_fingerprints_match"] = (
                isinstance(fp, dict)
                and fp.get("receipt_sha256") == case["receipt_sha256"]
                and fp.get("live_state_sha256") == case["live_state_sha256"]
            )
            if not case["input_fingerprints_match"]:
                case["record_warnings"].append("partner_input_fingerprint_mismatch")
            # Detect contradictory source descriptions independently of L1/L2.
            meta = _parse_json(args["case_meta_raw"])
            timestamp = _parse_json(args["live_state_raw"]).get("evaluation_timestamp")
            reference_time = fp.get("evaluation_timestamp") if isinstance(fp, dict) else None
            if reference_time is not None and reference_time != timestamp:
                case["record_warnings"].append("timestamp_mismatch:live_state_vs_fingerprint")
            freshness_time = partner.get("freshness_check", {}).get("evaluation_timestamp")
            if freshness_time is not None and reference_time is not None and freshness_time != reference_time:
                case["record_warnings"].append("timestamp_mismatch:freshness_vs_fingerprint")
            layer2_info = partner.get("three_state_result", {}).get(
                "layer_2_provenance_verification", {}
            )
            if number == 3:
                layer2_time = layer2_info.get("subchecks", {}).get(
                    "freshness", {}
                ).get("evaluation_timestamp")
                if layer2_time is not None and layer2_time != reference_time:
                    case["record_warnings"].append("timestamp_mismatch:layer2_vs_fingerprint")
                texts = (
                    partner.get("adoption_gate", {}).get("reason", ""),
                    meta.get("evaluation_context", ""),
                )
                for label, value in zip(("gate_reason", "case_meta_context"), texts, strict=True):
                    if isinstance(value, str) and any(
                        t != reference_time for t in _TIMESTAMP_RE.findall(value)
                    ):
                        case["record_warnings"].append("timestamp_mismatch:" + label)
            if number == 6:
                layer2 = partner.get("three_state_result", {}).get(
                    "layer_2_provenance_verification", {}
                )
                if ("not reached" in str(layer2.get("note", "")).lower()
                        and "fail" in str(layer2.get("result", "")).lower()):
                    case["record_warnings"].append("layer2_failed_but_not_reached")
                if partner.get("freshness_check", {}).get("freshness_pass") is True:
                    case["record_warnings"].append("unreached_freshness_marked_pass")
            output["cases"].append(case)
    output["records_reconciled"] = (
        output["manifest_integrity_pass"]
        and all(not c["record_warnings"] for c in output["cases"])
    )
    return output


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_file", help="Local six-case Evolve ZIP (no network)")
    arguments = parser.parse_args()
    print(json.dumps(evaluate_synthetic_zip(arguments.zip_file), indent=2, sort_keys=True))
