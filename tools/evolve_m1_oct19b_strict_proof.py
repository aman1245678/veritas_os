"""Local, offline Oct19b evidence check using the real VERITAS M1 harness.

Run in a checkout of PR #2387. Never commit or upload the partner ZIP.
This is synthetic boundary research, NOT trusted issuer authentication or a freeze.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from veritas_os.governance.evolve_trustledger_m1 import evaluate_synthetic_zip

ZIP_SHA = "sha256:8781bfc6d1518713291e1e262bc818d7855504aaea4f0280c625a51027a91787"
MANIFEST_SHA = "sha256:319ca54e89d697ac7f5945333f7498f4e04c7fb8ee8ab6826c3ef7c3aba675f3"
FAILURES = (
    "independent_veritas_authority_missing",
    "claims_hash_mismatch",
    "freshness_expired",
    "context_binding_mismatch",
    "issuer_not_recognized",
    "schema_version_unrecognized",
)
GATES = ("ADOPT", "INELIGIBLE", "INELIGIBLE", "INELIGIBLE", "FAIL_CLOSED", "FAIL_CLOSED")


def strict_check(zip_file: Path) -> dict:
    report = evaluate_synthetic_zip(zip_file)
    failures: list[str] = []

    def check(condition: bool, label: str) -> None:
        if not condition:
            failures.append(label)

    check(report.get("zip_sha256") == ZIP_SHA, "zip_hash")
    check(report.get("manifest_sha256") == MANIFEST_SHA, "manifest_hash")
    check(report.get("manifest_integrity_pass") is True, "manifest_integrity")
    check(report.get("records_reconciled") is True, "record_consistency")
    check(report.get("frozen_baseline_approved") is False, "premature_freeze")
    check(report.get("real_signature_verification") is False, "signature_overclaim")
    check(report.get("external_effect_performed") is False, "unexpected_effect")
    cases = report.get("cases", [])
    check(len(cases) == 6, "case_count")
    for i, case in enumerate(cases[:6]):
        name = f"case{i + 1}"
        check(case.get("first_failure") == FAILURES[i], name + "_first_failure")
        check(case.get("partner_gate_claim") == GATES[i], name + "_partner_gate")
        check(case.get("input_fingerprints_match") is True, name + "_fingerprints")
        check(not case.get("record_warnings"), name + "_record_warnings")
        check(case.get("issuer_authenticity_verified") is False, name + "_authenticity")
        for flag in ("authority_evidence_created", "human_approval_created",
                     "bind_authorization_created", "network_dispatch_performed",
                     "external_effect_performed"):
            check(case.get(flag) is False, name + "_" + flag)
        if i == 0:
            check(case.get("layer_2") == "SYNTHETIC_CONSISTENT_NOT_AUTHENTICATED",
                  name + "_layer2")
            check(case.get("layer_3") in {"BLOCK", "REFUSE", "ESCALATE"},
                  name + "_layer3_fail_closed")
            check(bool(case.get("authority_validation_status")),
                  name + "_real_commit_evaluator")
        else:
            check(case.get("layer_3") == "NOT_REACHED", name + "_layer3_unreached")
    report["strict_oct19b_proof"] = {
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "partner_zip_executed_as_code": False,
        "external_effect_performed": False,
        "frozen_baseline_approved": False,
        "milestone1_signed_off": False,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_file", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = strict_check(args.zip_file)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print("Oct19b strict local proof:", result["strict_oct19b_proof"]["status"])
    print("Report:", args.report)
    return 0 if result["strict_oct19b_proof"]["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
