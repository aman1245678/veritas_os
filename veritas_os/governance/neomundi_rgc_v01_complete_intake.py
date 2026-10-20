"""Fail-closed real-packet intake for RGC v0.1.0 COMPLETE-only evidence.

The legacy profile is explicitly selected; the signed document is never
relabeled to RGC v0.2. Neither an intake manifest nor a provenance receipt
creates key trust without a genuine operator-owned, out-of-band process.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from veritas_os.governance.external_measurement_evidence import (
    ApprovedExternalMeasurementProvider,
    ExternalMeasurementTrustPolicy,
    validate_verified_external_measurement_evidence,
    verify_external_measurement_artifact_to_evidence,
)
from veritas_os.governance.neomundi_jwks_provenance import (
    bind_neomundi_trusted_jwks_provenance,
)
from veritas_os.governance.neomundi_real_observation_intake import (
    bind_neomundi_real_observation_intake,
)
from veritas_os.governance.neomundi_real_observation_poc import (
    FileExternalMeasurementReplayGuard,
    NeoMundiRealObservationPocError,
    _failure_report,
    _provider_result_to_dict,
    verified_external_measurement_to_dict,
)
from veritas_os.governance.neomundi_rgc_v01_complete import (
    NeoMundiRgcV01CompleteVerifier,
)
from veritas_os.security.hash import sha256_of_canonical_json


def verify_neomundi_v01_complete_packet(
    *,
    artifact: dict[str, Any],
    artifact_file_sha256: str,
    trusted_jwks: dict[str, Any],
    trusted_jwks_file_sha256: str,
    provenance_receipt: dict[str, Any],
    provenance_receipt_file_sha256: str,
    intake_manifest: dict[str, Any],
    intake_manifest_file_sha256: str,
    replay_state_dir: str | Path,
    accepted_measurement_version: str,
    max_age_seconds: int,
    max_future_skew_seconds: int = 60,
    allow_no_expiry: bool = False,
    verifier_policy_id: str = "neomundi-rgc-v01-complete-poc",
    verifier_trust_level: str = "external-poc",
    trust_policy_id: str = "neomundi-rgc-v01-complete-evidence-poc",
    now: datetime | None = None,
) -> dict[str, dict[str, Any]]:
    """Check the exact packet, key provenance, signed payload and generic policy.

    This method is the only opt-in v0.1.0 production-artifact entry point.
    `now` is for injected deterministic tests; the CLI never exposes it.
    """
    current = now if now is not None else datetime.now(UTC)
    if (
        current.tzinfo is None
        or current.utcoffset() is None
        or isinstance(max_age_seconds, bool)
        or not isinstance(max_age_seconds, int)
        or max_age_seconds < 0
        or isinstance(max_future_skew_seconds, bool)
        or not isinstance(max_future_skew_seconds, int)
        or max_future_skew_seconds < 0
        or not isinstance(accepted_measurement_version, str)
        or not accepted_measurement_version.strip()
    ):
        reason = "neomundi_v01_intake_policy_invalid"
        raise NeoMundiRealObservationPocError(
            reason, report=_failure_report(stage="configuration", reason=reason)
        )

    try:
        intake = bind_neomundi_real_observation_intake(
            intake_manifest,
            artifact=artifact,
            artifact_file_sha256=artifact_file_sha256,
            trusted_jwks_file_sha256=trusted_jwks_file_sha256,
            trusted_key_provenance_receipt_file_sha256=(
                provenance_receipt_file_sha256
            ),
            expected_artifact_version="0.1.0",
        )
    except ValueError as exc:
        reason = str(exc)
        raise NeoMundiRealObservationPocError(
            reason, report=_failure_report(stage="intake_manifest", reason=reason)
        ) from exc

    try:
        key_binding = bind_neomundi_trusted_jwks_provenance(
            artifact, trusted_jwks=trusted_jwks, provenance_receipt=provenance_receipt
        )
    except ValueError as exc:
        reason = str(exc)
        raise NeoMundiRealObservationPocError(
            reason, report=_failure_report(stage="trusted_key_provenance", reason=reason)
        ) from exc

    intake_meta = {
        "accepted": True,
        **intake.to_dict(),
        "manifest_file_sha256": intake_manifest_file_sha256,
    }
    key_meta = {
        "accepted": True,
        **key_binding.to_dict(),
        "receipt_file_sha256": provenance_receipt_file_sha256,
    }

    try:
        verifier = NeoMundiRgcV01CompleteVerifier(
            trusted_jwks=trusted_jwks,
            verifier_policy_id=verifier_policy_id,
            verifier_trust_level=verifier_trust_level,
            accepted_measurement_versions=(accepted_measurement_version,),
        )
    except ValueError as exc:
        reason = str(exc)
        raise NeoMundiRealObservationPocError(
            reason, report=_failure_report(stage="verifier_configuration", reason=reason)
        ) from exc

    result = verifier.verify(artifact)
    if not result.verified:
        reason = result.reason or "neomundi_v01_provider_verification_failed"
        report = _failure_report(
            stage="provider_verification", reason=reason, provider_result=result
        )
        report["intake_manifest"] = intake_meta
        report["trusted_key_provenance"] = key_meta
        raise NeoMundiRealObservationPocError(reason, report=report)

    policy = ExternalMeasurementTrustPolicy(
        policy_id=trust_policy_id,
        approved_providers=[
            ApprovedExternalMeasurementProvider(
                provider_id="neomundi",
                verifier_id=verifier.verifier_id,
                verifier_trust_level=verifier.verifier_trust_level,
                verifier_policy_id=verifier.verifier_policy_id,
                verifier_policy_hash=verifier.verifier_policy_hash,
            )
        ],
        max_age_seconds=max_age_seconds,
        max_future_skew_seconds=max_future_skew_seconds,
        require_expiry=not allow_no_expiry,
    )

    try:
        # The replay guard is constructed only after exact packet, key,
        # signature and semantic verification have passed.
        proof = verify_external_measurement_artifact_to_evidence(
            artifact,
            provider_verifier=verifier,
            trust_policy=policy,
            replay_guard=FileExternalMeasurementReplayGuard(replay_state_dir),
            now=current,
        )
    except ValueError as exc:
        reason = str(exc)
        report = _failure_report(
            stage="generic_external_measurement_boundary",
            reason=reason,
            provider_result=result,
        )
        report["intake_manifest"] = intake_meta
        report["trusted_key_provenance"] = key_meta
        raise NeoMundiRealObservationPocError(reason, report=report) from exc

    failures = validate_verified_external_measurement_evidence(
        proof, trust_policy=policy, now=current
    )
    if failures:
        reason = "neomundi_v01_intake_proof_revalidation_failed"
        report = _failure_report(
            stage="sealed_proof_revalidation", reason=reason, provider_result=result
        )
        report["revalidation_failures"] = failures
        raise NeoMundiRealObservationPocError(reason, report=report)

    serialized_proof = verified_external_measurement_to_dict(proof)
    report: dict[str, Any] = {
        "status": "verified",
        "stage": "complete",
        "reason": "neomundi_v01_complete_packet_verified",
        "provider_verification": _provider_result_to_dict(result),
        "intake_manifest": intake_meta,
        "trusted_key_provenance": key_meta,
        "generic_boundary": {
            "accepted": True,
            "max_age_seconds": policy.max_age_seconds,
            "max_future_skew_seconds": policy.max_future_skew_seconds,
            "require_expiry": policy.require_expiry,
            "trust_policy_hash": policy.deterministic_hash(),
            "revalidation_failures": [],
        },
        "claim_boundary": {
            "measurement_only": True,
            "authority_created": False,
            "human_approval_created": False,
            "bind_authorization_created": False,
            "governance_decision_created": False,
            "external_effect_performed": False,
        },
    }
    manifest: dict[str, Any] = {
        "manifest_version": "1.0",
        "purpose": "neomundi_rgc_v01_historical_complete_packet",
        "verified_at": proof.verified_at,
        "inputs": {
            "artifact_id": proof.evidence.artifact_id,
            "artifact_version": "0.1.0",
            "measurement_version": proof.evidence.provenance["measurement_version"],
            "artifact_file_sha256": artifact_file_sha256,
            "artifact_payload_sha256": proof.evidence.payload_hash,
            "trusted_jwks_file_sha256": trusted_jwks_file_sha256,
            "trusted_key_provenance_receipt_file_sha256": (
                provenance_receipt_file_sha256
            ),
            "intake_manifest_file_sha256": intake_manifest_file_sha256,
            "intake_manifest_canonical_sha256": intake.manifest_canonical_sha256,
            "trusted_key_provenance_receipt_canonical_sha256": (
                key_binding.receipt_canonical_sha256
            ),
            "public_key_fingerprint_sha256": (
                key_binding.public_key_fingerprint_sha256
            ),
        },
        "verification": {
            "key_id": proof.key_id,
            "verifier_id": proof.verifier_id,
            "verifier_policy_hash": proof.verifier_policy_hash,
            "trust_policy_hash": proof.trust_policy_hash,
            "evidence_hash": proof.evidence_hash,
            "verification_proof_hash": proof.verification_proof_hash,
            "replay_key": proof.replay_key,
        },
        "outputs": {
            "verification_report": "verification_report.json",
            "verification_report_canonical_sha256": sha256_of_canonical_json(report),
            "verified_external_measurement_evidence": (
                "verified_external_measurement_evidence.json"
            ),
            "verified_external_measurement_evidence_canonical_sha256": (
                sha256_of_canonical_json(serialized_proof)
            ),
        },
        "claim_boundary": report["claim_boundary"],
        "non_claims": [
            "not independent proof of the out-of-band key trust channel",
            "not production readiness or deployment",
            "not factual correctness or local execution proof",
            "not authority, approval, permission or a governance decision",
            "not single-observation evidence of drift",
        ],
    }
    return {
        "verification_report": report,
        "verified_external_measurement_evidence": serialized_proof,
        "evidence_manifest": manifest,
    }
