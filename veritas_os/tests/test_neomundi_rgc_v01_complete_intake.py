"""Synthetic tests for the explicit, fail-closed NeoMundi RGC v0.1 packet intake.

No production RGC, production JWKS, or partner trust approval is committed.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from veritas_os.governance.neomundi_real_observation_intake import (
    bind_neomundi_real_observation_intake,
)
from veritas_os.governance.neomundi_real_observation_poc import (
    NeoMundiRealObservationPocError,
)
from veritas_os.governance.neomundi_rgc_v01_complete_intake import (
    verify_neomundi_v01_complete_packet,
)
from veritas_os.tests.test_neomundi_rgc_v01_complete import (
    NOW,
    _artifact,
    _material,
    _sign,
)


def _sha(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _packet() -> dict[str, Any]:
    private, jwks = _material()
    artifact = _sign(_artifact(), private)
    encoded = jwks["keys"][0]["x"]
    raw_key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    receipt = {
        "receipt_type": "trusted_public_key_provenance",
        "algorithm": "Ed25519",
        "public_key_fingerprint_sha256": hashlib.sha256(raw_key).hexdigest(),
        "trust_channel": "operator_handoff",
        "received_at": NOW.isoformat(),
        "approved_by": "synthetic-test-operator",
        "approval_reference": "SYNTHETIC-ONLY-KEY-APPROVAL",
        "notes": "Test data only; no real independent trust channel.",
        "bundle_internal_key_used": False,
    }
    artifact_hash = _sha(artifact)
    jwks_hash = _sha(jwks)
    receipt_hash = _sha(receipt)
    manifest = {
        "manifest_version": "1.0",
        "manifest_id": "synthetic-v01-intake",
        "provider_id": "neomundi",
        "artifact_type": "neomundi_rgc",
        "artifact_version": "0.1.0",
        "artifact_id": artifact["identity"]["request_id"],
        "expected_key_id": artifact["integrity"]["key_id"],
        "expected_signer_identity": artifact["integrity"]["signer_identity"],
        "artifact_file_sha256": artifact_hash,
        "trusted_jwks_file_sha256": jwks_hash,
        "trusted_key_provenance_receipt_file_sha256": receipt_hash,
        "handoff_reference": "SYNTHETIC-ONLY",
        "received_at": NOW.isoformat(),
    }
    return {
        "artifact": artifact,
        "artifact_file_sha256": artifact_hash,
        "trusted_jwks": jwks,
        "trusted_jwks_file_sha256": jwks_hash,
        "provenance_receipt": receipt,
        "provenance_receipt_file_sha256": receipt_hash,
        "intake_manifest": manifest,
        "intake_manifest_file_sha256": _sha(manifest),
    }


def _verify(packet: dict[str, Any], state: Path, **kwargs: Any) -> dict[str, Any]:
    return verify_neomundi_v01_complete_packet(
        **packet,
        replay_state_dir=state,
        accepted_measurement_version=kwargs.pop(
            "accepted_measurement_version", "3.3.0"
        ),
        max_age_seconds=kwargs.pop("max_age_seconds", 3600),
        allow_no_expiry=kwargs.pop("allow_no_expiry", True),
        now=kwargs.pop("now", NOW),
        **kwargs,
    )


def test_exact_v01_signed_packet_produces_measurement_only_once(
    tmp_path: Path,
) -> None:
    packet = _packet()
    outputs = _verify(packet, tmp_path / "replay")
    report = outputs["verification_report"]
    proof = outputs["verified_external_measurement_evidence"]
    manifest = outputs["evidence_manifest"]

    assert report["status"] == "verified"
    assert report["intake_manifest"]["artifact_version"] == "0.1.0"
    assert report["trusted_key_provenance"]["out_of_band_trust_established_by_veritas"] is False
    assert report["claim_boundary"]["authority_created"] is False
    assert report["claim_boundary"]["governance_decision_created"] is False
    assert proof["evidence"]["artifact_version"] == "0.1.0"
    assert proof["evidence"]["provenance"]["measurement_version"] == "3.3.0"
    assert proof["evidence"]["metadata"]["execution_permission_imported"] is False
    assert manifest["inputs"]["artifact_file_sha256"] == packet["artifact_file_sha256"]
    assert manifest["verification"]["verification_proof_hash"]

    with pytest.raises(
        NeoMundiRealObservationPocError, match="external_measurement_replay_detected"
    ) as caught:
        _verify(packet, tmp_path / "replay")
    assert caught.value.report["stage"] == "generic_external_measurement_boundary"


@pytest.mark.parametrize(
    ("mutator", "stage", "reason"),
    [
        (
            lambda p: p["intake_manifest"].__setitem__(
                "artifact_file_sha256", "f" * 64
            ),
            "intake_manifest",
            "neomundi_poc_intake_artifact_hash_mismatch",
        ),
        (
            lambda p: p["intake_manifest"].__setitem__(
                "artifact_version", "0.2.0"
            ),
            "intake_manifest",
            "neomundi_poc_intake_artifact_version_mismatch",
        ),
        (
            lambda p: p["intake_manifest"].__setitem__(
                "trusted_jwks_file_sha256", "f" * 64
            ),
            "intake_manifest",
            "neomundi_poc_intake_jwks_hash_mismatch",
        ),
        (
            lambda p: p["intake_manifest"].__setitem__(
                "trusted_key_provenance_receipt_file_sha256", "f" * 64
            ),
            "intake_manifest",
            "neomundi_poc_intake_provenance_hash_mismatch",
        ),
        (
            lambda p: p["intake_manifest"].__setitem__(
                "expected_key_id", "someone-else"
            ),
            "intake_manifest",
            "neomundi_poc_intake_key_id_mismatch",
        ),
        (
            lambda p: p["provenance_receipt"].__setitem__(
                "public_key_fingerprint_sha256", "f" * 64
            ),
            "trusted_key_provenance",
            "neomundi_poc_provenance_fingerprint_mismatch",
        ),
        (
            lambda p: p["artifact"]["observation"]["observed_signals"].__setitem__(
                "coherence_score", 0.1
            ),
            "provider_verification",
            "neomundi_v01_payload_hash_mismatch",
        ),
    ],
)
def test_packet_fails_before_replay_on_each_boundary(
    tmp_path: Path, mutator: Any, stage: str, reason: str
) -> None:
    packet = _packet()
    mutator(packet)
    with pytest.raises(NeoMundiRealObservationPocError, match=reason) as caught:
        _verify(packet, tmp_path / "replay")
    assert caught.value.report["stage"] == stage
    assert not (tmp_path / "replay").exists()


def test_explicit_v01_intake_does_not_change_default_v02_binding() -> None:
    packet = _packet()
    args = {
        "artifact": packet["artifact"],
        "artifact_file_sha256": packet["artifact_file_sha256"],
        "trusted_jwks_file_sha256": packet["trusted_jwks_file_sha256"],
        "trusted_key_provenance_receipt_file_sha256": (
            packet["provenance_receipt_file_sha256"]
        ),
    }
    with pytest.raises(
        ValueError, match="neomundi_poc_intake_artifact_version_mismatch"
    ):
        bind_neomundi_real_observation_intake(packet["intake_manifest"], **args)
    valid = bind_neomundi_real_observation_intake(
        packet["intake_manifest"], expected_artifact_version="0.1.0", **args
    )
    assert valid.artifact_version == "0.1.0"
    with pytest.raises(
        ValueError, match="neomundi_poc_intake_expected_version_unsupported"
    ):
        bind_neomundi_real_observation_intake(
            packet["intake_manifest"], expected_artifact_version="any", **args
        )


def test_nonapproved_measurement_version_fails_without_replay(tmp_path: Path) -> None:
    with pytest.raises(
        NeoMundiRealObservationPocError,
        match="neomundi_v01_measurement_version_unapproved",
    ) as caught:
        _verify(
            _packet(),
            tmp_path / "replay",
            accepted_measurement_version="3.3.1",
        )
    assert caught.value.report["stage"] == "provider_verification"
    assert not (tmp_path / "replay").exists()


def test_freshness_and_expiry_stay_at_generic_boundary(tmp_path: Path) -> None:
    packet = _packet()
    with pytest.raises(
        NeoMundiRealObservationPocError, match="external_measurement_stale"
    ) as stale:
        _verify(packet, tmp_path / "stale", now=NOW + timedelta(days=1))
    assert stale.value.report["stage"] == "generic_external_measurement_boundary"
    assert not list((tmp_path / "stale").glob("*.json"))

    with pytest.raises(
        NeoMundiRealObservationPocError, match="external_measurement_expiry_missing"
    ) as expiry:
        _verify(packet, tmp_path / "expiry", allow_no_expiry=False)
    assert expiry.value.report["stage"] == "generic_external_measurement_boundary"
    assert not list((tmp_path / "expiry").glob("*.json"))
