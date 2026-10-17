"""#2385: externally supplied source data, pinned verifier, no self-signed fallback.

The signer used by these offline tests is an adversarial controlled test
fixture on the CI host, NOT independently operated RCC/Ben evidence.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat,
)

from scripts.enterprise_iam_lab import external_rcc_source_import as ext
from scripts.enterprise_iam_lab import source_bound_iam_origin as origin
from scripts.enterprise_iam_lab.source_bound_target_policy import (
    TargetSourceDenied, verify_external_origin_pin,
)


def fixture(tmp_path: Path):
    now = datetime.now(timezone.utc)
    signing_key = Ed25519PrivateKey.generate()
    public = signing_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo,
    )
    candidate = {
        "candidate_id": "controlled-synthetic-iam-2385",
        "actor_identity": "test-operator",
        **origin.TARGET,
    }
    request = {
        "source": "rcc-revas-controlled-synthetic-iam-request",
        "actor_identity": candidate["actor_identity"],
        "target_system": candidate["target_system"],
        "target_resource": candidate["target_resource"],
        "intended_action": candidate["intended_action"],
        "scope": "saas:grant_admin",
        "role": "admin",
        "user_request": "Synthetic IAM-only request explicitly controls admin grant.",
    }
    payload = {
        "schema": origin.SCHEMA,
        "original_request": request,
        "original_request_digest": origin.sha(request),
        "candidate": candidate,
        "candidate_digest": origin.sha(candidate),
        "issued_at": (now - timedelta(seconds=1)).isoformat(),
        "expires_at": (now + timedelta(seconds=90)).isoformat(),
        "nonce": "d" * 64,
        "production_claim": False,
    }
    signed = {"payload": payload, "signature": base64.b64encode(
        signing_key.sign(origin.canonical(payload))).decode("ascii")}
    att = tmp_path / "externally-provided-request.json"
    pub = tmp_path / "trusted-external-origin.pem"
    att.write_text(json.dumps(signed))
    pub.write_bytes(public)
    return now, signing_key, signed, att, pub, ext.key_fingerprint(public)


def test_external_explicit_trust_pin_admits_without_issuing_authority(tmp_path):
    now, _, _, att, pub, pin = fixture(tmp_path)
    report = ext.admit(att, pub, pin, now=now)
    assert report["result"] == "PASS"
    assert report["trust_spki_sha256"] == pin
    assert report["source_signature_valid"] is True
    assert report["no_native_authorization_issued"] is True
    assert report["independent_rcc_operator_proven"] is False
    assert report["actual_rcc_original_request_proven"] is False
    assert verify_external_origin_pin(pub.read_bytes(), pin) == pin
    assert report["source_envelope_sha256"] == hashlib.sha256(
        origin.canonical(json.loads(att.read_text()))).hexdigest()


@pytest.mark.parametrize("wrong", ["", "AUTO", "a" * 64, "A" * 64, "1" * 63])
def test_untrusted_or_noncanonical_pin_is_refused(tmp_path, wrong):
    now, _, _, att, pub, pin = fixture(tmp_path)
    with pytest.raises((ext.ExternalSourceDenied, TargetSourceDenied)):
        ext.admit(att, pub, wrong, now=now)
    with pytest.raises(TargetSourceDenied):
        verify_external_origin_pin(pub.read_bytes(), wrong)
    assert ext.verify_trust(pub.read_bytes(), pin) == pin


def test_wrong_key_even_for_fresh_signatures_refused(tmp_path):
    now, _, _, att, pub, pin = fixture(tmp_path)
    other_key = Ed25519PrivateKey.generate()
    other_public = other_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo,
    )
    pub.write_bytes(other_public)
    with pytest.raises(ext.ExternalSourceDenied, match="OUT_OF_BAND_PIN_MISMATCH"):
        ext.admit(att, pub, pin, now=now)
    with pytest.raises(TargetSourceDenied, match="EXTERNAL_TRUST_PIN_MISMATCH"):
        verify_external_origin_pin(pub.read_bytes(), pin)
    # Rewriting the trusted public key fingerprint requires an independent
    # explicit operator-approved pin change; it is not auto-discovered here.


@pytest.mark.parametrize("change", [
    lambda p: p["candidate"].update(target_system="local-counter"),
    lambda p: p["candidate"].update(required_authority=["counter:increment"]),
    lambda p: p["original_request"].update(target_resource="privileged-root"),
    lambda p: p.update(production_claim=True),
    lambda p: p.update(expires_at="2020-01-01T00:00:00+00:00"),
])
def test_resigned_scope_and_counter_mismatch_refused(tmp_path, change):
    now, key, signed, att, pub, pin = fixture(tmp_path)
    forged = deepcopy(signed)
    change(forged["payload"])
    forged["payload"]["original_request_digest"] = origin.sha(
        forged["payload"]["original_request"])
    forged["payload"]["candidate_digest"] = origin.sha(
        forged["payload"]["candidate"])
    forged["signature"] = base64.b64encode(
        key.sign(origin.canonical(forged["payload"]))).decode()
    att.write_text(json.dumps(forged))
    with pytest.raises(origin.SourceAdmissionDenied):
        ext.admit(att, pub, pin, now=now)


def test_signature_changes_are_rejected(tmp_path):
    now, _, signed, att, pub, pin = fixture(tmp_path)
    signed["signature"] = base64.b64encode(
        Ed25519PrivateKey.generate().sign(
            origin.canonical(signed["payload"]))).decode()
    att.write_text(json.dumps(signed))
    with pytest.raises(origin.SourceAdmissionDenied, match="SIGNATURE_INVALID"):
        ext.admit(att, pub, pin, now=now)


def test_duplicate_json_key_refused(tmp_path):
    now, _, signed, att, pub, pin = fixture(tmp_path)
    body = json.dumps(signed)
    att.write_text(body.replace('"signature":', '"signature": "duplicate", "signature":', 1))
    with pytest.raises(ext.ExternalSourceDenied, match="ATTESTATION_JSON_INVALID"):
        ext.admit(att, pub, pin, now=now)


def test_symlinks_absent_or_large_data_refused(tmp_path):
    now, _, _, att, pub, pin = fixture(tmp_path)
    link = tmp_path / "public-link.pem"
    link.symlink_to(pub)
    with pytest.raises(ext.ExternalSourceDenied, match="SYMLINK"):
        ext.admit(att, link, pin, now=now)
    with pytest.raises(ext.ExternalSourceDenied, match="ABSOLUTE_PATH"):
        ext.admit(Path("source.json"), pub, pin, now=now)
    att.write_bytes(b"X" * (ext.MAX_ATTESTATION_BYTES + 1))
    with pytest.raises(ext.ExternalSourceDenied, match="ATTESTATION_SIZE_INVALID"):
        ext.admit(att, pub, pin, now=now)


def test_runner_optin_refuses_silent_local_mint_and_keeps_source_out_of_report():
    runner = Path("scripts/enterprise_iam_lab/run_native_docker.sh").read_text()
    assert 'LAB_RCC_EXTERNAL_SOURCE_MODE:-0' in runner
    assert 'IAM2385_EXTERNAL_SOURCE_INPUT_KEY_PIN_AND_TARGET_V2_REQUIRED' in runner
    assert "external_rcc_source_import" in runner
    assert 'IAM_SOURCE_ATTESTATION_PATH="$LAB_TMP/iam_external_source_input.json"' in runner
    assert 'cp -- "$LAB_RCC_SIGNED_SOURCE_FILE" "$IAM_SOURCE_ATTESTATION_PATH"' in runner
    assert 'LAB_ORIGIN_DIR' in runner  # only older synthetic branch self-signs
    assert '--external-origin-pin "$LAB_RCC_TRUST_SPKI_SHA256"' in runner
    assert '--require-external-source-pin' in runner
    target = Path("scripts/enterprise_iam_lab/target_service.py").read_text()
    assert "verify_external_origin_pin" in target
    assert 'LAB_TARGET_REQUIRE_EXTERNAL_RCC_PIN' in target


def test_native_issuer_requires_explicit_external_pin_and_v2(tmp_path):
    import asyncio
    from scripts.enterprise_iam_lab.native_docker_issuer import issue
    att = tmp_path / "att.json"
    pub = tmp_path / "pub.pem"
    att.write_text("{}")
    pub.write_text("wrong public")
    with pytest.raises(ValueError, match="IAM2384_SOURCE_BOUND_REQUIRES"):
        asyncio.run(issue(tmp_path, tmp_path, tmp_path, tmp_path,
                          source_bound_target_permit=True))
    with pytest.raises(ValueError):
        asyncio.run(issue(tmp_path, tmp_path, tmp_path, tmp_path,
                          source_attestation=att, source_trust_key=pub,
                          external_origin_pin="f" * 64))
