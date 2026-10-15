"""Offline tests for signed IAM effect permit primitive (no target dispatch)."""
from datetime import datetime, timezone, timedelta
import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SOURCE = Path(__file__).resolve().parents[2] / "scripts/enterprise_iam_lab/signed_permit.py"
spec = importlib.util.spec_from_file_location("iam_signed_permit", SOURCE)
permit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(permit)
NOW = datetime(2026, 10, 14, 0, 0, tzinfo=timezone.utc)


def claims():
    return {
        **permit.EXPECTED,
        "issuer": "test-issuer",
        "permit_id": "permit-1",
        "authorization_id": "authorization-1",
        "execution_intent_id": "intent-1",
        "request_id": "request-1",
        "not_before": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
    }


def test_valid_signed_effect_bound_permit():
    signer = Ed25519PrivateKey.generate()
    envelope = permit.sign_permit(claims(), signer)
    assert permit.verify_permit(envelope, signer.public_key(), NOW) == claims()


@pytest.mark.parametrize("field,changed", [
    ("path", "/v1/iam/users/another/roles"),
    ("subject", "another"),
    ("scope", "saas:read"),
    ("role", "viewer"),
    ("audience", "different-target"),
    ("method", "GET"),
])
def test_signed_but_wrong_effect_is_denied(field, changed):
    signer = Ed25519PrivateKey.generate()
    data = claims()
    data[field] = changed
    with pytest.raises(permit.PermitRejected, match="effect_binding_mismatch"):
        permit.verify_permit(permit.sign_permit(data, signer), signer.public_key(), NOW)


def test_tamper_and_wrong_signer_are_denied():
    signer = Ed25519PrivateKey.generate()
    envelope = permit.sign_permit(claims(), signer)
    envelope["payload"]["role"] = "viewer"
    with pytest.raises(permit.PermitRejected, match="invalid_permit_signature"):
        permit.verify_permit(envelope, signer.public_key(), NOW)
    with pytest.raises(permit.PermitRejected, match="invalid_permit_signature"):
        permit.verify_permit(permit.sign_permit(claims(), signer), Ed25519PrivateKey.generate().public_key(), NOW)


def test_expired_and_future_permits_are_denied():
    signer = Ed25519PrivateKey.generate()
    envelope = permit.sign_permit(claims(), signer)
    for at in (NOW - timedelta(minutes=2), NOW + timedelta(minutes=2)):
        with pytest.raises(permit.PermitRejected, match="permit_outside_validity"):
            permit.verify_permit(envelope, signer.public_key(), at)


def test_unknown_fields_and_naive_clock_fail_closed():
    signer = Ed25519PrivateKey.generate()
    data = claims()
    data["extra"] = "unsafe"
    with pytest.raises(permit.PermitRejected, match="invalid_permit_fields"):
        permit.sign_permit(data, signer)
    with pytest.raises(permit.PermitRejected, match="invalid_verification_clock"):
        permit.verify_permit(permit.sign_permit(claims(), signer), signer.public_key(), datetime(2026, 10, 14))


@pytest.mark.parametrize("broken", ["!not-base64!", "@", "abc%", "====", ""])
def test_malformed_base64_signature_fails_closed_without_handler_crash(broken):
    signer = Ed25519PrivateKey.generate()
    envelope = permit.sign_permit(claims(), signer)
    envelope["signature"] = broken
    with pytest.raises(permit.PermitRejected, match="invalid_permit_signature"):
        permit.verify_permit(envelope, signer.public_key(), NOW)
