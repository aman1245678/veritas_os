"""Isolated IAM effect-bound permit cryptographic primitive.

Not a VERITAS native authorization bridge and not dispatch authority.
No target effects or production credentials.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REQUIRED = frozenset({
    "version", "issuer", "audience", "permit_id", "authorization_id",
    "execution_intent_id", "request_id", "method", "path", "subject",
    "role", "scope", "not_before", "expires_at",
})
EXPECTED = {
    "version": "isolated-iam-permit-v1",
    "audience": "isolated-iam-target",
    "method": "POST",
    "path": "/v1/iam/users/contractor-001/roles",
    "subject": "contractor-001",
    "role": "admin",
    "scope": "saas:grant_admin",
}


class PermitRejected(ValueError):
    """Permit fails canonical, cryptographic, or effect-bound checks."""


def canonical(payload: Mapping[str, Any]) -> bytes:
    if set(payload) != REQUIRED or any(type(value) is not str or not value for value in payload.values()):
        raise PermitRejected("invalid_permit_fields")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PermitRejected("invalid_permit_time") from exc
    if parsed.tzinfo is None:
        raise PermitRejected("naive_permit_time")
    return parsed.astimezone(timezone.utc)


def validate_claims(payload: Mapping[str, Any], now: datetime) -> None:
    canonical(payload)
    if any(payload[key] != value for key, value in EXPECTED.items()):
        raise PermitRejected("effect_binding_mismatch")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise PermitRejected("invalid_verification_clock")
    if not _time(payload["not_before"]) <= now.astimezone(timezone.utc) < _time(payload["expires_at"]):
        raise PermitRejected("permit_outside_validity")


def sign_permit(payload: Mapping[str, Any], signer: Ed25519PrivateKey) -> dict[str, Any]:
    message = canonical(payload)
    return {
        "payload": dict(payload),
        "signature": base64.b64encode(signer.sign(message)).decode("ascii"),
    }


def verify_permit(envelope: Mapping[str, Any], verifier: Ed25519PublicKey, now: datetime) -> dict[str, str]:
    if set(envelope) != {"payload", "signature"} or not isinstance(envelope["payload"], dict):
        raise PermitRejected("invalid_permit_envelope")
    payload = envelope["payload"]
    message = canonical(payload)
    signature = envelope["signature"]
    if not isinstance(signature, str):
        raise PermitRejected("invalid_permit_signature")
    try:
        decoded = base64.b64decode(signature, validate=True)
        verifier.verify(decoded, message)
    except (ValueError, InvalidSignature) as exc:
        raise PermitRejected("invalid_permit_signature") from exc
    validate_claims(payload, now)
    return dict(payload)
