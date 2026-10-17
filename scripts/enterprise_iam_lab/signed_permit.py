"""Isolated IAM effect-bound permit cryptographic primitive.

Not a VERITAS native authorization bridge and not dispatch authority.
No target effects or production credentials.
"""
from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime, timezone
from typing import Any, Mapping
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REQUIRED = frozenset({
    "version", "issuer", "audience", "permit_id", "authorization_id",
    "execution_intent_id", "request_id", "method", "path", "subject",
    "role", "scope", "not_before", "expires_at",
})
SOURCE_FIELDS_V2 = frozenset({
    "source_envelope", "original_request_digest", "candidate_digest",
    "source_attestation_digest", "source_nonce_sha256",
})
V2 = "isolated-iam-permit-v2-source-bound"

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
    if not isinstance(payload, Mapping):
        raise PermitRejected("invalid_permit_fields")
    version = payload.get("version")
    if version == EXPECTED["version"]:
        if set(payload) != REQUIRED:
            raise PermitRejected("invalid_permit_fields")
    elif version == V2:
        if set(payload) != (REQUIRED | SOURCE_FIELDS_V2):
            raise PermitRejected("invalid_v2_permit_fields")
        source = payload.get("source_envelope")
        if (type(source) is not dict or set(source) != {"payload", "signature"}
                or type(source.get("payload")) is not dict
                or type(source.get("signature")) is not str):
            raise PermitRejected("invalid_source_envelope")
        if any(type(payload.get(field)) is not str
               or re.fullmatch(r"[a-f0-9]{64}", payload[field]) is None
               for field in SOURCE_FIELDS_V2 - {"source_envelope"}):
            raise PermitRejected("invalid_v2_source_hash")
    else:
        raise PermitRejected("permit_version_unsupported")
    if any(type(payload.get(key)) is not str or not payload[key]
           for key in REQUIRED):
        raise PermitRejected("invalid_permit_fields")
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PermitRejected("noncanonical_permit_fields") from exc


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
    if any(payload[key] != value for key, value in EXPECTED.items() if key != "version"):
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
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise PermitRejected("invalid_permit_signature") from exc
    validate_claims(payload, now)
    return dict(payload)
