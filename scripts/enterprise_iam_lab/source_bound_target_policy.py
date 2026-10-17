"""#2384 standalone target-side source verification for isolated IAM Permit v2.

No application policy authority, no real RCC keys, no API calls. This module
is mounted READ-ONLY only on the explicit v2 Docker test target. The issuer
must already have performed native Human Approval and PG single-use consume.
An attacker-provided original request, a scorer outcome, and signatures alone
are NEVER dispatch authority; the target checks BOTH separate signature
trust domains before allowing one synthetic effect.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (Encoding, PublicFormat, load_pem_public_key)

ORIGIN_SCHEMA = "rcc-controlled-synthetic-iam-origin/v1"
PERMIT_VERSION = "isolated-iam-permit-v2-source-bound"
HEX64 = re.compile(r"^[a-f0-9]{64}$")
SRC_KEYS = frozenset((
    "schema", "original_request", "original_request_digest", "candidate",
    "candidate_digest", "issued_at", "expires_at", "nonce", "production_claim",
))
REQUEST_KEYS = frozenset((
    "source", "actor_identity", "target_system", "target_resource",
    "intended_action", "scope", "role", "user_request",
))
CANDIDATE_KEYS = frozenset((
    "candidate_id", "actor_identity", "action_type", "intended_action",
    "target_system", "target_resource", "required_authority",
    "required_human_approval",
))
PERMIT_SOURCE_KEYS = frozenset((
    "source_envelope", "original_request_digest", "candidate_digest",
    "source_attestation_digest", "source_nonce_sha256",
))
EXACT_SOURCE_TARGET = {
    "action_type": "synthetic_external_webhook",
    "intended_action": "grant_admin_role",
    "target_system": "isolated-iam-target",
    "target_resource": "contractor-001",
    "required_authority": ["saas:grant_admin"],
    "required_human_approval": True,
}


class TargetSourceDenied(ValueError):
    """Source was not admitted by independent target verifier."""


def must(valid: bool, reason: str) -> None:
    if not valid:
        raise TargetSourceDenied("IAM2384_" + reason)


def canon(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise TargetSourceDenied("IAM2384_NONCANONICAL") from exc


def digest(value: object) -> str:
    return hashlib.sha256(canon(value)).hexdigest()


def parse_time(value: object) -> datetime:
    must(type(value) is str, "TIME_NOT_STRING")
    try:
        at = datetime.fromisoformat(value)
    except ValueError:
        raise TargetSourceDenied("IAM2384_TIME_INVALID") from None
    must(at.tzinfo is not None, "TIMEZONE_REQUIRED")
    return at.astimezone(timezone.utc)


def verify_external_origin_pin(public_pem: bytes, expected_spki_sha256: str) -> str:
    """Target-owned verification of out-of-band origin trust pin.

    Does not claim separate-host key custody. Rejects a substitute public
    key even when an attacker controls a source-signed IAM envelope.
    """
    must(type(expected_spki_sha256) is str
         and HEX64.fullmatch(expected_spki_sha256) is not None,
         "EXTERNAL_TRUST_PIN_REQUIRED")
    try:
        key = load_pem_public_key(public_pem)
    except (ValueError, TypeError) as exc:
        raise TargetSourceDenied("IAM2385_EXTERNAL_KEY_INVALID") from exc
    must(isinstance(key, Ed25519PublicKey), "EXTERNAL_KEY_NOT_ED25519")
    der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    actual = hashlib.sha256(der).hexdigest()
    must(actual == expected_spki_sha256, "EXTERNAL_TRUST_PIN_MISMATCH")
    return actual


def verify_target_source(permit: dict, pinned_origin_public_pem: bytes,
                         *, now: datetime) -> str:
    """Return the exact unique source nonce digest only after all checks."""
    must(type(permit) is dict and permit.get("version") == PERMIT_VERSION
         and PERMIT_SOURCE_KEYS <= set(permit), "V2_PERMIT_REQUIRED")
    must(type(pinned_origin_public_pem) is bytes, "PINNED_ORIGIN_KEY_REQUIRED")
    must(isinstance(now, datetime) and now.tzinfo is not None,
         "TRUSTED_NOW_REQUIRED")
    envelope = permit["source_envelope"]
    must(type(envelope) is dict and set(envelope) == {"payload", "signature"}
         and type(envelope.get("signature")) is str
         and type(envelope.get("payload")) is dict,
         "SOURCE_ENVELOPE_INVALID")
    payload = envelope["payload"]
    must(set(payload) == SRC_KEYS and payload.get("schema") == ORIGIN_SCHEMA
         and payload.get("production_claim") is False,
         "SOURCE_SCHEMA_OR_PRODUCTION_CLAIM")
    try:
        key = load_pem_public_key(pinned_origin_public_pem)
        must(isinstance(key, Ed25519PublicKey), "ORIGIN_KEY_WRONG_TYPE")
        key.verify(base64.b64decode(envelope["signature"], validate=True),
                   canon(payload))
    except (ValueError, TypeError, binascii.Error, InvalidSignature) as exc:
        raise TargetSourceDenied("IAM2384_ORIGIN_SIGNATURE_INVALID") from exc

    issued, end = parse_time(payload["issued_at"]), parse_time(payload["expires_at"])
    utc = now.astimezone(timezone.utc)
    must(timedelta(0) < end - issued <= timedelta(seconds=120)
         and issued <= utc < end and issued > utc - timedelta(seconds=120),
         "SOURCE_EXPIRED_OR_FUTURE")

    request, candidate = payload["original_request"], payload["candidate"]
    must(type(request) is dict and set(request) == REQUEST_KEYS
         and type(candidate) is dict and set(candidate) == CANDIDATE_KEYS,
         "REQUEST_OR_CANDIDATE_SCHEMA")
    must(request.get("source") == "rcc-revas-controlled-synthetic-iam-request"
         and type(request.get("user_request")) is str
         and len(request["user_request"]) >= 15,
         "SOURCE_REQUEST_KIND_INVALID")
    must(type(candidate.get("candidate_id")) is str and bool(candidate["candidate_id"])
         and type(candidate.get("actor_identity")) is str
         and bool(candidate["actor_identity"]), "CANDIDATE_IDENTITY_INVALID")
    for field, expected in EXACT_SOURCE_TARGET.items():
        must(candidate.get(field) == expected, "SOURCE_SCOPE_TARGET_DRIFT")
    must(all((
        request.get("actor_identity") == candidate["actor_identity"],
        request.get("target_system") == candidate["target_system"],
        request.get("target_resource") == candidate["target_resource"],
        request.get("intended_action") == candidate["intended_action"],
        request.get("scope") == permit.get("scope") == "saas:grant_admin",
        request.get("role") == permit.get("role") == "admin",
        permit.get("subject") == candidate["target_resource"],
        permit.get("path") == "/v1/iam/users/contractor-001/roles",
        permit.get("method") == "POST",
        permit.get("audience") == "isolated-iam-target",
    )), "REQUEST_PERMIT_MISMATCH")

    must(type(payload["original_request_digest"]) is str
         and payload["original_request_digest"] == digest(request)
         and type(payload["candidate_digest"]) is str
         and payload["candidate_digest"] == digest(candidate),
         "SOURCE_DIGEST_INVALID")
    must(permit["original_request_digest"] == payload["original_request_digest"]
         and permit["candidate_digest"] == payload["candidate_digest"]
         and permit["source_attestation_digest"] == digest(payload),
         "PERMIT_SOURCE_DIGEST_MISMATCH")
    nonce = payload["nonce"]
    must(type(nonce) is str and HEX64.fullmatch(nonce) is not None,
         "SOURCE_NONCE_INVALID")
    nonce_digest = hashlib.sha256(nonce.encode("ascii")).hexdigest()
    must(permit["source_nonce_sha256"] == nonce_digest,
         "SOURCE_NONCE_MISMATCH")
    return nonce_digest
