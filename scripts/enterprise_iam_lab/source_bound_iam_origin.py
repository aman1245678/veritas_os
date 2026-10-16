"""#2383 opt-in signed RCC-shaped IAM proposal admission before native issuance.

This is an isolated, SAME-HOST synthetic origin, not RCC #416's local-counter
permission, not an actual upstream AgentDojo request, and not production.
The signed original request and exact IAM action are DATA, never authority.
Native signed Human Approval + durable Bind consumption remain mandatory.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
    load_pem_public_key,
)
from scripts.enterprise_iam_lab.signed_permit import EXPECTED

SCHEMA = "rcc-controlled-synthetic-iam-origin/v1"
BRIDGE_SCHEMA = "iam-2383-source-admission-to-native-consume/v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_FIELDS = frozenset((
    "schema", "original_request", "original_request_digest", "candidate",
    "candidate_digest", "issued_at", "expires_at", "nonce", "production_claim",
))
PROJECTION_FIELDS = frozenset((
    "candidate_id", "actor_identity", "action_type", "intended_action",
    "target_system", "target_resource", "required_authority",
    "required_human_approval",
))
TARGET = {
    "action_type": "synthetic_external_webhook",
    "intended_action": "grant_admin_role",
    "target_system": "isolated-iam-target",
    "target_resource": "contractor-001",
    "required_authority": ["saas:grant_admin"],
    "required_human_approval": True,
}


class SourceAdmissionDenied(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise SourceAdmissionDenied("IAM2383_" + reason)


def canonical(item: object) -> bytes:
    return json.dumps(item, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(item: object) -> str:
    return hashlib.sha256(canonical(item)).hexdigest()


def _clock(value: object) -> datetime:
    require(type(value) is str, "INVALID_SOURCE_CLOCK")
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        raise SourceAdmissionDenied("IAM2383_INVALID_SOURCE_CLOCK") from None
    require(result.tzinfo is not None, "UNZONED_SOURCE_CLOCK")
    return result.astimezone(timezone.utc)


def project(candidate: dict) -> dict:
    require(type(candidate) is dict and PROJECTION_FIELDS <= set(candidate),
            "NATIVE_CANDIDATE_FIELDS_MISSING")
    values = {key: candidate[key] for key in sorted(PROJECTION_FIELDS)}
    require(type(values["required_authority"]) is list, "SCOPE_INVALID")
    return values


def validate_source(payload: object, *, now: datetime) -> dict:
    require(type(payload) is dict and set(payload) == SOURCE_FIELDS,
            "SOURCE_SCHEMA_FIELDS_INVALID")
    require(payload["schema"] == SCHEMA and payload["production_claim"] is False,
            "SOURCE_NOT_SYNTHETIC")
    request = payload["original_request"]
    candidate = payload["candidate"]
    require(type(request) is dict and set(request) ==
            {"source", "actor_identity", "target_system", "target_resource",
             "intended_action", "scope", "role", "user_request"},
            "ORIGINAL_REQUEST_FIELDS_INVALID")
    require(request["source"] == "rcc-revas-controlled-synthetic-iam-request"
            and type(request["user_request"]) is str
            and len(request["user_request"]) >= 15,
            "ORIGINAL_REQUEST_SOURCE_INVALID")
    require(type(candidate) is dict and set(candidate) == PROJECTION_FIELDS,
            "CANDIDATE_SCHEMA_INVALID")
    for name, expected in TARGET.items():
        require(candidate.get(name) == expected, "IAM_ACTION_SCOPE_DRIFT:" + name)
    require(type(candidate.get("candidate_id")) is str
            and bool(candidate["candidate_id"])
            and type(candidate.get("actor_identity")) is str
            and bool(candidate["actor_identity"]),
            "CANDIDATE_IDENTITY_INVALID")
    require(request["actor_identity"] == candidate["actor_identity"]
            and request["target_system"] == candidate["target_system"]
            and request["target_resource"] == candidate["target_resource"]
            and request["intended_action"] == candidate["intended_action"]
            and request["scope"] == EXPECTED["scope"]
            and request["role"] == EXPECTED["role"],
            "ORIGINAL_REQUEST_CANDIDATE_MISMATCH")
    require(type(payload["original_request_digest"]) is str
            and payload["original_request_digest"] == sha(request)
            and type(payload["candidate_digest"]) is str
            and payload["candidate_digest"] == sha(candidate),
            "SOURCE_COMMITMENT_INVALID")
    require(type(payload["nonce"]) is str and
            HEX64.fullmatch(payload["nonce"]) is not None,
            "SOURCE_NONCE_INVALID")
    issued = _clock(payload["issued_at"])
    expires = _clock(payload["expires_at"])
    require(isinstance(now, datetime) and now.tzinfo is not None,
            "VERIFIER_TRUSTED_CLOCK_REQUIRED")
    utc = now.astimezone(timezone.utc)
    require(timedelta(0) < expires - issued <= timedelta(seconds=120)
            and issued <= utc < expires
            and issued > utc - timedelta(seconds=120),
            "SOURCE_EXPIRED_OR_FUTURE")
    return payload


def verify_origin(envelope: dict, public_pem: bytes, *, now: datetime) -> dict:
    require(type(envelope) is dict and set(envelope) == {"payload", "signature"}
            and type(envelope["signature"]) is str, "SOURCE_ENVELOPE_INVALID")
    require(type(public_pem) is bytes, "SOURCE_TRUST_KEY_REQUIRED")
    try:
        public = load_pem_public_key(public_pem)
        require(isinstance(public, Ed25519PublicKey), "SOURCE_KEY_NOT_ED25519")
        raw = base64.b64decode(envelope["signature"], validate=True)
        public.verify(raw, canonical(envelope["payload"]))
    except (ValueError, TypeError, binascii.Error, InvalidSignature) as exc:
        raise SourceAdmissionDenied("IAM2383_SOURCE_SIGNATURE_INVALID") from exc
    return validate_source(envelope["payload"], now=now)


def verify_selected_candidate(payload: dict, selected: dict) -> None:
    require(project(selected) == payload["candidate"],
            "RCC_CANDIDATE_NOT_ACTUAL_NATIVE_SELECTION")


def issue_synthetic_origin(source_dir: Path, public_dir: Path, output: Path) -> dict:
    """Separate fixture process. Its private key is never passed to native issuer."""
    # Explicit controlled, IAM-specific source; never reuse #416's counter grant.
    from scripts import run_decision_to_external_bind_poc as poc
    base = poc._candidate()
    candidate = replace(base, evidence_refs=["synthetic:local-review-input"],
                        required_human_approval=True,
                        intended_action=TARGET["intended_action"],
                        target_system=TARGET["target_system"],
                        target_resource=TARGET["target_resource"],
                        required_authority=list(TARGET["required_authority"]))
    chosen = project(candidate.to_dict())
    request = {
        "source": "rcc-revas-controlled-synthetic-iam-request",
        "actor_identity": chosen["actor_identity"],
        "target_system": chosen["target_system"],
        "target_resource": chosen["target_resource"],
        "intended_action": chosen["intended_action"],
        "scope": EXPECTED["scope"],
        "role": EXPECTED["role"],
        "user_request": "Grant admin to contractor-001 in isolated synthetic IAM.",
    }
    now = datetime.now(timezone.utc)
    payload = {
        "schema": SCHEMA,
        "original_request": request,
        "original_request_digest": sha(request),
        "candidate": chosen,
        "candidate_digest": sha(chosen),
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=120)).isoformat(),
        "nonce": secrets.token_hex(32),
        "production_claim": False,
    }
    validate_source(payload, now=now)
    signer = Ed25519PrivateKey.generate()
    private = signer.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public = signer.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    (source_dir / "origin-private.pem").write_bytes(private)
    (source_dir / "origin-private.pem").chmod(0o600)
    (public_dir / "origin-public.pem").write_bytes(public)
    signed = {"payload": payload,
              "signature": base64.b64encode(signer.sign(canonical(payload))).decode("ascii")}
    require(not output.exists(), "SOURCE_OUTPUT_EXISTS")
    output.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    return {"result": "PASS", "source_schema": SCHEMA,
            "original_request_digest": payload["original_request_digest"],
            "candidate_digest": payload["candidate_digest"],
            "synthetic_origin_only": True, "production_claim": False}


def signed_native_bridge(payload: dict, issuer_receipt: dict,
                         signer: Ed25519PrivateKey) -> dict:
    """Issuer-signed evidence map, not a target-enforced Permit claim."""
    require(type(issuer_receipt) is dict and
            issuer_receipt.get("native_authorization_consumed") is True
            and issuer_receipt.get("native_signed_human_approval_verified") is True
            and issuer_receipt.get("native_store_durable") is True
            and issuer_receipt.get("external_iam_provider_called") is False,
            "NATIVE_BIND_NOT_VERIFIED")
    bridge = {
        "schema": BRIDGE_SCHEMA,
        "original_request_digest": payload["original_request_digest"],
        "candidate_digest": payload["candidate_digest"],
        "source_attestation_digest": sha(payload),
        "source_nonce_sha256": hashlib.sha256(payload["nonce"].encode("ascii")).hexdigest(),
        "native_request_id": issuer_receipt["request_id"],
        "native_execution_intent_id": issuer_receipt["execution_intent_id"],
        "native_authorization_id": issuer_receipt["authorization_id"],
        "native_consumption_id": issuer_receipt["consumption_id"],
        "permit_id": issuer_receipt["permit_id"],
        "approved_iam_scope": EXPECTED["scope"],
        "approved_iam_target": EXPECTED["path"],
        "target_enforces_source_digest": False,
        "actual_rcc_canonical_416_imported": False,
        "production_claim": False,
    }
    return {"payload": bridge,
            "signature": base64.b64encode(signer.sign(canonical(bridge))).decode("ascii")}


def verify_native_bridge(signed: dict, public_pem: bytes,
                         origin_payload: dict, receipt: dict) -> dict:
    require(type(signed) is dict and set(signed) == {"payload", "signature"}
            and type(signed["payload"]) is dict
            and type(signed["signature"]) is str,
            "NATIVE_BRIDGE_ENVELOPE_INVALID")
    try:
        signer = load_pem_public_key(public_pem)
        require(isinstance(signer, Ed25519PublicKey), "NATIVE_BRIDGE_SIGNER_INVALID")
        signer.verify(base64.b64decode(signed["signature"], validate=True),
                      canonical(signed["payload"]))
    except (TypeError, ValueError, InvalidSignature, binascii.Error) as exc:
        raise SourceAdmissionDenied("IAM2383_NATIVE_BRIDGE_SIGNATURE_INVALID") from exc
    b = signed["payload"]
    require(b.get("schema") == BRIDGE_SCHEMA and len(b) == 15
            and b.get("original_request_digest") == origin_payload["original_request_digest"]
            and b.get("candidate_digest") == origin_payload["candidate_digest"]
            and b.get("source_attestation_digest") == sha(origin_payload)
            and b.get("source_nonce_sha256") ==
            hashlib.sha256(origin_payload["nonce"].encode("ascii")).hexdigest(),
            "NATIVE_BRIDGE_SOURCE_CHANGED")
    for key, source in (
        ("native_request_id", "request_id"),
        ("native_execution_intent_id", "execution_intent_id"),
        ("native_authorization_id", "authorization_id"),
        ("native_consumption_id", "consumption_id"),
        ("permit_id", "permit_id"),
    ):
        require(b.get(key) == receipt.get(source), "NATIVE_BRIDGE_ID_DRIFT:" + key)
    require(b.get("approved_iam_scope") == EXPECTED["scope"]
            and b.get("approved_iam_target") == EXPECTED["path"]
            and b.get("target_enforces_source_digest") is False
            and b.get("actual_rcc_canonical_416_imported") is False
            and b.get("production_claim") is False,
            "NATIVE_BRIDGE_CLAIM_DRIFT")
    return b


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("prepare-synthetic-origin", "verify-evidence"))
    parser.add_argument("--origin-dir", type=Path)
    parser.add_argument("--trust-dir", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--issuer-receipt", type=Path)
    parser.add_argument("--native-bridge", type=Path)
    args = parser.parse_args()
    if args.phase == "prepare-synthetic-origin":
        require(args.origin_dir is not None and args.origin_dir.is_dir()
                and args.trust_dir.is_dir(), "PREPARE_DIRECTORIES_REQUIRED")
        result = issue_synthetic_origin(args.origin_dir, args.trust_dir,
                                        args.attestation)
    else:
        require(args.issuer_receipt is not None and args.native_bridge is not None,
                "VERIFY_INPUTS_REQUIRED")
        payload = verify_origin(json.loads(args.attestation.read_text()),
                                (args.trust_dir / "origin-public.pem").read_bytes(),
                                now=datetime.now(timezone.utc))
        receipt = json.loads(args.issuer_receipt.read_text())
        bridge = verify_native_bridge(json.loads(args.native_bridge.read_text()),
                                      (args.trust_dir / "permit-public.pem").read_bytes(),
                                      payload, receipt)
        result = {"result": "PASS", "bridge_schema": bridge["schema"],
                  "native_source_admission_verified": True,
                  "same_host_fixture_only": True,
                  "real_rcc_original_request_loaded": False,
                  "target_enforces_source_digest": False,
                  "production_claim": False}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
