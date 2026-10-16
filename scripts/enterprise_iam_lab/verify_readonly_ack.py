#!/usr/bin/env python3
"""#2379 bounded signed, mTLS-protected, read-only target observation proof.

Intentionally never opens target-owned SQLite or calls target's mutation POST.
Verifies a receipt obtained by a SEPARATE Docker reader and joins it to the
existing REAL PostgreSQL native authorization-consumption record.

The host generated the disposable signer key and therefore is NOT an
independent operator. No EFFECT_UNKNOWN->CONFIRMED_EFFECT CAS in #2379.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from scripts.enterprise_iam_lab.reconcile_native_lost_ack import require
from scripts.enterprise_iam_lab.signed_permit import (
    canonical as canonical_permit, verify_permit,
)
from scripts.enterprise_iam_lab.target_readonly_receipt import (
    SCHEMA, SOURCE_IDENTITY, canonical,
)
from scripts.enterprise_iam_lab.verify_transport import verify_topology
from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
    PostgresAtomicAuthorizationConsumptionStore,
)
from veritas_os.storage.db import close_pool


STATUS = "SYNTHETIC_SIGNED_TARGET_MTLS_READONLY_RECEIPT_NOT_PRODUCTION_PROVEN"


def read_json(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), "IAM2379_EVIDENCE_MISSING")
    data = json.loads(path.read_text(encoding="utf-8"))
    require(type(data) is dict, "IAM2379_EVIDENCE_MALFORMED")
    return data


def read_known_response_issuer(folder: Path, trust: Path,
                               permit_dir: Path) -> tuple[dict, dict]:
    """Verify #2379's known-response native Permit; never bypass #2377's
    required IN_FLIGHT scope or change that protected helper.
    """
    receipt = read_json(folder / "native_issuer_receipt.json")
    require(
        receipt.get("issuer_mode") == "REAL_NATIVE_POSTGRES_CONSUME_TEST_ONLY"
        and receipt.get("native_store_durable") is True
        and receipt.get("native_in_memory_test_override") is False
        and receipt.get("durable_in_flight_created") is False
        and receipt.get("native_authorization_consumed") is True
        and receipt.get("production_claim") is False,
        "IAM2379_UNTRUSTED_KNOWN_RESPONSE_ISSUER",
    )
    public = load_pem_public_key((trust / "permit-public.pem").read_bytes())
    require(isinstance(public, Ed25519PublicKey),
            "IAM2379_NATIVE_ISSUER_KEY_INVALID")
    envelope = read_json(permit_dir / "valid.json")
    issued_at = datetime.fromisoformat(receipt["permit_not_before"])
    require(issued_at.tzinfo is not None, "IAM2379_NATIVE_ISSUE_TIME_INVALID")
    permit = verify_permit(envelope, public, issued_at)
    require(
        permit["permit_id"] == receipt.get("permit_id")
        and permit["authorization_id"] == receipt.get("authorization_id")
        and permit["execution_intent_id"] == receipt.get("execution_intent_id")
        and permit["request_id"] == receipt.get("request_id")
        and hashlib.sha256(canonical_permit(permit)).hexdigest()
        == receipt.get("permit_payload_sha256"),
        "IAM2379_NATIVE_PERMIT_LINEAGE_MISMATCH",
    )
    return receipt, permit


def verify_target_signature(envelope: dict, public_pem: bytes) -> dict:
    require(type(envelope) is dict and set(envelope) == {"payload", "signature"},
            "IAM2379_ACK_ENVELOPE_INVALID")
    payload = envelope["payload"]
    signature = envelope["signature"]
    require(type(signature) is str, "IAM2379_ACK_SIGNATURE_INVALID")
    key = load_pem_public_key(public_pem)
    require(isinstance(key, Ed25519PublicKey), "IAM2379_TARGET_PUBLIC_KEY_INVALID")
    try:
        decoded = base64.b64decode(signature, validate=True)
        key.verify(decoded, canonical(payload))
    except (ValueError, TypeError, binascii.Error, InvalidSignature):
        raise ValueError("IAM2379_ACK_SIGNATURE_INVALID") from None
    require(
        payload["schema"] == SCHEMA
        and payload["source_identity"] == SOURCE_IDENTITY
        and payload["status"] == "committed"
        and payload["external_operation_reference"] == payload["permit_id"]
        and payload["audit_status"] == 201
        and payload["audit_reason"] == "committed"
        and payload["actor"] == "scoped-executor"
        and payload["grant_subject"] == "contractor-001"
        and payload["grant_role"] == "admin",
        "IAM2379_ACK_UNTRUSTED_STATUS_OR_SCOPE",
    )
    return payload


def verify_readonly_topology(config: dict) -> dict:
    verify_topology(config)
    services = config["services"]
    reader = services.get("reconciliation-reader")
    target = services.get("iam-target")
    require(type(reader) is dict and type(target) is dict, "IAM2379_READER_TOPOLOGY_MISSING")
    mounts = {v["target"] for v in reader.get("volumes", [])}
    target_mounts = {v["target"] for v in target.get("volumes", [])}
    require(
        reader.get("read_only") is True
        and "ALL" in reader.get("cap_drop", [])
        and "no-new-privileges:true" in reader.get("security_opt", [])
        and set(reader.get("networks", {})) == {"effect_net"}
        and not reader.get("ports")
        and "/run/lab/refs" in mounts
        and "/run/lab/certs" in mounts
        and "/run/lab/state" not in mounts
        and "/run/lab/permits" not in mounts
        and "/run/lab/ack-private" not in mounts
        and "/run/lab/ack-private" in target_mounts
        and target["environment"].get("LAB_TEST_READONLY_ACK") == "1",
        "IAM2379_READER_CROSS_BOUNDARY_MOUNT_OR_NETWORK",
    )
    for name in ("agent-direct", "scoped-executor", "unscoped-probe", "tls-probe",
                 "reconciliation-wrong-scope", "reconciliation-no-cert"):
        service = services.get(name)
        require(type(service) is dict, "IAM2379_EXPECTED_DENIAL_SERVICE_MISSING")
        denial_mounts = {v["target"] for v in service.get("volumes", [])}
        require("/run/lab/ack-private" not in denial_mounts
                and "/run/lab/state" not in denial_mounts,
                "IAM2379_DENIAL_SERVICE_HAS_TARGET_STATE_OR_SIGNER")
    return {
        "reader_is_separate_docker_service": True,
        "reader_has_no_target_sqlite": True,
        "reader_has_no_effect_permit": True,
        "reader_has_no_target_signer_private_key": True,
        "signer_private_key_only_target_mounted": True,
        "all_effect_networks_internal": True,
    }


def verify_probes(folder: Path) -> dict:
    normal = read_json(folder / "readonly_valid.json")
    wrong = read_json(folder / "readonly_wrong_scope.json")
    missing = read_json(folder / "readonly_missing.json")
    certless = read_json(folder / "readonly_no_certificate.json")
    require(
        normal.get("case_id") == "valid" and normal.get("result") == "PASS"
        and normal.get("status") == 200
        and normal.get("target_http_response_authenticated_via_mtls") is True
        and normal.get("target_receipt_signature_verified") is True
        and normal.get("reader_has_target_sqlite_mount") is False
        and normal.get("reader_has_target_signer_private_key") is False,
        "IAM2379_ALLOWED_READER_OBSERVATION_INVALID",
    )
    for observation, case, code, reason in (
        (wrong, "wrong-scope", 403, "reconciliation_reader_not_authorized"),
        (missing, "missing", 404, "effect_not_confirmed"),
    ):
        require(
            observation.get("case_id") == case
            and observation.get("result") == "PASS"
            and observation.get("observed_http_status") == code
            and observation.get("reason") == reason
            and observation.get("signed_no_effect_proof_generated") is False,
            "IAM2379_READ_ONLY_DENIAL_MISSING:" + case,
        )
    require(
        certless.get("case_id") == "no-certificate"
        and certless.get("result") == "PASS"
        and certless.get("observed_http_status") is None
        and certless.get("expected_tls_denial_observed") is True,
        "IAM2379_READ_ONLY_CERTLESS_ACCESS_NOT_REJECTED",
    )
    return normal["signed_ack"]


async def verify(*, folder: Path, trust: Path, permit_dir: Path,
                 target_pub: Path, config: dict) -> dict:
    topology = verify_readonly_topology(config)
    receipt, permit = read_known_response_issuer(folder, trust, permit_dir)
    target_public = target_pub.read_bytes()
    require(target_public != (trust / "permit-public.pem").read_bytes(),
            "IAM2379_TARGET_AND_ISSUER_SIGNER_MUST_DIFFER")
    envelope = verify_probes(folder)
    ack = verify_target_signature(envelope, target_public)
    require(
        ack["permit_id"] == permit["permit_id"]
        and ack["authorization_id"] == permit["authorization_id"]
        and ack["execution_intent_id"] == permit["execution_intent_id"]
        and ack["request_id"] == permit["request_id"],
        "IAM2379_SIGNED_TARGET_PERMIT_LINEAGE_MISMATCH",
    )
    consumed_at = datetime.fromisoformat(ack["consumed_at"])
    valid_from = datetime.fromisoformat(permit["not_before"])
    expires_at = datetime.fromisoformat(permit["expires_at"])
    require(
        consumed_at.tzinfo is not None
        and valid_from <= consumed_at < expires_at,
        "IAM2379_SIGNED_TARGET_COMMIT_TIME_INVALID",
    )
    store = PostgresAtomicAuthorizationConsumptionStore()
    try:
        original = await store.get(permit["authorization_id"])
        require(original is not None, "IAM2379_DURABLE_NATIVE_CONSUMPTION_MISSING")
        require(
            original.consumption_id == receipt["consumption_id"]
            and original.consumption_hash == receipt["consumption_hash"]
            and original.live_adapter_bind_authorization_id == permit["authorization_id"]
            and original.live_adapter_bind_authorization_hash == receipt["authorization_hash"]
            and original.execution_intent_id == permit["execution_intent_id"]
            and original.idempotency_key == permit["request_id"]
            and datetime.fromisoformat(original.consumed_at) <= consumed_at,
            "IAM2379_SIGNED_TARGET_NATIVE_POSTGRES_JOIN_FAILED",
        )
    finally:
        await close_pool()
    return {
        "result": "PASS", "status": STATUS, **topology,
        "source_identity": SOURCE_IDENTITY,
        "signed_target_commit_verified": True,
        "target_signer_distinct_from_native_issuer": True,
        "mTLS_reader_identity_required": True,
        "missing_target_effect_remains_unknown": True,
        "signed_ack_sha256": hashlib.sha256(canonical(ack)).hexdigest(),
        "real_postgres_native_authorization_consumption_verified": True,
        "single_synthetic_target_effect_observed": True,
        "target_sqlite_read_by_verifier": False,
        "unknown_effect_promoted_to_confirmed": False,
        "independent_operator_key_custody": False,
        "real_enterprise_effects": 0,
        "paid_provider_calls": 0,
        "production_claim": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--trust-dir", required=True, type=Path)
    parser.add_argument("--permit-dir", required=True, type=Path)
    parser.add_argument("--target-public-key", required=True, type=Path)
    parser.add_argument("--compose-config", required=True, type=Path)
    args = parser.parse_args()
    config = read_json(args.compose_config)
    report = asyncio.run(verify(
        folder=args.report_dir, trust=args.trust_dir,
        permit_dir=args.permit_dir, target_pub=args.target_public_key, config=config,
    ))
    (args.report_dir / "iam_target_readonly_ack_verification.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
