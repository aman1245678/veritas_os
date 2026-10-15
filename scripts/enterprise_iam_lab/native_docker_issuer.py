#!/usr/bin/env python3
"""Disposable, test-only REAL native approval/consume -> Docker mTLS permit issuer.

PREPARE pins the verifier public key on target before it starts. ISSUE invokes
the genuine synthetic /v1/decide -> native Ed25519 Human Approval -> native
atomic consume-only verification path and signs ONLY after consume succeeds.
No production credentials, provider API, real IAM system, or billable calls.
Native store is IN-MEMORY TEST ONLY, not durable multi-process authority.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

# Direct script execution must resolve the repository's namespace packages,
# not import an unrelated installed "scripts" package.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key,
)

from scripts.enterprise_iam_lab import native_permit_bridge as bridge
from scripts.enterprise_iam_lab.signed_permit import (
    EXPECTED, canonical, sign_permit, verify_permit,
)
from veritas_os.policy.canonical_verified_decision_promotion import (
    build_canonical_verified_decision_promotion_packet,
)
from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
    InMemoryAtomicAuthorizationConsumptionStore,
    PostgresAtomicAuthorizationConsumptionStore,
)
from veritas_os.storage.db import close_pool
from veritas_os.tests.helpers.native_approval_source import build_native_authority_source
from veritas_os.tests.test_native_bind_authorization import _setup
from veritas_os.tests.test_native_bind_authorization_consumption import _fresh
from veritas_os.tests.test_promotion_human_approval_requirement_satisfaction import _contract

PUBLIC_NAME = "permit-public.pem"
KEY_NAME = "ephemeral-native-issuer-private.pem"
RECEIPT = "native_issuer_receipt.json"


def _write_exclusive(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "wb") as sink:
        sink.write(payload)


def prepare(issuer_dir: Path, trust_dir: Path) -> None:
    if not issuer_dir.is_dir() or not trust_dir.is_dir():
        raise ValueError("disposable issuer and public verifier folders required")
    signer = Ed25519PrivateKey.generate()
    _write_exclusive(
        issuer_dir / KEY_NAME,
        signer.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
    )
    _write_exclusive(
        trust_dir / PUBLIC_NAME,
        signer.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        mode=0o644,
    )
    print(json.dumps({
        "phase": "prepare", "result": "PASS",
        "issuer_private_key_mounted": False, "production_claim": False,
    }, sort_keys=True))


def _native_fixture(issuer_dir: Path):
    capture_path = issuer_dir / ("capture-" + secrets.token_hex(8) + ".json")
    subprocess.run(
        [
            sys.executable, "-m", "veritas_os.tests.helpers.live_decision_capture",
            str(capture_path), "--synthetic-iam-grant",
        ],
        cwd=ROOT, check=True, capture_output=True, text=True, timeout=180,
    )
    captured = json.loads(capture_path.read_text(encoding="utf-8"))
    assert captured["pipeline_ok"] is True
    assert captured["candidate"]["intended_action"] == bridge.ACTION
    assert captured["candidate"]["required_human_approval"] is True
    assert captured["candidate"]["required_authority"] == [EXPECTED["scope"]]
    now = datetime.fromisoformat(captured["observed_at"])
    assert now.tzinfo is not None
    promotion = build_canonical_verified_decision_promotion_packet(
        captured["canonical_decision_artifact"], captured["candidate"],
        promoted_at=now, ttl_seconds=300,
        expected_state_fingerprint="synthetic:observed-state:one",
    )
    source = build_native_authority_source(
        promotion, now,
        authority_scope=EXPECTED["scope"],
        endpoint_overrides={
            "endpoint_candidate_id": "endpoint:isolated:iam:2375",
            "endpoint_host": "iam-target",
            "endpoint_port": 8443,
            "endpoint_path_prefix": EXPECTED["path"],
            "endpoint_environment": "isolated-lab",
            "endpoint_purpose": "synthetic-native-docker-proof",
        },
        credential_overrides={
            "credential_reference_id": "credential:isolated:iam:2375",
            "credential_scope": EXPECTED["scope"],
            "credential_environment": "isolated-lab",
            "credential_purpose": "synthetic-native-docker-proof",
        },
    )
    contract = replace(
        _contract(action=bridge.ACTION, required=True),
        allowed_scope=[EXPECTED["scope"]], prohibited_scope=[],
        description="Isolated synthetic IAM grant with signed human approval",
    )
    contract.irreversibility["boundary"] = "future-bind-consumption"
    # The signed authorizer's short window must remain WITHIN a separately
    # verified runtime risk decision (30s in these synthetic fixtures).
    artifact, issuance, *_ = _setup(
        source, contract, now, validity_seconds=26,
    )
    assert artifact.human_approval_requirement_status == "VERIFIED"
    assert artifact.signed_human_approval_artifact is not None
    assert artifact.execution_intent["intended_action"] == bridge.ACTION
    return artifact, issuance, captured


async def issue(issuer_dir: Path, trust_dir: Path, permit_dir: Path,
                evidence_dir: Path, *, durable_postgres: bool = False,
                persist_effect_in_flight: bool = False) -> dict:
    """Use only trusted exact store classes; PostgreSQL is mandatory in durable mode."""
    if type(durable_postgres) is not bool:
        raise ValueError("IAM_NATIVE_STORE_MODE_INVALID")
    if persist_effect_in_flight and not durable_postgres:
        raise ValueError("IAM_DURABLE_EFFECT_TRACKING_REQUIRES_POSTGRES")
    if durable_postgres and not os.getenv("VERITAS_DATABASE_URL", "").startswith(
        ("postgresql://", "postgresql+psycopg://")
    ):
        raise ValueError("IAM_NATIVE_REAL_POSTGRES_REQUIRED")
    key_file = issuer_dir / KEY_NAME
    if not key_file.is_file() or not permit_dir.is_dir() or not evidence_dir.is_dir():
        raise ValueError("prepared trusted issuer and output dirs required")
    signer = load_pem_private_key(key_file.read_bytes(), password=None)
    if not isinstance(signer, Ed25519PrivateKey):
        raise ValueError("wrong signer kind")
    public = signer.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo,
    )
    assert (trust_dir / PUBLIC_NAME).read_bytes() == public

    artifact, issuance, captured = _native_fixture(issuer_dir)
    # Use the REAL wall clock for the Docker target. Never patch its clock.
    earliest = issuance["governance_inputs"].verification_now + timedelta(seconds=1)
    actual = datetime.now(timezone.utc)
    if actual < earliest:
        time.sleep((earliest - actual).total_seconds())
    actual = datetime.now(timezone.utc)
    expires = datetime.fromisoformat(artifact.valid_until)
    if expires - actual < timedelta(seconds=6):
        raise ValueError("NATIVE_WINDOW_TOO_SHORT_FOR_DOCKER_TRANSPORT")
    risk, current = _fresh(issuance, actual)
    store = (
        PostgresAtomicAuthorizationConsumptionStore()
        if durable_postgres else InMemoryAtomicAuthorizationConsumptionStore()
    )
    try:
        envelope = await bridge.issue_iam_permit_after_native_consumption(
            artifact,
            deployment_pin=bridge.IAMPermitDeploymentPin(
                execution_intent_id=artifact.execution_intent_id,
                execution_intent_hash=artifact.execution_intent_hash,
                bind_context_hash=artifact.bind_context_hash,
                action_contract_digest=artifact.action_contract_digest,
            ),
            issuance_source_inputs=issuance["source_inputs"],
            governance_inputs=issuance["governance_inputs"],
            trust_inputs=issuance["trust_inputs"],
            current_source_inputs=current,
            current_runtime_risk_packet=risk,
            now=actual,
            consumption_store=store,
            signer=signer,
            allow_in_memory_for_testing=not durable_postgres,
        )
        verified = verify_permit(envelope, signer.public_key(), actual)
        entry = await store.get(artifact.authorization_id)
        if persist_effect_in_flight:
            if entry is None:
                raise ValueError("IAM_CONSUMED_RECORD_REQUIRED_FOR_EFFECT_TRACKING")
            from veritas_os.policy.bind_effect_reconciliation import (
                EffectExecutionState, PostgresAtomicEffectStateStore,
            )
            from veritas_os.policy.bind_effect_runtime import (
                recover_in_flight_after_consumption,
            )
            # Create the durable IN_FLIGHT marker after consumption and
            # before making the executable permit available to Docker.
            # It is NOT confirmation of a target effect or an execution grant.
            effect_state = await recover_in_flight_after_consumption(
                consumption=entry,
                effect_store=PostgresAtomicEffectStateStore(),
                updated_at=datetime.now(timezone.utc),
            )
            if effect_state.state != EffectExecutionState.IN_FLIGHT:
                raise ValueError("IAM_EFFECT_STATE_NOT_IN_FLIGHT")
    finally:
        if durable_postgres:
            await close_pool()
    assert entry is not None, "no target permit without atomic native consumption"
    assert entry.live_adapter_bind_authorization_id == artifact.authorization_id
    assert entry.execution_intent_id == artifact.execution_intent_id
    assert verified["authorization_id"] == artifact.authorization_id
    assert verified["execution_intent_id"] == artifact.execution_intent_id
    assert verified["request_id"] == artifact.idempotency_key
    # A transport beyond token expiry is a FAILURE; never extend validity
    # or forge a replacement permit from an unverified success boolean.
    if datetime.fromisoformat(verified["expires_at"]) - datetime.now(timezone.utc) < timedelta(seconds=3):
        raise ValueError("NATIVE_PERMIT_EXPIRED_BEFORE_TRANSFER")
    invalid = sign_permit(verified, Ed25519PrivateKey.generate())
    tampered = {
        "payload": {**verified, "scope": "saas:read"},
        "signature": envelope["signature"],
    }
    # Issuer and permit output directories are host-only and never mounted on
    # agent. Executor gets only the bearer permit + scoped client certificate.
    for filename, value in (
        ("valid.json", envelope), ("tampered.json", tampered),
        ("wrong-signer.json", invalid),
    ):
        _write_exclusive(
            permit_dir / filename,
            (json.dumps(value, sort_keys=True) + "\n").encode("utf-8"),
        )
        os.chmod(permit_dir / filename, 0o644)

    receipt = {
        "result": "PASS",
        "issuer_mode": (
            "REAL_NATIVE_POSTGRES_CONSUME_TEST_ONLY"
            if durable_postgres else "REAL_NATIVE_CONSUME_TEST_ONLY"
        ),
        "native_veritas_authorization_exercised": True,
        "native_signed_human_approval_verified": True,
        "native_authorization_consumed": True,
        "native_store_durable": durable_postgres,
        "durable_in_flight_created": persist_effect_in_flight,
        "native_in_memory_test_override": not durable_postgres,
        "authorization_id": artifact.authorization_id,
        "authorization_hash": artifact.authorization_hash,
        "execution_intent_id": artifact.execution_intent_id,
        "request_id": artifact.idempotency_key,
        "permit_id": verified["permit_id"],
        "consumption_id": entry.consumption_id,
        "consumption_hash": entry.consumption_hash,
        "consumption_recorded_at": entry.consumed_at,
        "approval_proof_digest": artifact.human_approval_verification_proof_digest,
        "permit_payload_sha256": hashlib.sha256(canonical(verified)).hexdigest(),
        "permit_not_before": verified["not_before"],
        "permit_expires_at": verified["expires_at"],
        "decision_pipeline_ok": captured["pipeline_ok"],
        "synthetic_provider_clients_only": True,
        "production_claim": False,
        "external_iam_provider_called": False,
    }
    (evidence_dir / RECEIPT).write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("prepare", "issue"), required=True)
    parser.add_argument("--issuer-dir", type=Path, required=True)
    parser.add_argument("--trust-dir", type=Path, required=True)
    parser.add_argument("--permit-dir", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--durable-postgres", action="store_true")
    parser.add_argument("--persist-effect-in-flight", action="store_true")
    args = parser.parse_args()
    if args.phase == "prepare":
        prepare(args.issuer_dir, args.trust_dir)
        return
    if args.permit_dir is None or args.evidence_dir is None:
        raise ValueError("issue requires permit/evidence dirs")
    # Print only safe bounded fields; never print signed permits or key bytes.
    receipt = asyncio.run(issue(
        args.issuer_dir, args.trust_dir, args.permit_dir, args.evidence_dir,
        durable_postgres=args.durable_postgres,
        persist_effect_in_flight=args.persist_effect_in_flight,
    ))
    print(json.dumps({
        "result": receipt["result"], "issuer_mode": receipt["issuer_mode"],
        "native_authorization_consumed": receipt["native_authorization_consumed"],
        "native_store_durable": receipt["native_store_durable"],
        "production_claim": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
