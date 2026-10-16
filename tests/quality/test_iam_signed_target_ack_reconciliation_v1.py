"""#2380: fail-closed verification of remote-signed effect before native PG CAS.

Unit fixtures have no cloud IAM or external API. Dedicated workflow tests the
real Docker mTLS receipt and real PostgreSQL state machine in one CI job.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, PublicFormat,
)

from scripts.enterprise_iam_lab.reconcile_signed_target_ack import (
    SOURCE_TYPE, SyntheticSignedMtlsAckVerifier, aware, signature_digest,
    validate_signed_lineage,
)
from scripts.enterprise_iam_lab.target_readonly_receipt import (
    SCHEMA, SOURCE_IDENTITY, canonical,
)
from veritas_os.policy.bind_effect_reconciliation import (
    ReconciliationClaim, ReconciliationEvidence,
)
from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
    build_authorization_consumption_record,
)
from veritas_os.policy.trusted_https_reconciliation import reconciliation_observation_digest


@pytest.fixture()
def paired():
    start = datetime.now(timezone.utc) - timedelta(seconds=3)
    committed = start + timedelta(seconds=1)
    observed = committed + timedelta(seconds=1)
    authorization_id = "laba:v2:sha256:" + "a" * 64
    authorization_hash = "b" * 64
    intent_id = "intent-" + "c" * 64
    intent_hash = "d" * 64
    request_id = "request-" + "e" * 64
    permit_id = "iam-permit:v1:sha256:" + "f" * 64
    native = build_authorization_consumption_record(
        live_adapter_bind_authorization_id=authorization_id,
        live_adapter_bind_authorization_hash=authorization_hash,
        idempotency_key=request_id,
        bind_context_hash="1" * 64,
        execution_intent_id=intent_id,
        execution_intent_hash=intent_hash,
        endpoint_identity_binding_digest="2" * 64,
        credential_reference_digest="3" * 64,
        credential_scope_binding_digest="4" * 64,
        consumed_at=start.isoformat(),
    )
    permit = {
        "permit_id": permit_id, "authorization_id": authorization_id,
        "execution_intent_id": intent_id, "request_id": request_id,
        "not_before": start.isoformat(),
        "expires_at": (start + timedelta(seconds=10)).isoformat(),
    }
    receipt = {
        "permit_id": permit_id, "authorization_id": authorization_id,
        "authorization_hash": authorization_hash,
        "execution_intent_id": intent_id, "request_id": request_id,
        "consumption_id": native.consumption_id,
        "consumption_hash": native.consumption_hash,
    }
    payload = {
        "schema": SCHEMA, "source_identity": SOURCE_IDENTITY,
        "external_operation_reference": permit_id,
        "status": "committed", "permit_id": permit_id,
        "authorization_id": authorization_id, "execution_intent_id": intent_id,
        "request_id": request_id, "actor": "scoped-executor",
        "grant_subject": "contractor-001", "grant_role": "admin",
        "audit_id": 1, "audit_status": 201, "audit_reason": "committed",
        "consumed_at": committed.isoformat(),
    }
    signer = Ed25519PrivateKey.generate()
    import base64
    envelope = {
        "payload": payload,
        "signature": base64.b64encode(signer.sign(canonical(payload))).decode("ascii"),
    }
    target_pub = signer.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo,
    )
    return native, permit, receipt, envelope, target_pub, observed.isoformat()


def test_real_signed_positive_consumption_lineage(paired):
    native, permit, receipt, envelope, public, clock = paired
    ack = validate_signed_lineage(
        envelope=envelope, target_public_pem=public,
        receipt=receipt, permit=permit, native=native, observed_at=clock,
    )
    assert ack["status"] == "committed"
    assert ack["permit_id"] == permit["permit_id"]


@pytest.mark.parametrize("which", (
    "wrong_permit", "wrong_authorization", "wrong_intent",
    "wrong_request", "wrong_consumption", "wrong_consumption_digest",
))
def test_mismatched_exact_lineage_fails_closed(paired, which):
    native, permit, receipt, envelope, public, clock = paired
    permit = dict(permit)
    receipt = dict(receipt)
    if which == "wrong_permit":
        permit["permit_id"] = "iam-permit:v1:sha256:" + "0" * 64
    elif which == "wrong_authorization":
        receipt["authorization_id"] = "different-authorization"
    elif which == "wrong_intent":
        permit["execution_intent_id"] = "different-intent"
    elif which == "wrong_request":
        receipt["request_id"] = "forged-idempotency-key"
    elif which == "wrong_consumption":
        receipt["consumption_id"] = "forged-consumption"
    elif which == "wrong_consumption_digest":
        receipt["consumption_hash"] = "0" * 64
    with pytest.raises(ValueError, match="IAM2380_"):
        validate_signed_lineage(
            envelope=envelope, target_public_pem=public,
            receipt=receipt, permit=permit, native=native, observed_at=clock,
        )


@pytest.mark.parametrize("which", (
    "committed_before_native", "committed_after_expiry", "observed_before_commit",
))
def test_signed_time_must_match_single_use_permit_window(paired, which):
    native, permit, receipt, envelope, public, clock = paired
    permit = dict(permit)
    if which == "committed_before_native":
        permit["not_before"] = (datetime.now(timezone.utc)+timedelta(seconds=1)).isoformat()
    elif which == "committed_after_expiry":
        permit["expires_at"] = (datetime.now(timezone.utc)-timedelta(seconds=4)).isoformat()
    else:
        clock = (datetime.now(timezone.utc)-timedelta(seconds=6)).isoformat()
    with pytest.raises(ValueError, match="IAM2380_ACK_COMMIT_CLOCK_OUTSIDE_NATIVE_PERMIT"):
        validate_signed_lineage(
            envelope=envelope, target_public_pem=public,
            receipt=receipt, permit=permit, native=native, observed_at=clock,
        )


@pytest.mark.parametrize("which", (
    "changed_status", "changed_actor", "changed_target", "changed_receipt_signature",
))
def test_tampered_target_signed_ack_is_not_reconciliation_authority(paired, which):
    native, permit, receipt, original, public, clock = paired
    envelope = {"payload": dict(original["payload"]), "signature": original["signature"]}
    if which == "changed_status":
        envelope["payload"]["status"] = "not_applied"
    elif which == "changed_actor":
        envelope["payload"]["actor"] = "unscoped-probe"
    elif which == "changed_target":
        envelope["payload"]["grant_role"] = "read"
    else:
        envelope["signature"] = "AAAA"
    with pytest.raises((ValueError, TypeError)):
        validate_signed_lineage(
            envelope=envelope, target_public_pem=public,
            receipt=receipt, permit=permit, native=native, observed_at=clock,
        )


@pytest.mark.parametrize("bad_clock", ("", "not-a-time", "2026-10-16T12:00:00"))
def test_untrusted_clock_rejected(bad_clock):
    with pytest.raises(ValueError, match="IAM2380_TIMESTAMP_"):
        aware(bad_clock)


def make_claim(native, permit, envelope, observed, *, claim=ReconciliationClaim.CONFIRMED_EFFECT,
               digest_override=None):
    evidence = ReconciliationEvidence(
        operation_id=native.consumption_id,
        authorization_id=permit["authorization_id"],
        consumption_id=native.consumption_id,
        claim=claim, source_type=SOURCE_TYPE, source_identity=SOURCE_IDENTITY,
        observed_at=observed, external_operation_reference=permit["permit_id"],
        external_ack_digest=digest_override or signature_digest(envelope),
        observation_digest="0" * 64,
    )
    return evidence.model_copy(update={
        "observation_digest": reconciliation_observation_digest(evidence),
    })


@pytest.mark.asyncio
async def test_signed_verifier_reads_actual_native_pg_consume(monkeypatch, paired):
    native, permit, receipt, envelope, public, observed = paired
    verifier = SyntheticSignedMtlsAckVerifier(
        envelope=envelope, pinned_target_public=public,
        receipt=receipt, permit=permit, native=native,
    )
    read = AsyncMock(return_value=native)
    monkeypatch.setattr(
        "scripts.enterprise_iam_lab.reconcile_signed_target_ack."
        "PostgresAtomicAuthorizationConsumptionStore.get", read,
    )
    claim = make_claim(native, permit, envelope, observed)
    verified = await verifier.verify(claim)
    assert verified.evidence == claim
    assert verified.verifier_id.startswith("iam-2380-")
    assert verified.verification_proof_hash
    assert read.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ("no_effect", "wrong_digest", "wrong_source",
                               "wrong_authorization", "wrong_operation"))
async def test_untrusted_noeffect_or_changed_claim_denied_before_cas(paired, bad):
    native, permit, receipt, envelope, public, observed = paired
    verifier = SyntheticSignedMtlsAckVerifier(
        envelope=envelope, pinned_target_public=public,
        receipt=receipt, permit=permit, native=native,
    )
    claim = make_claim(native, permit, envelope, observed)
    if bad == "no_effect":
        claim = claim.model_copy(update={"claim": ReconciliationClaim.CONFIRMED_NO_EFFECT})
    elif bad == "wrong_digest":
        claim = claim.model_copy(update={"external_ack_digest": "0" * 64})
    elif bad == "wrong_source":
        claim = claim.model_copy(update={"source_identity": "untrusted"})
    elif bad == "wrong_authorization":
        claim = claim.model_copy(update={"authorization_id": "untrusted"})
    else:
        claim = claim.model_copy(update={"operation_id": "untrusted"})
    with pytest.raises(ValueError, match="IAM2380_UNTRUSTED_RECONCILIATION_CLAIM"):
        await verifier.verify(claim)


@pytest.mark.asyncio
async def test_missing_real_pg_record_denied_even_with_valid_signed_receipt(monkeypatch, paired):
    native, permit, receipt, envelope, public, observed = paired
    verifier = SyntheticSignedMtlsAckVerifier(
        envelope=envelope, pinned_target_public=public,
        receipt=receipt, permit=permit, native=native,
    )
    monkeypatch.setattr(
        "scripts.enterprise_iam_lab.reconcile_signed_target_ack."
        "PostgresAtomicAuthorizationConsumptionStore.get",
        AsyncMock(return_value=None),
    )
    with pytest.raises(ValueError, match="IAM2380_NATIVE_POSTGRES_CHANGED_OR_MISSING"):
        await verifier.verify(make_claim(native, permit, envelope, observed))


def test_new_reconciliation_path_has_no_target_sqlite_or_mutation_api():
    source = Path("scripts/enterprise_iam_lab/reconcile_signed_target_ack.py").read_text(
        encoding="utf-8",
    )
    assert "sqlite3" not in source
    assert "lookup_exact_target_effect(" not in source
    assert "_verified_native_postgres_join(" not in source
    assert "--target-database" not in source
    assert "commit_verified_permit(" not in source
    assert "issue_iam_permit_after_native_consumption(" not in source
    assert "recover_in_flight_after_consumption(" not in source
    assert "reconcile_effect_unknown(" in source
    assert "verify_target_signature(" in source


def test_new_mode_never_relaxes_default_legacy_requirements():
    shell = Path("scripts/enterprise_iam_lab/run_native_docker.sh").read_text("utf-8")
    assert 'LAB_NATIVE_SIGNED_ACK_RECONCILE:-0' in shell
    assert "SIGNED_ACK_RECONCILIATION_REQUIRES_DURABLE_LOST_ACK_AND_READONLY_MTLS" in shell
    assert "python3 -m scripts.enterprise_iam_lab.reconcile_signed_target_ack" in shell
    assert "python3 -m scripts.enterprise_iam_lab.reconcile_native_lost_ack" in shell
