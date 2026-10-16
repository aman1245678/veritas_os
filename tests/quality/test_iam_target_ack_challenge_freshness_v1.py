"""#2381 synthetic challenge-bound signed target ACK tests; no provider calls."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.enterprise_iam_lab.target_readonly_receipt import (
    CHALLENGE_PATTERN, MAX_OBSERVATION_VALIDITY, SCHEMA_CHALLENGE,
    canonical, challenge_bound_committed, sign_committed,
)
from scripts.enterprise_iam_lab.reconcile_signed_target_ack import (
    validate_signed_lineage,
)
from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
    build_authorization_consumption_record,
)


@pytest.fixture()
def bounded(tmp_path):
    start = datetime.now(timezone.utc) - timedelta(seconds=5)
    committed = start + timedelta(seconds=1)
    issued = datetime.now(timezone.utc) - timedelta(seconds=1)
    permit_id = "iam-permit:v1:sha256:" + "f" * 64
    authorization = "laba:v2:sha256:" + "a" * 64
    intent = "intent-" + "c" * 64
    request = "request-" + "e" * 64
    native = build_authorization_consumption_record(
        live_adapter_bind_authorization_id=authorization,
        live_adapter_bind_authorization_hash="b" * 64,
        idempotency_key=request,
        bind_context_hash="1" * 64,
        execution_intent_id=intent,
        execution_intent_hash="d" * 64,
        endpoint_identity_binding_digest="2" * 64,
        credential_reference_digest="3" * 64,
        credential_scope_binding_digest="4" * 64,
        consumed_at=start.isoformat(),
    )
    receipt = {
        "permit_id": permit_id, "authorization_id": authorization,
        "execution_intent_id": intent, "request_id": request,
        "authorization_hash": native.live_adapter_bind_authorization_hash,
        "consumption_id": native.consumption_id,
        "consumption_hash": native.consumption_hash,
    }
    permit = {
        "permit_id": permit_id, "authorization_id": authorization,
        "execution_intent_id": intent, "request_id": request,
        "not_before": start.isoformat(),
        "expires_at": (start + timedelta(seconds=10)).isoformat(),
    }
    db = tmp_path / "target.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE grants (user_id TEXT PRIMARY KEY,role TEXT NOT NULL)")
        conn.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT,status INTEGER,reason TEXT)")
        conn.execute("CREATE TABLE permit_consumptions (permit_id TEXT PRIMARY KEY,authorization_id TEXT UNIQUE,execution_intent_id TEXT,request_id TEXT,actor TEXT,audit_id INTEGER,consumed_at TEXT)")
        conn.execute("INSERT INTO grants VALUES ('contractor-001','admin')")
        conn.execute("INSERT INTO audit(actor,status,reason) VALUES('scoped-executor',201,'committed')")
        conn.execute("INSERT INTO permit_consumptions VALUES(?,?,?,?,?,?,?)",
                     (permit_id, authorization, intent, request, "scoped-executor", 1,
                      committed.isoformat()))
    signer = Ed25519PrivateKey.generate()
    key_file = tmp_path / "private.pem"
    from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption
    key_file.write_bytes(signer.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    public = signer.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    challenge = "1" * 64
    payload = challenge_bound_committed(db, permit_id, challenge, observed_at=issued)
    envelope = sign_committed(payload, key_file)
    return {
        "native": native, "receipt": receipt, "permit": permit,
        "challenge": challenge, "issued_at": issued.isoformat(),
        "target_payload": payload, "signed": envelope, "public": public,
        "signer": signer, "db": db, "permit_id": permit_id,
        "now": datetime.now(timezone.utc).isoformat(),
    }


def verify(fixture, *, envelope=None, challenge=None, issued_at=None, observed_at=None):
    return validate_signed_lineage(
        envelope=envelope if envelope is not None else fixture["signed"],
        target_public_pem=fixture["public"],
        receipt=fixture["receipt"], permit=fixture["permit"],
        native=fixture["native"],
        observed_at=observed_at if observed_at is not None else fixture["now"],
        expected_challenge=challenge if challenge is not None else fixture["challenge"],
        challenge_issued_at=issued_at if issued_at is not None else fixture["issued_at"],
    )


def resign(fixture, changes: dict):
    data = dict(fixture["target_payload"])
    data.update(changes)
    return {
        "payload": data,
        "signature": base64.b64encode(
            fixture["signer"].sign(canonical(data))
        ).decode("ascii"),
    }


def test_256_bit_challenge_bound_mtls_receipt_can_verify(bounded):
    assert CHALLENGE_PATTERN.fullmatch(bounded["challenge"])
    assert MAX_OBSERVATION_VALIDITY == timedelta(seconds=120)
    assert verify(bounded)["schema"] == SCHEMA_CHALLENGE
    assert verify(bounded)["status"] == "committed"


def test_previous_valid_signed_receipt_rejected_for_new_request_challenge(bounded):
    with pytest.raises(ValueError, match="IAM2381_WRONG_OR_MISSING_CHALLENGE"):
        verify(bounded, challenge="2" * 64)


def test_honest_old_v1_ack_cannot_answer_challenge_v2(bounded):
    from scripts.enterprise_iam_lab.target_readonly_receipt import committed_from_target
    v1 = committed_from_target(bounded["db"], bounded["permit_id"])
    old = {
        "payload": v1,
        "signature": base64.b64encode(
            bounded["signer"].sign(canonical(v1))
        ).decode("ascii"),
    }
    with pytest.raises(ValueError, match="IAM2379_ACK_UNTRUSTED_STATUS_OR_SCOPE"):
        verify(bounded, envelope=old)


@pytest.mark.parametrize("field,replacement", [
    ("challenge", "2" * 64),
    ("source_identity", "attacker-target"),
    ("authorization_id", "wrong-auth"),
    ("grant_role", "reader"),
    ("target_observed_at", "2000-01-01T00:00:00+00:00"),
])
def test_changed_signed_content_without_target_key_is_invalid(bounded, field, replacement):
    fake = {"payload": dict(bounded["target_payload"]), "signature": bounded["signed"]["signature"]}
    fake["payload"][field] = replacement
    with pytest.raises(ValueError, match="IAM2379_ACK_SIGNATURE_INVALID"):
        verify(bounded, envelope=fake)


def test_previous_challenge_signed_with_same_key_is_not_new_challenge(bounded):
    old = resign(bounded, {"challenge": "3" * 64})
    with pytest.raises(ValueError, match="IAM2381_WRONG_OR_MISSING_CHALLENGE"):
        verify(bounded, envelope=old)


@pytest.mark.parametrize("offset", [-180, 130])
def test_target_observed_time_stale_or_in_future_fails_closed(bounded, offset):
    now = datetime.fromisoformat(bounded["now"])
    different = now + timedelta(seconds=offset)
    stale = resign(bounded, {
        "target_observed_at": different.isoformat(),
        "target_expires_at": (different + timedelta(seconds=120)).isoformat(),
    })
    with pytest.raises(ValueError, match="IAM2381_STALE_FUTURE_OR_UNSOLICITED_SIGNED_OBSERVATION"):
        verify(bounded, envelope=stale)


def test_unexpired_old_receipt_rejected_if_host_nonce_is_old(bounded):
    original = datetime.fromisoformat(bounded["now"])
    with pytest.raises(ValueError, match="IAM2381_STALE_FUTURE_OR_UNSOLICITED_SIGNED_OBSERVATION"):
        verify(bounded, issued_at=(original-timedelta(seconds=130)).isoformat())


def test_valid_signature_not_enough_when_signed_expiry_is_past(bounded):
    normal = datetime.fromisoformat(bounded["issued_at"])
    signed = resign(bounded, {
        "target_observed_at": (normal-timedelta(seconds=100)).isoformat(),
        "target_expires_at": (normal-timedelta(seconds=1)).isoformat(),
    })
    with pytest.raises(ValueError, match="IAM2381_STALE_FUTURE_OR_UNSOLICITED_SIGNED_OBSERVATION"):
        verify(bounded, envelope=signed)


def test_target_forged_long_lifetime_refused_by_canonical(bounded):
    payload = dict(bounded["target_payload"])
    original = datetime.fromisoformat(payload["target_observed_at"])
    payload["target_expires_at"] = (original + timedelta(seconds=121)).isoformat()
    with pytest.raises(ValueError, match="IAM2381_CHALLENGE_LIFETIME_INVALID"):
        canonical(payload)


@pytest.mark.parametrize("challenge", ["0" * 63, "G" * 64, "0" * 65, "", "../../etc/passwd"])
def test_bad_challenge_never_reaches_target_signed_effect(bounded, challenge):
    with pytest.raises(ValueError, match="IAM2381_CHALLENGE_INVALID"):
        challenge_bound_committed(bounded["db"], bounded["permit_id"], challenge)


def test_unknown_target_effect_is_never_signed_no_effect(bounded):
    from scripts.enterprise_iam_lab.target_readonly_receipt import UnknownEffect
    with pytest.raises(UnknownEffect, match="IAM2379_TARGET_EFFECT_NOT_CONFIRMED"):
        challenge_bound_committed(bounded["db"], "iam-permit:v1:sha256:" + "0" * 64, bounded["challenge"])


def test_source_isolated_opt_in_and_previous_modes_remain_strict():
    runner = Path("scripts/enterprise_iam_lab/run_native_docker.sh").read_text("utf-8")
    service = Path("scripts/enterprise_iam_lab/target_service.py").read_text("utf-8")
    verify_source = Path("scripts/enterprise_iam_lab/reconcile_signed_target_ack.py").read_text("utf-8")
    assert "CHALLENGE_BOUND_ACK_REQUIRES_REAL_PG_LOST_ACK_SIGNED_MTLS_CAS" in runner
    assert "LAB_TEST_READONLY_FRESHNESS" in service
    assert "reconciliation_challenge_required" in service
    assert "freshness_challenge" in verify_source
    assert "reconcile_effect_unknown(" in verify_source
    assert "lookup_exact_target_effect(" not in verify_source
    assert "sqlite3.connect(" not in verify_source
