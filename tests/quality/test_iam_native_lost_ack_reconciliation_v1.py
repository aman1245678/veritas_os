"""#2377 offline malicious-evidence tests; real PostgreSQL and Docker run separately."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3

import pytest

from scripts.enterprise_iam_lab.reconcile_native_lost_ack import (
    SOURCE_IDENTITY, SOURCE_TYPE, SyntheticTargetLedgerVerifier,
    lookup_exact_target_effect, require_discarded_response,
)
from veritas_os.policy.bind_effect_reconciliation import (
    ReconciliationClaim, ReconciliationEvidence,
)
from veritas_os.policy.trusted_https_reconciliation import reconciliation_observation_digest


@pytest.fixture()
def receipt_fixture(tmp_path):
    dbpath = tmp_path / "target.sqlite3"
    with sqlite3.connect(dbpath) as db:
        db.execute("CREATE TABLE grants (user_id TEXT PRIMARY KEY, role TEXT NOT NULL)")
        db.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, status INTEGER, reason TEXT)")
        db.execute("CREATE TABLE permit_consumptions (permit_id TEXT PRIMARY KEY, authorization_id TEXT UNIQUE, execution_intent_id TEXT, request_id TEXT, actor TEXT, audit_id INTEGER, consumed_at TEXT)")
    now = datetime.now(timezone.utc)
    permit = {
        "permit_id": "permit-" + "f" * 64,
        "authorization_id": "auth-" + "a" * 64,
        "execution_intent_id": "intent-" + "b" * 64,
        "request_id": "request-" + "c" * 64,
        "not_before": (now - timedelta(seconds=2)).isoformat(),
        "expires_at": (now + timedelta(seconds=10)).isoformat(),
    }
    receipt = {"consumption_id": "labac:v1:sha256:" + "d" * 64}
    return dbpath, permit, receipt


def commit(dbpath, permit, *, actor="scoped-executor", status=201, role="admin",
           consumed_at=None):
    with sqlite3.connect(dbpath) as db:
        db.execute("INSERT INTO grants(user_id, role) VALUES (?,?)",
                   ("contractor-001", role))
        cur = db.execute("INSERT INTO audit(actor,status,reason) VALUES (?,?,?)",
                         (actor, status, "committed"))
        db.execute("INSERT INTO permit_consumptions VALUES (?,?,?,?,?,?,?)", (
            permit["permit_id"], permit["authorization_id"],
            permit["execution_intent_id"], permit["request_id"],
            actor, cur.lastrowid, consumed_at or datetime.now(timezone.utc).isoformat(),
        ))


def observation(permit, receipt, claim=ReconciliationClaim.CONFIRMED_EFFECT):
    base = ReconciliationEvidence(
        operation_id=receipt["consumption_id"],
        authorization_id=permit["authorization_id"],
        consumption_id=receipt["consumption_id"],
        claim=claim,
        source_type=SOURCE_TYPE,
        source_identity=SOURCE_IDENTITY,
        observed_at=datetime.now(timezone.utc).isoformat(),
        external_operation_reference=permit["permit_id"],
        external_ack_digest="0" * 64,
        observation_digest="0" * 64,
    )
    return base.model_copy(update={
        "observation_digest": reconciliation_observation_digest(base)
    })


def test_missing_target_database_never_confirms_effect(receipt_fixture):
    database, permit, _ = receipt_fixture
    database.unlink()
    with pytest.raises(ValueError, match="IAM2377_TARGET_DATABASE_ABSENT"):
        lookup_exact_target_effect(database, permit)


def test_absent_target_row_is_unknown_not_no_effect(receipt_fixture):
    database, permit, _ = receipt_fixture
    with pytest.raises(ValueError, match="IAM2377_TARGET_EFFECT_NOT_VERIFIED"):
        lookup_exact_target_effect(database, permit)


@pytest.mark.parametrize("change", ["wrong_actor", "wrong_role", "wrong_request",
                                   "wrong_status", "extra_grant", "extra_success"])
def test_false_target_ledger_refused(receipt_fixture, change):
    database, permit, _ = receipt_fixture
    commit(
        database,
        permit,
        actor="unscoped-probe" if change == "wrong_actor" else "scoped-executor",
        status=202 if change == "wrong_status" else 201,
        role="reader" if change == "wrong_role" else "admin",
    )
    with sqlite3.connect(database) as db:
        if change == "wrong_request":
            db.execute("UPDATE permit_consumptions SET request_id = 'forged'")
        elif change == "extra_grant":
            db.execute("INSERT INTO grants VALUES ('unexpected-user', 'admin')")
        elif change == "extra_success":
            db.execute("INSERT INTO audit(actor,status,reason) VALUES ('scoped-executor',201,'committed')")
    with pytest.raises(ValueError, match="IAM2377_TARGET_COMMIT_LINEAGE_MISMATCH"):
        lookup_exact_target_effect(database, permit)


def test_effect_outside_signed_validity_cannot_confirm(receipt_fixture):
    database, permit, _ = receipt_fixture
    expired = (datetime.fromisoformat(permit["expires_at"]) + timedelta(seconds=1)).isoformat()
    commit(database, permit, consumed_at=expired)
    with pytest.raises(ValueError, match="IAM2377_TARGET_CONSUMPTION_OUTSIDE_PERMIT"):
        lookup_exact_target_effect(database, permit)


def test_valid_local_target_ledger_only_produces_readonly_ack(receipt_fixture):
    database, permit, _ = receipt_fixture
    commit(database, permit)
    result = lookup_exact_target_effect(database, permit)
    assert result["permit_id"] == permit["permit_id"]
    assert result["authorization_id"] == permit["authorization_id"]
    assert result["request_id"] == permit["request_id"]
    assert result["grant_role"] == "admin"


def test_missing_or_forged_discarded_response_cannot_claim_loss(tmp_path):
    with pytest.raises(ValueError, match="IAM2377_EVIDENCE_FILE_MISSING"):
        require_discarded_response(tmp_path)
    (tmp_path / "allow_lost_ack.json").write_text(json.dumps({
        "case_id": "allow-no-ack",
        "result": "PASS",
        "observed_failure_kind": "TARGET_HTTP_RESPONSE",
        "observed_http_status": 201,
        "request_send_completed": True,
        "acknowledgement_discarded": False,
        "target_effect_claimed_from_transport": True,
        "real_tls_socket": True,
        "production_claim": False,
    }))
    with pytest.raises(ValueError, match="IAM2377_ACKNOWLEDGEMENT_NOT_ACTUALLY_DISCARDED"):
        require_discarded_response(tmp_path)


@pytest.mark.asyncio
async def test_verifier_rejects_fabricated_no_effect_without_target_lookup(receipt_fixture):
    database, permit, receipt = receipt_fixture
    verifier = SyntheticTargetLedgerVerifier(
        receipt=receipt, permit=permit, database=database,
    )
    fake = observation(permit, receipt, claim=ReconciliationClaim.CONFIRMED_NO_EFFECT)
    with pytest.raises(ValueError, match="IAM2377_RECONCILIATION_EVIDENCE_UNTRUSTED"):
        await verifier.verify(fake)


@pytest.mark.asyncio
async def test_verifier_rejects_changed_operation_identity(receipt_fixture):
    database, permit, receipt = receipt_fixture
    verifier = SyntheticTargetLedgerVerifier(receipt=receipt, permit=permit, database=database)
    original = observation(permit, receipt)
    wrong = original.model_copy(update={"authorization_id": "someone-else"})
    with pytest.raises(ValueError, match="IAM2377_RECONCILIATION_EVIDENCE_UNTRUSTED"):
        await verifier.verify(wrong)


@pytest.mark.asyncio
async def test_verifier_requires_actual_target_commit(receipt_fixture):
    database, permit, receipt = receipt_fixture
    verifier = SyntheticTargetLedgerVerifier(receipt=receipt, permit=permit, database=database)
    with pytest.raises(ValueError, match="IAM2377_TARGET_EFFECT_NOT_VERIFIED"):
        await verifier.verify(observation(permit, receipt))
