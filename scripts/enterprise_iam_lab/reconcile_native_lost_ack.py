#!/usr/bin/env python3
"""#2377: bounded, host-controlled lost-ACK IAM reconciliation using existing stores.

No POST is issued here. This executable reads the genuine target-owned SQLite
ledger read-only, checks existing signed synthetic permit and native PostgreSQL
lineage, and invokes the existing durable EFFECT_UNKNOWN -> CONFIRMED_EFFECT
state machine. It is NOT independently operated production reconciliation,
authenticated cross-host observation, or CONFIRMED_NO_EFFECT authority.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from scripts.enterprise_iam_lab.signed_permit import canonical, verify_permit
from scripts.enterprise_iam_lab.verify_native_docker import _verified_native_postgres_join
from veritas_os.policy.bind_effect_reconciliation import (
    BindEffectStateError,
    EffectExecutionState,
    PostgresAtomicEffectStateStore,
    ReconciliationClaim,
    ReconciliationEvidence,
    VerifiedReconciliationEvidence,
    classify_bind_exception,
    reconcile_effect_unknown,
)
from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
    PostgresAtomicAuthorizationConsumptionStore,
)
from veritas_os.policy.trusted_https_reconciliation import reconciliation_observation_digest
from veritas_os.security.hash import sha256_of_canonical_json
from veritas_os.storage.db import close_pool

SOURCE_TYPE = "synthetic-iam-target-owned-sqlite-v1"
SOURCE_IDENTITY = "isolated-iam-target:readonly-ledger-on-disposable-host"
VERIFIER_ID = "iam-2377-synthetic-host-ledger-reader-v1"
POLICY_HASH = sha256_of_canonical_json({
    "verifier_id": VERIFIER_ID,
    "source_type": SOURCE_TYPE,
    "source_identity": SOURCE_IDENTITY,
    "scope": "disposable-same-host-read-only-target-ledger",
    "positive_claim_only": True,
    "production": False,
})


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def parse(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), "IAM2377_EVIDENCE_FILE_MISSING")
    obj = json.loads(path.read_text(encoding="utf-8"))
    require(type(obj) is dict, "IAM2377_EVIDENCE_NOT_OBJECT")
    return obj


def read_native_issuer(folder: Path, trust: Path, permits: Path) -> tuple[dict, dict]:
    receipt = parse(folder / "native_issuer_receipt.json")
    require(
        receipt.get("issuer_mode") == "REAL_NATIVE_POSTGRES_CONSUME_TEST_ONLY"
        and receipt.get("native_store_durable") is True
        and receipt.get("native_in_memory_test_override") is False
        and receipt.get("durable_in_flight_created") is True
        and receipt.get("production_claim") is False,
        "IAM2377_UNTRUSTED_ISSUER_SCOPE",
    )
    public = load_pem_public_key((trust / "permit-public.pem").read_bytes())
    envelope = parse(permits / "valid.json")
    issue_time = datetime.fromisoformat(receipt["permit_not_before"])
    require(issue_time.tzinfo is not None, "IAM2377_UNTRUSTED_ISSUE_CLOCK")
    permit = verify_permit(envelope, public, issue_time)
    require(
        receipt.get("permit_id") == permit["permit_id"]
        and receipt.get("authorization_id") == permit["authorization_id"]
        and receipt.get("execution_intent_id") == permit["execution_intent_id"]
        and receipt.get("request_id") == permit["request_id"]
        and hashlib.sha256(canonical(permit)).hexdigest() == receipt.get("permit_payload_sha256"),
        "IAM2377_ISSUER_PERMIT_BINDING_MISMATCH",
    )
    return receipt, permit


def require_discarded_response(folder: Path) -> None:
    discarded = parse(folder / "allow_lost_ack.json")
    require(
        discarded.get("case_id") == "allow-no-ack"
        and discarded.get("result") == "PASS"
        and discarded.get("observed_failure_kind") == "HTTP_RESPONSE_NOT_OBSERVED"
        and discarded.get("request_send_completed") is True
        and discarded.get("acknowledgement_discarded") is True
        and discarded.get("target_effect_claimed_from_transport") is False
        and discarded.get("observed_http_status") is None
        and discarded.get("real_tls_socket") is True
        and discarded.get("production_claim") is False,
        "IAM2377_ACKNOWLEDGEMENT_NOT_ACTUALLY_DISCARDED",
    )


def lookup_exact_target_effect(database: Path, permit: dict) -> dict:
    """Independent local read-only ledger lookup; absence means UNKNOWN, never NO_EFFECT."""
    require(database.is_file() and not database.is_symlink(), "IAM2377_TARGET_DATABASE_ABSENT")
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
        total_grants = db.execute("SELECT count(*) FROM grants").fetchone()[0]
        total_uses = db.execute("SELECT count(*) FROM permit_consumptions").fetchone()[0]
        matching = db.execute(
            "SELECT permit_id,authorization_id,execution_intent_id,request_id,"
            "actor,audit_id,consumed_at FROM permit_consumptions WHERE permit_id=?",
            (permit["permit_id"],),
        ).fetchall()
        require(len(matching) == 1, "IAM2377_TARGET_EFFECT_NOT_VERIFIED")
        row = matching[0]
        audit = db.execute(
            "SELECT actor,status,reason FROM audit WHERE id=?",
            (row[5],),
        ).fetchone()
        grants = db.execute(
            "SELECT user_id,role FROM grants ORDER BY user_id"
        ).fetchall()
        successes = db.execute("SELECT count(*) FROM audit WHERE status=201").fetchone()[0]
    require(
        total_grants == total_uses == successes == 1
        and grants == [("contractor-001", "admin")]
        and row[:5] == (
            permit["permit_id"], permit["authorization_id"],
            permit["execution_intent_id"], permit["request_id"], "scoped-executor",
        )
        and audit == ("scoped-executor", 201, "committed"),
        "IAM2377_TARGET_COMMIT_LINEAGE_MISMATCH",
    )
    consumed_at = datetime.fromisoformat(row[6])
    started = datetime.fromisoformat(permit["not_before"])
    expires = datetime.fromisoformat(permit["expires_at"])
    require(
        consumed_at.tzinfo is not None and
        started <= consumed_at < expires,
        "IAM2377_TARGET_CONSUMPTION_OUTSIDE_PERMIT",
    )
    return {
        "permit_id": row[0], "authorization_id": row[1],
        "execution_intent_id": row[2], "request_id": row[3],
        "actor": row[4], "audit_id": row[5], "consumed_at": row[6],
        "grant_target": "contractor-001", "grant_role": "admin",
    }


class SyntheticTargetLedgerVerifier:
    """Local trusted-host verifier. Not a verifier for real customer effects."""

    def __init__(self, *, receipt: dict, permit: dict, database: Path):
        self.receipt = receipt
        self.permit = permit
        self.database = database

    async def verify(self, evidence: ReconciliationEvidence) -> VerifiedReconciliationEvidence:
        require(
            evidence.claim == ReconciliationClaim.CONFIRMED_EFFECT
            and evidence.source_type == SOURCE_TYPE
            and evidence.source_identity == SOURCE_IDENTITY
            and evidence.external_operation_reference == self.permit["permit_id"]
            and evidence.authorization_id == self.permit["authorization_id"]
            and evidence.consumption_id == self.receipt["consumption_id"]
            and evidence.operation_id == self.receipt["consumption_id"]
            and evidence.observation_digest == reconciliation_observation_digest(evidence),
            "IAM2377_RECONCILIATION_EVIDENCE_UNTRUSTED",
        )
        ack = lookup_exact_target_effect(self.database, self.permit)
        require(evidence.external_ack_digest == sha256_of_canonical_json(ack),
                "IAM2377_TARGET_ACK_DIGEST_MISMATCH")
        # Reopen and independently validate the existing durable native database
        # against the same exact target SQL ledger and signed permit claims.
        joined = _verified_native_postgres_join(self.receipt, self.permit, self.database)
        require(joined["native_postgres_consumption_rows"] == 1
                and joined["target_effects_linked_to_postgres"] == 1
                and joined["native_record_digest_verified"] is True,
                "IAM2377_NATIVE_PG_TO_TARGET_JOIN_FAILED")
        verified_at = datetime.now(timezone.utc).isoformat()
        proof_hash = sha256_of_canonical_json({
            "policy_hash": POLICY_HASH, "verified_at": verified_at,
            "evidence": evidence.model_dump(mode="json"),
            "target_ack_digest": evidence.external_ack_digest,
        })
        return VerifiedReconciliationEvidence(
            evidence=evidence,
            verifier_id=VERIFIER_ID,
            verifier_policy_hash=POLICY_HASH,
            verification_proof_hash=proof_hash,
            verified_at=verified_at,
        )


async def perform(*, phase: str, folder: Path, trust: Path,
                  permits: Path, target_db: Path) -> dict:
    require_discarded_response(folder)
    receipt, permit = read_native_issuer(folder, trust, permits)
    native = PostgresAtomicAuthorizationConsumptionStore()
    effect_store = PostgresAtomicEffectStateStore()
    try:
        consumed = await native.get(permit["authorization_id"])
        require(consumed is not None, "IAM2377_NATIVE_PG_CONSUMPTION_NOT_FOUND")
        require(
            consumed.consumption_id == receipt["consumption_id"]
            and consumed.live_adapter_bind_authorization_id == permit["authorization_id"]
            and consumed.execution_intent_id == permit["execution_intent_id"]
            and consumed.idempotency_key == permit["request_id"],
            "IAM2377_NATIVE_CONSUMPTION_LINEAGE_BREAK",
        )
        original = await effect_store.get(consumed.consumption_id)
        require(original is not None, "IAM2377_PRE_DISPATCH_IN_FLIGHT_NOT_RECORDED")
        if phase == "mark-unknown":
            require(original.state == EffectExecutionState.IN_FLIGHT,
                    "IAM2377_PRE_DISPATCH_IN_FLIGHT_REQUIRED")
            unknown = await classify_bind_exception(
                consumption=consumed,
                error=RuntimeError("HTTP_RESPONSE_UNOBSERVED_NO_REDISPATCH"),
                effect_store=effect_store,
                updated_at=datetime.now(timezone.utc).isoformat(),
            )
            require(unknown.state == EffectExecutionState.EFFECT_UNKNOWN
                    and unknown.revision == original.revision + 1,
                    "IAM2377_UNKNOWN_PERSISTENCE_FAILED")
            return {
                "result": "PASS", "phase": phase,
                "operation_id": consumed.consumption_id,
                "effect_state": unknown.state.value,
                "revision": unknown.revision,
                "native_consumption_reissued": False,
                "target_post_retried": False, "production_claim": False,
            }
        require(phase == "reconcile", "IAM2377_INVALID_PHASE")
        require(original.state == EffectExecutionState.EFFECT_UNKNOWN,
                "IAM2377_UNKNOWN_REQUIRED_BEFORE_LOOKUP")
        # Evidence starts as untrusted. Only reading an exact committed target
        # row may produce the VERIFIED proof; absence never certifies no-effect.
        ack = lookup_exact_target_effect(target_db, permit)
        now = datetime.now(timezone.utc).isoformat()
        evidence = ReconciliationEvidence(
            operation_id=consumed.consumption_id,
            authorization_id=permit["authorization_id"],
            consumption_id=consumed.consumption_id,
            claim=ReconciliationClaim.CONFIRMED_EFFECT,
            source_type=SOURCE_TYPE, source_identity=SOURCE_IDENTITY,
            observed_at=now,
            external_operation_reference=permit["permit_id"],
            external_ack_digest=sha256_of_canonical_json(ack),
            observation_digest="0" * 64,
        )
        evidence = evidence.model_copy(update={
            "observation_digest": reconciliation_observation_digest(evidence)
        })
        verifier = SyntheticTargetLedgerVerifier(
            receipt=receipt, permit=permit, database=target_db,
        )
        confirmed = await reconcile_effect_unknown(
            operation_id=consumed.consumption_id,
            evidence=evidence,
            verifier=verifier, effect_store=effect_store, updated_at=now,
        )
        persisted = await effect_store.get(consumed.consumption_id)
        require(
            persisted == confirmed
            and confirmed.state == EffectExecutionState.CONFIRMED_EFFECT
            and confirmed.revision == original.revision + 1
            and confirmed.reconciliation_evidence_hash is not None,
            "IAM2377_CONFIRMED_EFFECT_NOT_DURABLY_PERSISTED",
        )
        terminal_immutable = False
        try:
            await reconcile_effect_unknown(
                operation_id=consumed.consumption_id, evidence=evidence,
                verifier=verifier, effect_store=effect_store, updated_at=now,
            )
        except BindEffectStateError as exc:
            terminal_immutable = str(exc) == "BES_TERMINAL_STATE_IMMUTABLE"
        require(terminal_immutable, "IAM2377_TERMINAL_NOT_IMMUTABLE")
        return {
            "result": "PASS", "phase": phase,
            "proof_status": "SYNTHETIC_SAME_HOST_READONLY_TARGET_RECONCILIATION_NOT_PRODUCTION_PROVEN",
            "operation_id": consumed.consumption_id,
            "effect_state_before": original.state.value,
            "effect_state_after": persisted.state.value,
            "revision": persisted.revision,
            "target_grants_confirmed": 1,
            "native_pg_consumption_records": 1,
            "target_post_retried": False,
            "permit_reissued": False,
            "terminal_state_immutable": terminal_immutable,
            "independent_operator_validation": False,
            "external_cloud_iam_effects": 0,
            "paid_provider_calls": 0,
            "production_claim": False,
        }
    finally:
        await close_pool()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=("mark-unknown", "reconcile"))
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--trust-dir", required=True, type=Path)
    parser.add_argument("--permit-dir", required=True, type=Path)
    parser.add_argument("--target-database", required=True, type=Path)
    args = parser.parse_args()
    result = asyncio.run(perform(
        phase=args.phase, folder=args.report_dir, trust=args.trust_dir,
        permits=args.permit_dir, target_db=args.target_database,
    ))
    output = args.report_dir / ("iam_reconciliation_" + args.phase.replace("-", "_") + ".json")
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "result": result["result"], "phase": result["phase"],
        "effect_state": result.get("effect_state", result.get("effect_state_after")),
        "target_post_retried": False, "production_claim": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
