#!/usr/bin/env python3
"""#2382: opt-in durable nonce registry and atomic nonce + effect-state CAS.

Does NOT issue permits, retry target effects, access target SQLite or claim
production replay immunity. Uses the existing PostgreSQL effect-state row;
both terminal state and challenge consumption commit in one transaction.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

from veritas_os.policy.bind_effect_reconciliation import (
    EffectExecutionState, EffectStateRecord, PostgresAtomicEffectStateStore,
    _record_hash_valid,
)
from veritas_os.storage.db import get_pool, close_pool

_HEX256 = re.compile(r"^[0-9a-f]{64}$")
_LIMIT = timedelta(seconds=120)


class ChallengeRegistryError(ValueError):
    pass


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ChallengeRegistryError(code)


def digest(challenge: str) -> str:
    require(type(challenge) is str and _HEX256.fullmatch(challenge) is not None,
            "IAM2382_INVALID_CHALLENGE")
    return hashlib.sha256(challenge.encode("ascii")).hexdigest()


def aware(value: str) -> datetime:
    require(type(value) is str, "IAM2382_INVALID_ISSUED_AT")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ChallengeRegistryError("IAM2382_INVALID_ISSUED_AT") from None
    require(parsed.utcoffset() is not None, "IAM2382_INVALID_ISSUED_AT")
    return parsed.astimezone(timezone.utc)


async def register(*, challenge: str, issued_at: str, permit_id: str,
                   operation_id: str, authorization_id: str,
                   consumption_id: str) -> str:
    """Register ONLY while original operation is durably EFFECT_UNKNOWN."""
    nonce_hash = digest(challenge)
    ts = aware(issued_at)
    require(operation_id == consumption_id and bool(authorization_id)
            and bool(permit_id), "IAM2382_REGISTRY_LINEAGE_INVALID")
    pool = await get_pool()
    async with pool.connection() as conn:
        async with conn.transaction():
            cur = await conn.execute(
                "INSERT INTO iam_reconciliation_challenges "
                "(challenge_sha256,operation_id,authorization_id,consumption_id,"
                "permit_id,issued_at,expires_at,state) "
                "SELECT %s, operation_id, authorization_id, consumption_id, %s, %s, %s, 'ISSUED' "
                "FROM bind_effect_states WHERE operation_id=%s AND authorization_id=%s "
                "AND consumption_id=%s AND state=%s AND revision=2 "
                "AND %s <= clock_timestamp() AND %s > clock_timestamp() "
                "ON CONFLICT (challenge_sha256) DO NOTHING RETURNING challenge_sha256",
                (nonce_hash, permit_id, ts, ts + _LIMIT, operation_id,
                 authorization_id, consumption_id,
                 EffectExecutionState.EFFECT_UNKNOWN.value,
                 ts, ts + _LIMIT),
            )
            require(await cur.fetchone() is not None,
                    "IAM2382_DUPLICATE_STALE_OR_UNBOUND_CHALLENGE")
    return nonce_hash


class ChallengeBoundPostgresEffectStore(PostgresAtomicEffectStateStore):
    """A capability to CAS a registered nonce together with one effect state.

    The standard reconciliation algorithm calls this store's get/transition;
    existing signed ACK verifier must still independently validate signature,
    original permit, native consumption, request lineage and freshness.
    """
    def __init__(self, *, nonce_sha256: str, permit_id: str,
                 authorization_id: str, operation_id: str):
        require(type(nonce_sha256) is str and _HEX256.fullmatch(nonce_sha256) is not None,
                "IAM2382_INVALID_DIGEST")
        self.nonce_sha256 = nonce_sha256
        self.permit_id = permit_id
        self.authorization_id = authorization_id
        self.operation_id = operation_id

    async def transition(self, *, operation_id: str,
                         expected_state: EffectExecutionState,
                         record: EffectStateRecord) -> bool:
        if (operation_id != self.operation_id or operation_id != record.operation_id
                or expected_state != EffectExecutionState.EFFECT_UNKNOWN
                or record.state != EffectExecutionState.CONFIRMED_EFFECT
                or record.authorization_id != self.authorization_id
                or not _record_hash_valid(record)):
            return False
        from psycopg.types.json import Jsonb
        pool = await get_pool()
        async with pool.connection() as conn:
            # One transaction: a crash cannot commit only the nonce or effect.
            async with conn.transaction():
                cur = await conn.execute(
                    "SELECT operation_id,authorization_id,consumption_id,permit_id,state "
                    "FROM iam_reconciliation_challenges "
                    "WHERE challenge_sha256=%s AND expires_at > clock_timestamp() "
                    "FOR UPDATE",
                    (self.nonce_sha256,),
                )
                row = await cur.fetchone()
                if row != (self.operation_id, self.authorization_id,
                           record.consumption_id, self.permit_id, "ISSUED"):
                    return False
                cur = await conn.execute(
                    "UPDATE bind_effect_states SET state=%s,revision=%s,record_hash=%s,"
                    "updated_at=%s,record=%s "
                    "WHERE operation_id=%s AND authorization_id=%s AND authorization_hash=%s "
                    "AND consumption_id=%s AND consumption_hash=%s "
                    "AND execution_intent_id=%s AND idempotency_key=%s "
                    "AND effect_provenance=%s AND state=%s "
                    "AND revision=%s AND reconciliation_archive IS NULL RETURNING operation_id",
                    (record.state.value, record.revision, record.record_hash,
                     record.updated_at, Jsonb(record.model_dump(mode="json")),
                     operation_id, record.authorization_id, record.authorization_hash,
                     record.consumption_id, record.consumption_hash,
                     record.execution_intent_id, record.idempotency_key,
                     record.effect_provenance.value, expected_state.value,
                     record.revision - 1),
                )
                if await cur.fetchone() is None:
                    return False
                cur = await conn.execute(
                    "UPDATE iam_reconciliation_challenges "
                    "SET state='CONSUMED', consumed_at=clock_timestamp(), evidence_hash=%s "
                    "WHERE challenge_sha256=%s AND state='ISSUED' "
                    "AND expires_at > clock_timestamp() RETURNING challenge_sha256",
                    (record.reconciliation_evidence_hash, self.nonce_sha256),
                )
                # Raise inside transaction to roll back prior effect CAS as well.
                require(await cur.fetchone() is not None,
                        "IAM2382_NONCE_CONSUMPTION_FAILED_ROLLBACK")
        return True


async def lookup(nonce_sha256: str) -> dict | None:
    require(_HEX256.fullmatch(nonce_sha256) is not None, "IAM2382_INVALID_DIGEST")
    pool = await get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT challenge_sha256,operation_id,authorization_id,"
            "consumption_id,permit_id,state,issued_at,expires_at,"
            "consumed_at,evidence_hash FROM iam_reconciliation_challenges "
            "WHERE challenge_sha256=%s", (nonce_sha256,),
        )
        row = await cur.fetchone()
    if row is None:
        return None
    keys = ("challenge_sha256", "operation_id", "authorization_id",
            "consumption_id", "permit_id", "state", "issued_at",
            "expires_at", "consumed_at", "evidence_hash")
    return dict(zip(keys, row))


async def cli(args: argparse.Namespace) -> dict:
    folder = args.report_dir
    nonce = json.loads((folder / "iam_freshness_challenge.json").read_text())
    issuer = json.loads((folder / "native_issuer_receipt.json").read_text())
    operation_id = issuer["consumption_id"]
    require(nonce["permit_id"] == issuer["permit_id"],
            "IAM2382_CHALLENGE_ISSUER_PERMIT_MISMATCH")
    try:
        if args.action == "register":
            hash_value = await register(
                challenge=nonce["challenge"], issued_at=nonce["issued_at"],
                permit_id=nonce["permit_id"],
                operation_id=operation_id,
                authorization_id=issuer["authorization_id"],
                consumption_id=operation_id,
            )
            state = "ISSUED"
        else:
            hash_value = digest(nonce["challenge"])
            record = await lookup(hash_value)
            require(record is not None and record["state"] == "CONSUMED"
                    and record["operation_id"] == operation_id
                    and record["authorization_id"] == issuer["authorization_id"]
                    and record["permit_id"] == issuer["permit_id"]
                    and bool(record["evidence_hash"]),
                    "IAM2382_DURABLE_CHALLENGE_NOT_CONSUMED")
            state = record["state"]
            # The same operation cannot register its old challenge after
            # restart, nor can any of eight parallel replay CAS attempts
            # spend an already CONSUMED challenge.
            try:
                await register(
                    challenge=nonce["challenge"], issued_at=nonce["issued_at"],
                    permit_id=nonce["permit_id"], operation_id=operation_id,
                    authorization_id=issuer["authorization_id"],
                    consumption_id=operation_id,
                )
            except ChallengeRegistryError as exc:
                require(str(exc) == "IAM2382_DUPLICATE_STALE_OR_UNBOUND_CHALLENGE",
                        "IAM2382_REPLAY_REGISTER_WRONG_REFUSAL")
            else:
                raise ChallengeRegistryError("IAM2382_REPLAY_REGISTERED")
            store = ChallengeBoundPostgresEffectStore(
                nonce_sha256=hash_value, permit_id=issuer["permit_id"],
                authorization_id=issuer["authorization_id"],
                operation_id=operation_id,
            )
            persisted = await store.get(operation_id)
            require(persisted is not None
                    and persisted.state == EffectExecutionState.CONFIRMED_EFFECT
                    and persisted.reconciliation_evidence_hash == record["evidence_hash"],
                    "IAM2382_REPLAY_EFFECT_CHANGED")
            async def replay():
                return await store.transition(
                    operation_id=operation_id,
                    expected_state=EffectExecutionState.EFFECT_UNKNOWN,
                    record=persisted,
                )
            refused = await asyncio.gather(*(replay() for _ in range(8)))
            require(refused == [False] * 8,
                    "IAM2382_ALREADY_SPENT_CHALLENGE_REUSED")
        return {"result": "PASS", "schema": "iam-2382-durable-challenge/v1",
                "challenge_sha256": hash_value, "state": state,
                "production_claim": False, "single_host": True}
    finally:
        await close_pool()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("register", "verify-consumed"))
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args()
    report = asyncio.run(cli(args))
    (args.report_dir / ("iam_challenge_registered.json" if args.action == "register"
                       else "iam_challenge_consumed.json")).write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8",
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
