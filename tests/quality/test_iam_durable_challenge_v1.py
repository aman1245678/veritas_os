"""#2382 fail-closed unit invariants; real PG/Docker is in dedicated workflow."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from scripts.enterprise_iam_lab.durable_challenge_registry import (
    ChallengeBoundPostgresEffectStore,
    ChallengeRegistryError, aware, digest, register,
)
from veritas_os.policy.bind_effect_reconciliation import EffectExecutionState


@pytest.mark.parametrize("value", ["", "0" * 63, "0" * 65, "F" * 64,
                                   "../../../foo", None, 123, "x" * 64])
def test_invalid_nonce_never_reaches_database(value):
    with pytest.raises(ChallengeRegistryError, match="IAM2382_INVALID_CHALLENGE"):
        digest(value)


def test_valid_nonce_is_hashed_not_stored_raw():
    nonce = "a" * 64
    hashed = digest(nonce)
    assert len(hashed) == 64 and hashed != nonce


@pytest.mark.parametrize("value", ["", "2026-10-16T00:00:00", "garbage", None])
def test_untrusted_or_unzoned_registration_time_rejected(value):
    with pytest.raises(ChallengeRegistryError, match="IAM2382_INVALID_ISSUED_AT"):
        aware(value)


def test_invalid_registry_operation_refuses_before_any_database_access():
    async def check():
        with pytest.raises(ChallengeRegistryError, match="IAM2382_REGISTRY_LINEAGE_INVALID"):
            await register(
                challenge="a" * 64,
                issued_at="2026-10-16T00:00:00+00:00",
                permit_id="synthetic-permit",
                operation_id="operation-A", authorization_id="authorization-A",
                consumption_id="operation-B",
            )
    asyncio.run(check())


def test_guard_rejects_wrong_operation_without_database_access():
    store = ChallengeBoundPostgresEffectStore(
        nonce_sha256=digest("a" * 64), permit_id="permit",
        operation_id="operation-A", authorization_id="auth-A",
    )
    async def check():
        assert await store.transition(
            operation_id="wrong-operation",
            expected_state=EffectExecutionState.EFFECT_UNKNOWN,
            record=None,
        ) is False
    asyncio.run(check())


def test_test_only_sql_predicates_are_fail_closed():
    source = Path("scripts/enterprise_iam_lab/durable_challenge_registry.py").read_text()
    migration = Path("alembic/versions/0011_iam_reconciliation_challenge.py").read_text()
    runner = Path("scripts/enterprise_iam_lab/run_native_docker.sh").read_text()
    reconcile = Path("scripts/enterprise_iam_lab/reconcile_signed_target_ack.py").read_text()
    assert "async with conn.transaction()" in source
    assert "FOR UPDATE" in source
    assert "state='CONSUMED'" in source
    assert "ON CONFLICT (challenge_sha256) DO NOTHING" in source
    assert "RETURNING operation_id" in source
    assert "revision=%s AND reconciliation_archive IS NULL" in source
    assert "iam_challenge_one_consumed_per_operation" in migration
    assert "LAB_DURABLE_CHALLENGE" in runner
    assert "ChallengeBoundPostgresEffectStore" in reconcile
    assert "freshness_challenge" in reconcile


def test_durable_flag_cannot_be_mistaken_for_production_claim():
    source = Path("scripts/enterprise_iam_lab/durable_challenge_registry.py").read_text()
    assert '"production_claim": False' in source
    assert "No target SQLite" not in source or "target SQLite" in source
