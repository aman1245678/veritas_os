"""Native signed authorization consumption cannot itself modify the IAM effect sink.

This is a negative isolation proof, not an ALLOW_01 authorization-to-effect proof.
Real synthetic Ed25519 issuer/verifiers are provided by existing test fixtures.
"""
from __future__ import annotations

import sqlite3

import pytest

from veritas_os.policy.native_bind_authorization_consumption import (
    consume_native_bind_authorization,
)
from veritas_os.tests.test_native_bind_authorization import (
    issued,
    api_risk_source,
)
from veritas_os.tests.test_native_bind_authorization_consumption import (
    consumable,
    _store_inputs,
)

pytestmark = pytest.mark.slow


@pytest.mark.asyncio
async def test_native_consumption_and_replay_leave_target_owned_database_unchanged(
    consumable, tmp_path
):
    artifact, original, _ = consumable
    target_db = tmp_path / "target-owned-iam.sqlite3"
    with sqlite3.connect(target_db) as db:
        db.execute(
            "CREATE TABLE grants (user_id TEXT PRIMARY KEY, role TEXT NOT NULL)"
        )
        db.execute(
            "CREATE TABLE audit (id INTEGER PRIMARY KEY, actor TEXT, status INTEGER, reason TEXT)"
        )
    store, inputs = _store_inputs(original)

    result = await consume_native_bind_authorization(artifact, **inputs)
    assert result.authorization_consumed
    assert not result.external_action_executed
    assert not result.bind_invoked
    assert await store.get(artifact.authorization_id) == result.consumption_record

    with sqlite3.connect(target_db) as db:
        assert db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 0

    with pytest.raises(ValueError, match="NABC_ALREADY_CONSUMED"):
        await consume_native_bind_authorization(artifact, **inputs)

    with sqlite3.connect(target_db) as db:
        assert db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 0
