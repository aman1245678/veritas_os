"""#2376: negative assertions for durable-native IAM transport selection.

The live Docker + real PostgreSQL workflow performs authoritative positive
tests. These tests only prove that absent/untrusted DB data fail closed.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.enterprise_iam_lab import native_docker_issuer
from scripts.enterprise_iam_lab import verify_native_docker


@pytest.mark.asyncio
async def test_postgres_issuer_rejects_missing_database_before_signer_or_native(monkeypatch, tmp_path):
    monkeypatch.delenv("VERITAS_DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="IAM_NATIVE_REAL_POSTGRES_REQUIRED"):
        await native_docker_issuer.issue(
            tmp_path, tmp_path, tmp_path, tmp_path,
            durable_postgres=True,
        )


@pytest.mark.asyncio
async def test_postgres_issuer_rejects_non_postgres_url(monkeypatch, tmp_path):
    monkeypatch.setenv("VERITAS_DATABASE_URL", "sqlite:///not-native")
    with pytest.raises(ValueError, match="IAM_NATIVE_REAL_POSTGRES_REQUIRED"):
        await native_docker_issuer.issue(
            tmp_path, tmp_path, tmp_path, tmp_path,
            durable_postgres=True,
        )


@pytest.mark.asyncio
async def test_issuer_rejects_unrecognized_store_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("VERITAS_DATABASE_URL", "postgresql://example.invalid/nope")
    with pytest.raises(ValueError, match="IAM_NATIVE_STORE_MODE_INVALID"):
        await native_docker_issuer.issue(
            tmp_path, tmp_path, tmp_path, tmp_path,
            durable_postgres="true",
        )


def test_pg_verifier_rejects_missing_database_config(monkeypatch):
    monkeypatch.delenv("VERITAS_DATABASE_URL", raising=False)
    with pytest.raises(AssertionError, match="REAL_POSTGRES_URL_REQUIRED"):
        verify_native_docker._verify_postgres_pre_native()


def test_pg_join_rejects_absent_database_config(monkeypatch, tmp_path):
    monkeypatch.delenv("VERITAS_DATABASE_URL", raising=False)
    with pytest.raises(AssertionError, match="REAL_POSTGRES_URL_REQUIRED"):
        verify_native_docker._verified_native_postgres_join(
            {}, {}, tmp_path / "missing.sqlite3",
        )


def test_default_baseline_remains_in_memory_without_external_db(monkeypatch, tmp_path):
    script = Path("scripts/enterprise_iam_lab/run_native_docker.sh").read_text(
        encoding="utf-8"
    )
    assert 'LAB_NATIVE_DURABLE_PG:-0' in script
    assert "IAM_NATIVE_ISSUE_ARGS=()" in script
    assert "IAM_NATIVE_VERIFY_ARGS=()" in script
    assert "--durable-postgres" in script
    assert "--require-native-postgres" in script


def test_source_uses_exact_postgres_class_not_faked_production_safe():
    source = Path("scripts/enterprise_iam_lab/native_docker_issuer.py").read_text(
        encoding="utf-8"
    )
    assert "PostgresAtomicAuthorizationConsumptionStore()" in source
    assert "allow_in_memory_for_testing=not durable_postgres" in source
    assert "await store.get(artifact.authorization_id)" in source
    assert "await close_pool()" in source
