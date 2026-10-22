# tests for veritas_os/api/rate_limiting.py
"""Tests for rate limiting and nonce management."""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import pytest

from veritas_os.api.rate_limiting import (
    _cleanup_nonces_unsafe,
    _cleanup_rate_bucket,
    _cleanup_rate_bucket_unsafe,
    _effective_nonce_max,
    _env_int_safe,
    _nonce_lock,
    _nonce_store,
    _rate_bucket,
    _rate_lock,
)


class TestEnvIntSafe:
    def test_default(self):
        assert _env_int_safe("NONEXISTENT_999", 10) == 10

    def test_valid(self):
        with mock.patch.dict(os.environ, {"TEST_RL_INT": "50"}):
            assert _env_int_safe("TEST_RL_INT", 0) == 50

    def test_invalid(self):
        with mock.patch.dict(os.environ, {"TEST_RL_INT": "xyz"}):
            assert _env_int_safe("TEST_RL_INT", 7) == 7


class TestCleanupRateBucket:
    def test_removes_expired(self):
        now = time.time()
        with _rate_lock:
            _rate_bucket["expired_key_test"] = (1, now - 500)
            _rate_bucket["fresh_key_test"] = (1, now)
            _cleanup_rate_bucket_unsafe()
        assert "expired_key_test" not in _rate_bucket
        assert "fresh_key_test" in _rate_bucket
        # Clean up
        with _rate_lock:
            _rate_bucket.pop("fresh_key_test", None)

    def test_thread_safe_cleanup(self):
        _cleanup_rate_bucket()  # Should not raise


class TestCleanupNonces:
    def test_removes_expired_nonces(self):
        now = time.time()
        with _nonce_lock:
            _nonce_store["expired_nonce_test"] = now - 100  # Expired
            _nonce_store["valid_nonce_test"] = now + 100   # Still valid
            _cleanup_nonces_unsafe()
        assert "expired_nonce_test" not in _nonce_store
        assert "valid_nonce_test" in _nonce_store
        # Clean up
        with _nonce_lock:
            _nonce_store.pop("valid_nonce_test", None)


def test_effective_nonce_max_falls_back_for_non_positive_server_override(monkeypatch):
    import veritas_os.api as api_pkg

    class _DummyServer:
        _NONCE_MAX = 0

    monkeypatch.setattr(api_pkg, "server", _DummyServer, raising=False)
    monkeypatch.setattr("veritas_os.api.rate_limiting._NONCE_MAX", 77)
    assert _effective_nonce_max() == 77


@pytest.fixture
def bounded_nonce_store(monkeypatch):
    """Isolate the actual memory store and freeze time for capacity tests."""
    from veritas_os.api import auth, rate_limiting, server

    clock = [1000.0]
    monkeypatch.setattr(rate_limiting, "_nonce_store", {})
    monkeypatch.setattr(server, "_NONCE_MAX", 2)
    monkeypatch.setattr(rate_limiting.time, "time", lambda: clock[0])
    return auth.InMemoryAuthSecurityStore(), rate_limiting._nonce_store, clock


def test_nonce_capacity_refuses_new_entries_and_preserves_replay(bounded_nonce_store):
    store, records, clock = bounded_nonce_store
    assert store.register_nonce("first", 30) is True
    assert store.register_nonce("second", 60) is True
    original = dict(records)
    for index in range(10):
        assert store.register_nonce(f"overflow-{index}", 60) is False
        assert store.register_nonce("first", 30) is False
        assert records == original

    # Cleanup cannot make room by evicting a still-valid record.
    with _nonce_lock:
        _cleanup_nonces_unsafe()
    assert records == original

    # Only expiration frees capacity; the other live record stays protected.
    clock[0] += 31
    assert store.register_nonce("new", 60) is True
    assert "first" not in records
    assert store.register_nonce("second", 60) is False
    assert set(records) == {"second", "new"}


def test_nonce_cleanup_preserves_live_records_after_capacity_reduction(
    bounded_nonce_store, monkeypatch,
):
    from veritas_os.api import server

    store, records, _ = bounded_nonce_store
    assert store.register_nonce("first", 60) is True
    assert store.register_nonce("second", 60) is True
    monkeypatch.setattr(server, "_NONCE_MAX", 1)
    with _nonce_lock:
        _cleanup_nonces_unsafe()
    assert set(records) == {"first", "second"}
    assert store.register_nonce("third", 60) is False
    assert store.register_nonce("first", 60) is False


def test_nonce_capacity_is_atomic_across_threads(bounded_nonce_store):
    store, records, _ = bounded_nonce_store
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(
            lambda index: store.register_nonce(f"thread-{index}", 60), range(32),
        ))
    assert sum(results) == 2
    assert len(records) == 2
    assert all(store.register_nonce(nonce, 60) is False for nonce in records)


@pytest.mark.asyncio
async def test_valid_hmac_replay_stays_rejected_when_nonce_store_is_full(
    bounded_nonce_store, monkeypatch,
):
    from fastapi import HTTPException
    from veritas_os.api import auth

    store, records, clock = bounded_nonce_store
    secret = b"synthetic-capacity-regression-key"
    monkeypatch.setattr(auth, "_get_api_secret", lambda: secret)
    monkeypatch.setattr(auth, "_get_effective_auth_store", lambda: store)

    class Request:
        async def body(self):
            return b"{}"

    async def verify(nonce):
        timestamp = str(int(clock[0]))
        signature = hmac.new(
            secret, f"{timestamp}\n{nonce}\n{{}}".encode(), hashlib.sha256,
        ).hexdigest()
        return await auth.verify_signature(
            Request(), x_api_key="synthetic-key", x_timestamp=timestamp,
            x_nonce=nonce, x_signature=signature, x_veritas_timestamp=None,
            x_veritas_nonce=None, x_veritas_signature=None,
        )

    assert await verify("original") is True
    assert await verify("second") is True
    with pytest.raises(HTTPException) as overflow:
        await verify("overflow")
    assert overflow.value.status_code == 401
    with pytest.raises(HTTPException) as replay:
        await verify("original")
    assert replay.value.status_code == 401
    assert set(records) == {"original", "second"}
