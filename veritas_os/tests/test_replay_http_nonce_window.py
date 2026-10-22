"""Exercise the mounted replay route's real authentication and nonce lifetime.

Only the replay business callback is stubbed: these ASGI HTTP requests use the
production router, API-key check, rate limiter, HMAC verifier and nonce store.
No provider, persisted decision or external effect is invoked.
"""
from __future__ import annotations

import hashlib
import hmac
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from veritas_os.api import auth, rate_limiting, server

KEY = "replay-http-window-test-key"
SECRET = b"replay-http-window-test-secret-32-bytes"


@pytest.fixture
def replay_http(monkeypatch):
    clock = [2_000_000_000.0]
    calls = []
    monkeypatch.setenv("VERITAS_API_KEY", KEY)
    monkeypatch.delenv("VERITAS_API_KEYS", raising=False)
    monkeypatch.setenv("VERITAS_ENV", "production")
    monkeypatch.setenv("VERITAS_AUTH_STORE_FAILURE_MODE", "closed")
    monkeypatch.setattr(server, "API_KEY_DEFAULT", KEY)
    monkeypatch.setattr(server, "API_SECRET", SECRET)
    monkeypatch.setattr(auth.time, "time", lambda: clock[0])
    monkeypatch.setattr(rate_limiting, "_nonce_store", {})
    monkeypatch.setattr(rate_limiting, "_rate_bucket", {})
    monkeypatch.setattr(server, "_AUTH_SECURITY_STORE", auth.InMemoryAuthSecurityStore())

    async def run_replay(decision_id):
        calls.append(decision_id)
        return SimpleNamespace(
            decision_id=decision_id, replay_path="fixture", match=True,
            diff_summary="", replay_time_ms=1, schema_version="1.1.0",
            severity="info", divergence_level="no_divergence", audit_summary="",
        )

    monkeypatch.setattr(server, "run_replay", run_replay)
    client = TestClient(server.app)
    yield client, clock, calls
    client.close()


def signed_headers(timestamp, nonce="window-nonce"):
    payload = f"{timestamp}\n{nonce}\n{{}}".encode()
    return {
        "X-API-Key": KEY, "X-Timestamp": str(timestamp), "X-Nonce": nonce,
        "X-Signature": hmac.new(SECRET, payload, hashlib.sha256).hexdigest(),
        "Content-Type": "application/json",
    }


@pytest.mark.parametrize("offset", [0, 1, 150, 300])
def test_nonce_survives_entire_accepted_timestamp_window(replay_http, offset):
    client, clock, calls = replay_http
    start = clock[0]
    headers = signed_headers(int(start) + offset)
    url = "/v1/replay/fixture-decision"
    assert client.post(url, headers=headers, content="{}").status_code == 200
    # Includes the inclusive integer timestamp boundary and fractional second.
    for elapsed in sorted({1, 300, 300.5, offset + 300, offset + 300.9}):
        clock[0] = start + elapsed
        response = client.post(url, headers=headers, content="{}")
        assert response.status_code == 401
    assert calls == ["fixture-decision"]
    # A new signed request still reaches the callback after the window.
    clock[0] = start + offset + 302
    fresh = signed_headers(int(clock[0]), nonce="fresh-nonce")
    assert client.post(url, headers=fresh, content="{}").status_code == 200
    assert calls == ["fixture-decision", "fixture-decision"]


@pytest.mark.parametrize("failure", ["missing_key", "invalid_key", "signature", "stale", "future"])
def test_invalid_request_never_reaches_replay_callback(replay_http, failure):
    client, clock, calls = replay_http
    timestamp = int(clock[0])
    if failure == "stale":
        timestamp -= 301
    if failure == "future":
        timestamp += 301
    headers = signed_headers(timestamp)
    if failure == "missing_key":
        headers.pop("X-API-Key")
    if failure == "invalid_key":
        headers["X-API-Key"] = "invalid-test-key"
    if failure == "signature":
        headers["X-Signature"] = "0" * 64
    assert client.post("/v1/replay/fixture", headers=headers, content="{}").status_code == 401
    assert calls == []


@pytest.mark.parametrize("operation, expected_status", [("nonce", 401), ("rate", 429)])
def test_store_outage_blocks_replay_http(replay_http, monkeypatch, operation, expected_status):
    client, clock, calls = replay_http

    class BrokenStore(auth.InMemoryAuthSecurityStore):
        def register_nonce(self, nonce, ttl_sec):
            if operation == "nonce":
                raise ConnectionError("synthetic store outage")
            return super().register_nonce(nonce, ttl_sec)

        def increment_rate_limit(self, api_key, limit, window_sec):
            if operation == "rate":
                raise ConnectionError("synthetic store outage")
            return super().increment_rate_limit(api_key, limit, window_sec)

    monkeypatch.setattr(server, "_AUTH_SECURITY_STORE", BrokenStore())
    response = client.post(
        "/v1/replay/fixture", headers=signed_headers(int(clock[0])), content="{}",
    )
    assert response.status_code == expected_status
    assert calls == []


def test_redis_nonce_ttl_rounds_up_to_cover_fractional_millisecond():
    calls = []

    class Client:
        def set(self, **kwargs):
            calls.append(kwargs)
            return True

    assert auth.RedisAuthSecurityStore(Client()).register_nonce("fractional", 300.0001)
    assert calls == [{"name": "veritas:nonce:fractional", "value": "1", "nx": True, "px": 300001}]
