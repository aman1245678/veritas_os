"""Bounded Redis process/ASGI auth tests; no external effect or rollback proof."""

from __future__ import annotations

import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest


_WORKER = r'''
import json
import os
import sys
from veritas_os.api import auth, server

os.environ["VERITAS_ENV"] = os.environ.pop("VERITAS_TEST_AUTH_PROFILE", "production")
os.environ["WEB_CONCURRENCY"] = "2"
# Even an explicit request for fail-open must not weaken production behavior.
os.environ["VERITAS_AUTH_STORE_FAILURE_MODE"] = "open"
os.environ["VERITAS_AUTH_ALLOW_FAIL_OPEN"] = "true"
auth._check_multiworker_auth_store()
print(json.dumps({"pid": os.getpid(), "store": type(auth._get_effective_auth_store()).__name__}), flush=True)
for line in sys.stdin:
    command = json.loads(line)
    if command["op"] == "nonce":
        result = auth._auth_store_register_nonce(command["key"], ttl_sec=300)
    elif command["op"] == "rate":
        result = auth._auth_store_increment_rate_limit(command["key"], limit=2, window_sec=300)
    elif command["op"] in {"factory", "guard"}:
        previous_profile = os.environ["VERITAS_ENV"]
        os.environ["VERITAS_ENV"] = "production"
        try:
            if command["op"] == "factory":
                auth._create_auth_security_store()
            else:
                auth._check_multiworker_auth_store()
        except RuntimeError:
            result = True
        else:
            result = False
        finally:
            os.environ["VERITAS_ENV"] = previous_profile
    else:
        raise ValueError("unsupported test command")
    print(json.dumps({"result": result}), flush=True)
'''


def _read_worker(process: subprocess.Popen) -> dict:
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(timeout=15), "auth worker response timed out"
        line = process.stdout.readline()
    assert line, f"auth worker exited unexpectedly: {process.poll()}"
    return json.loads(line)


class _Worker:
    def __init__(self, process: subprocess.Popen):
        self.process = process
        self.ready = _read_worker(process)
        assert self.ready["store"] == "RedisAuthSecurityStore"

    def command(self, operation: str, key: str = "synthetic") -> bool:
        self.process.stdin.write(json.dumps({"op": operation, "key": key}) + "\n")
        self.process.stdin.flush()
        return _read_worker(self.process)["result"]


@contextmanager
def _worker(url: str, profile: str = "production"):
    # Use an allowlisted child environment, not ambient credentials or posture.
    env = {
        "PATH": os.defpath,
        "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
        "PYTHONUNBUFFERED": "1",
        "VERITAS_ENV": "test",
        "VERITAS_AUTH_SECURITY_STORE": "redis",
        "VERITAS_AUTH_REDIS_URL": url,
        "VERITAS_TEST_AUTH_PROFILE": profile,
        "OPENAI_API_KEY": "DUMMY_FOR_LOCAL_REDIS_TEST",
    }
    process = subprocess.Popen(
        [sys.executable, "-c", _WORKER], env=env,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        text=True,
    )
    try:
        yield _Worker(process)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        process.stdin.close()
        process.stdout.close()


@pytest.fixture
def real_redis(request):
    required = os.getenv("VERITAS_REQUIRE_REAL_REDIS_TESTS") == "1"
    binary = os.getenv("VERITAS_TEST_REDIS_SERVER") or shutil.which("redis-server")
    if not binary:
        if required:
            pytest.fail("real Redis tests required but redis-server is unavailable")
        pytest.skip("redis-server unavailable; dedicated real Redis CI requires it")
    try:
        import redis
    except ImportError:
        if required:
            pytest.fail("real Redis tests require the redis Python client")
        pytest.skip("redis Python client unavailable")

    profile = getattr(request, "param", "yes")
    settings = {"appendonly": profile} if isinstance(profile, str) else profile
    # All storage belongs to this fixture, including the restart profiles.
    with tempfile.TemporaryDirectory(prefix="veritas-auth-redis-") as directory:
        socket_path = str(Path(directory) / "redis.sock")
        url = f"unix://{socket_path}?socket_timeout=1&socket_connect_timeout=1"
        process = subprocess.Popen(
            [binary, "--port", "0", "--unixsocket", socket_path,
             "--unixsocketperm", "700", "--save", "",
             "--appendonly", settings.get("appendonly", "yes"),
             "--appendfsync", settings.get("appendfsync", "always"),
             "--maxmemory-policy", settings.get("maxmemory-policy", "noeviction"),
             "--no-appendfsync-on-rewrite", settings.get("no-appendfsync-on-rewrite", "no"),
             "--dir", directory],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        client = redis.Redis.from_url(url)
        try:
            deadline = time.monotonic() + 10
            while True:
                assert process.poll() is None, (
                    "fixture Redis exited before readiness: " + process.stdout.read()
                )
                try:
                    if client.ping():
                        break
                except redis.RedisError:
                    if time.monotonic() >= deadline:
                        pytest.fail("fixture Redis readiness timed out")
                    time.sleep(0.02)
            yield url, process, client
        finally:
            client.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process.stdout.close()


def test_real_redis_replay_and_rate_limit_are_shared(real_redis):
    url, _, client = real_redis
    with _worker(url) as first, _worker(url) as second:
        assert first.ready["pid"] != second.ready["pid"]
        assert first.process.poll() is None and second.process.poll() is None
        assert first.command("nonce", "shared-nonce") is True
        assert second.command("nonce", "shared-nonce") is False
        assert 0 < client.pttl("veritas:nonce:shared-nonce") <= 300000
        assert first.command("rate", "shared-rate") is False
        assert second.command("rate", "shared-rate") is False
        assert first.command("rate", "shared-rate") is True


def test_real_redis_competing_processes_consume_nonce_once(real_redis):
    url, _, client = real_redis
    with _worker(url) as first, _worker(url) as second:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(worker.command, "nonce", "contended")
                       for worker in (first, second)]
            results = [future.result(timeout=15) for future in futures]
        assert sorted(results) == [False, True]
        assert client.get("veritas:nonce:contended") == b"1"


def test_real_redis_worker_sigkill_does_not_clear_nonce(real_redis):
    url, _, _ = real_redis
    with _worker(url) as original:
        assert original.command("nonce", "before-worker-crash") is True
        original.process.kill()
        original.process.wait(timeout=5)
        with _worker(url) as replacement:
            assert replacement.ready["pid"] != original.ready["pid"]
            assert replacement.command("nonce", "before-worker-crash") is False
            assert replacement.command("nonce", "fresh-after-crash") is True


def test_real_redis_outage_refuses_nonce_rate_and_factory(real_redis):
    url, redis_process, _ = real_redis
    with _worker(url) as worker:
        assert worker.command("nonce", "before-outage") is True
        assert worker.command("rate", "before-outage") is False
        redis_process.terminate()
        redis_process.wait(timeout=5)
        assert worker.command("nonce", "before-outage") is False
        assert worker.command("nonce", "fresh-during-outage") is False
        assert worker.command("rate", "fresh-during-outage") is True
        assert worker.command("factory") is True


@contextmanager
def _restarted_redis(original: subprocess.Popen, client):
    """Reopen exactly the original fixture directory and server settings."""
    import redis

    assert original.poll() is not None
    process = subprocess.Popen(
        original.args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        # Discard the admin client's old connection before observing the new PID.
        client.connection_pool.disconnect()
        deadline = time.monotonic() + 10
        while True:
            assert process.poll() is None, (
                "restarted Redis exited before readiness: " + process.stdout.read()
            )
            try:
                if client.ping():
                    break
            except redis.RedisError:
                if time.monotonic() >= deadline:
                    pytest.fail("restarted Redis readiness timed out")
                time.sleep(0.02)
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        process.stdout.close()


@pytest.mark.parametrize("real_redis", ["no", "yes"], indirect=True,
                         ids=["no-persistence-reaccepts", "aof-always-refuses"])
@pytest.mark.parametrize("stop", ["terminate", "kill"])
def test_real_redis_restart_retention_depends_on_persistence(real_redis, stop):
    """Expose volatile-store replay and verify bounded AOF process recovery."""
    url, original, client = real_redis
    durable = client.config_get("appendonly")["appendonly"] == "yes"
    assert client.config_get("appendfsync")["appendfsync"] == "always"
    assert client.config_get("maxmemory-policy")["maxmemory-policy"] == "noeviction"
    profile = "production" if durable else "local"
    with _worker(url, profile=profile) as worker:
        assert worker.command("nonce", "before-redis-restart") is True
        assert worker.command("rate", "before-redis-restart") is False
        assert worker.command("rate", "before-redis-restart") is False
    ttl_before = client.pttl("veritas:nonce:before-redis-restart")
    assert ttl_before > 0
    if durable:
        assert client.info("persistence")["aof_last_write_status"] == "ok"
    getattr(original, stop)()
    original.wait(timeout=5)

    with _restarted_redis(original, client) as restarted:
        assert restarted.pid != original.pid
        if durable:
            assert client.get("veritas:nonce:before-redis-restart") == b"1"
            assert 0 < client.pttl("veritas:nonce:before-redis-restart") <= ttl_before
        else:
            # This is a demonstrated limitation, never a safe positive outcome.
            assert client.exists("veritas:nonce:before-redis-restart") == 0
        with _worker(url, profile=profile) as replacement:
            assert replacement.command("nonce", "before-redis-restart") is (not durable)
            assert replacement.command("rate", "before-redis-restart") is durable
            assert replacement.command("nonce", "fresh-after-redis-restart") is True


@pytest.mark.parametrize("real_redis", [
    {"appendonly": "no"}, {"appendfsync": "everysec"},
    {"maxmemory-policy": "allkeys-lru"}, {"no-appendfsync-on-rewrite": "yes"},
], indirect=True, ids=["volatile", "delayed-fsync", "evicting", "rewrite-skips-fsync"])
def test_real_redis_unsafe_settings_refuse_strict_factory_and_guard(real_redis):
    url, _, _ = real_redis
    # Local setup is explicit; each command then invokes the actual strict path.
    with _worker(url, profile="local") as worker:
        assert worker.command("factory") is True
        assert worker.command("guard") is True


@pytest.mark.parametrize("offset", [0, 300])
def test_real_redis_http_nonce_covers_signature_window(real_redis, monkeypatch, offset):
    """Actual mounted HMAC route stores the full window in a real Redis key."""
    import hashlib
    import hmac
    from types import SimpleNamespace
    from fastapi.testclient import TestClient
    from veritas_os.api import auth, server

    _, _, redis_client = real_redis
    key = "real-redis-http-test-key"
    secret = b"real-redis-http-synthetic-secret-32"
    now = 2_000_000_000
    timestamp = now + offset
    nonce = "real-http-window"
    calls = []
    monkeypatch.setenv("VERITAS_API_KEY", key)
    monkeypatch.delenv("VERITAS_API_KEYS", raising=False)
    monkeypatch.setenv("VERITAS_ENV", "production")
    monkeypatch.setattr(server, "API_KEY_DEFAULT", key)
    # This real-Redis HTTP test isolates nonce retention after startup.
    monkeypatch.setattr(server.app.state, "security_startup_complete", True, raising=False)
    monkeypatch.setattr(server.app.state, "security_startup_pid", os.getpid(), raising=False)
    monkeypatch.setattr(server, "API_SECRET", secret)
    monkeypatch.setattr(server, "_AUTH_SECURITY_STORE", auth.RedisAuthSecurityStore(redis_client))
    monkeypatch.setattr(auth.time, "time", lambda: float(now))

    async def run_replay(decision_id, *, strict):
        assert strict is True
        calls.append(decision_id)
        return SimpleNamespace(
            decision_id=decision_id, replay_path="fixture", match=True,
            diff_summary="", replay_time_ms=1, schema_version="1.1.0",
            severity="info", divergence_level="no_divergence", audit_summary="",
        )

    monkeypatch.setattr(server, "run_replay", run_replay)
    payload = f"{timestamp}\n{nonce}\n{{}}".encode()
    headers = {
        "X-API-Key": key, "X-Timestamp": str(timestamp), "X-Nonce": nonce,
        "X-Signature": hmac.new(secret, payload, hashlib.sha256).hexdigest(),
        "Content-Type": "application/json",
    }
    client = TestClient(server.app)
    try:
        assert client.post("/v1/replay/fixture", headers=headers, content="{}").status_code == 200
        remaining_ms = redis_client.pttl(f"veritas:nonce:{nonce}")
        assert (offset + 300) * 1000 < remaining_ms <= (offset + 301) * 1000
        assert client.post("/v1/replay/fixture", headers=headers, content="{}").status_code == 401
        assert calls == ["fixture"]
    finally:
        client.close()
