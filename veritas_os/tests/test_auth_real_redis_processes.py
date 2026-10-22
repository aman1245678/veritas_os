"""Real Redis/process tests; no HTTP, Provider, or durable Redis restart claim."""

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

os.environ["VERITAS_ENV"] = "production"
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
    elif command["op"] == "factory":
        try:
            auth._create_auth_security_store()
        except RuntimeError:
            result = True
        else:
            result = False
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
def _worker(url: str):
    # Use an allowlisted child environment, not ambient credentials or posture.
    env = {
        "PATH": os.defpath,
        "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
        "PYTHONUNBUFFERED": "1",
        "VERITAS_ENV": "test",
        "VERITAS_AUTH_SECURITY_STORE": "redis",
        "VERITAS_AUTH_REDIS_URL": url,
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
def real_redis():
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

    # Short private Unix-socket path, with no TCP listener or persistent data.
    with tempfile.TemporaryDirectory(prefix="veritas-auth-redis-") as directory:
        socket_path = str(Path(directory) / "redis.sock")
        url = f"unix://{socket_path}?socket_timeout=1&socket_connect_timeout=1"
        process = subprocess.Popen(
            [binary, "--port", "0", "--unixsocket", socket_path,
             "--unixsocketperm", "700", "--save", "", "--appendonly", "no",
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
