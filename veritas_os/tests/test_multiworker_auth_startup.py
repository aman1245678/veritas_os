"""Deployment guard tests for process-local authentication state."""

from __future__ import annotations

import pytest

from veritas_os.api import auth


@pytest.fixture(autouse=True)
def isolated_auth_deployment(monkeypatch):
    """Use memory auth and explicit deployment flags without ambient posture."""
    for key in (
        "VERITAS_ENV", "VERITAS_POSTURE", "NODE_ENV",
        "VERITAS_REQUIRE_PRODUCTION_TRUSTLOG_POSTURE",
        "WEB_CONCURRENCY", "UVICORN_WORKERS",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(
        auth, "_get_effective_auth_store", lambda: auth.InMemoryAuthSecurityStore(),
    )


@pytest.mark.parametrize("worker_var", ["WEB_CONCURRENCY", "UVICORN_WORKERS"])
@pytest.mark.parametrize("profile", ["prod", "production", "secure", "hardened"])
def test_strict_multiworker_memory_store_refuses_startup(monkeypatch, worker_var, profile):
    monkeypatch.setenv("VERITAS_ENV", profile)
    monkeypatch.setenv(worker_var, "2")
    with pytest.raises(RuntimeError, match="shared Redis auth store"):
        auth._check_multiworker_auth_store()


@pytest.mark.parametrize("posture", ["secure", "prod"])
def test_strict_posture_multiworker_memory_store_refuses_startup(monkeypatch, posture):
    monkeypatch.setenv("VERITAS_ENV", "local")
    monkeypatch.setenv("VERITAS_POSTURE", posture)
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    with pytest.raises(RuntimeError, match="shared Redis auth store"):
        auth._check_multiworker_auth_store()


@pytest.mark.parametrize("counts", [("invalid", "2"), ("2", "invalid")])
def test_invalid_count_cannot_hide_other_multiworker_setting(monkeypatch, counts):
    monkeypatch.setenv("VERITAS_ENV", "production")
    monkeypatch.setenv("WEB_CONCURRENCY", counts[0])
    monkeypatch.setenv("UVICORN_WORKERS", counts[1])
    with pytest.raises(RuntimeError, match="shared Redis auth store"):
        auth._check_multiworker_auth_store()


@pytest.mark.parametrize("profile", ["local", "dev", "test", "staging"])
def test_non_strict_multiworker_memory_store_warns(monkeypatch, caplog, profile):
    monkeypatch.setenv("VERITAS_ENV", profile)
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    auth._check_multiworker_auth_store()
    assert "NOT shared across workers" in caplog.text


def test_production_single_worker_memory_store_remains_allowed(monkeypatch, caplog):
    monkeypatch.setenv("VERITAS_ENV", "production")
    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    monkeypatch.setenv("UVICORN_WORKERS", "1")
    auth._check_multiworker_auth_store()
    assert "NOT shared across workers" not in caplog.text


def test_production_multiworker_redis_store_passes_guard(monkeypatch):
    class InspectedRedis:
        def config_get(self, name):
            return {name: {
                "appendonly": "yes", "appendfsync": "always",
                "no-appendfsync-on-rewrite": "no", "maxmemory-policy": "noeviction",
            }[name]}

        def info(self, section):
            return {"aof_enabled": 1, "aof_last_write_status": "ok"}

    store = auth.RedisAuthSecurityStore(InspectedRedis())
    monkeypatch.setattr(auth, "_get_effective_auth_store", lambda: store)
    monkeypatch.setenv("VERITAS_ENV", "production")
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    auth._check_multiworker_auth_store()
