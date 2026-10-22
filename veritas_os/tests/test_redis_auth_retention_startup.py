"""Strict Redis startup refuses volatile, unknown or unhealthy retention."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from veritas_os.api import auth


class _InspectableRedis:
    def __init__(self):
        self.settings = {
            "appendonly": "yes", "appendfsync": "always",
            "no-appendfsync-on-rewrite": "no", "maxmemory-policy": "noeviction",
        }
        self.persistence = {"aof_enabled": 1, "aof_last_write_status": "ok"}
        self.reads = []

    def ping(self):
        return True

    def config_get(self, name):
        self.reads.append(name)
        return {name: self.settings[name]} if name in self.settings else {}

    def info(self, section):
        assert section == "persistence"
        self.reads.append(section)
        return self.persistence


@pytest.fixture
def configured_redis(monkeypatch):
    for key in ("VERITAS_POSTURE", "NODE_ENV",
                "VERITAS_REQUIRE_PRODUCTION_TRUSTLOG_POSTURE",
                "WEB_CONCURRENCY", "UVICORN_WORKERS"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VERITAS_ENV", "production")
    monkeypatch.setenv("VERITAS_AUTH_SECURITY_STORE", "redis")
    monkeypatch.setenv("VERITAS_AUTH_REDIS_URL", "redis://synthetic.invalid/0")
    client = _InspectableRedis()
    module = SimpleNamespace(Redis=SimpleNamespace(from_url=lambda *a, **kw: client))
    monkeypatch.setattr(auth.importlib, "import_module", lambda name: module)
    store = auth.RedisAuthSecurityStore(client)
    monkeypatch.setattr(auth, "_get_effective_auth_store", lambda: store)
    return client


@pytest.mark.parametrize("profile", ["production", "prod", "secure", "hardened"])
def test_valid_read_only_profile_passes_factory_and_startup(configured_redis, monkeypatch, profile):
    monkeypatch.setenv("VERITAS_ENV", profile)
    assert isinstance(auth._create_auth_security_store(), auth.RedisAuthSecurityStore)
    auth._check_multiworker_auth_store()
    assert "persistence" in configured_redis.reads


@pytest.mark.parametrize("name,value", [
    ("appendonly", "no"), ("appendfsync", "everysec"),
    ("appendfsync", "no"), ("maxmemory-policy", "allkeys-lru"),
    ("no-appendfsync-on-rewrite", "yes"), ("appendonly", None),
])
def test_unsafe_or_missing_setting_refuses_factory_and_startup(configured_redis, name, value):
    if value is None:
        configured_redis.settings.pop(name)
    else:
        configured_redis.settings[name] = value
    with pytest.raises(RuntimeError, match="Redis auth retention requires"):
        auth._create_auth_security_store()
    with pytest.raises(RuntimeError, match="Redis auth retention requires"):
        auth._check_multiworker_auth_store()


@pytest.mark.parametrize("status", [
    {}, {"aof_enabled": 0, "aof_last_write_status": "ok"},
    {"aof_enabled": 1, "aof_last_write_status": "err"}, None,
])
def test_unhealthy_or_unknown_aof_refuses_startup(configured_redis, status):
    configured_redis.persistence = status
    with pytest.raises(RuntimeError, match="healthy AOF writes"):
        auth._create_auth_security_store()
    with pytest.raises(RuntimeError, match="healthy AOF writes"):
        auth._check_multiworker_auth_store()


@pytest.mark.parametrize("method", ["config_get", "info"])
def test_inspection_denial_cannot_silently_skip_guard(configured_redis, monkeypatch, method):
    def denied(*args):
        raise RuntimeError("synthetic ACL inspection denied")

    monkeypatch.setattr(configured_redis, method, denied)
    with pytest.raises(RuntimeError, match="inspection denied"):
        auth._create_auth_security_store()
    with pytest.raises(RuntimeError, match="inspection denied"):
        auth._check_multiworker_auth_store()


def test_local_factory_and_startup_do_not_enforce_strict_profile(configured_redis, monkeypatch):
    monkeypatch.setenv("VERITAS_ENV", "local")
    configured_redis.settings["appendonly"] = "no"
    assert isinstance(auth._create_auth_security_store(), auth.RedisAuthSecurityStore)
    auth._check_multiworker_auth_store()
    assert configured_redis.reads == []
