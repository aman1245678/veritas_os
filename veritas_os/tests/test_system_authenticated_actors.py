"""Management mutations must attribute effects to authenticated API principals."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from veritas_os.api import auth, routes_system, server
from veritas_os.core.eu_ai_act_oversight import SystemHaltController
from veritas_os.policy.bind_core import core as bind_core
from veritas_os.security.hash import sha256_of_canonical_json


@pytest.fixture()
def management_state(monkeypatch):
    keys = ["management-actor-one", "management-actor-two"]
    monkeypatch.setenv("VERITAS_API_KEY", keys[0])
    monkeypatch.setenv("VERITAS_API_KEYS", json.dumps([
        {"key": key, "role": "admin"} for key in keys
    ]))
    monkeypatch.setattr(server, "get_policy", lambda: {"version": "actor-fixture"})
    monkeypatch.setattr(server, "SystemHaltController", SystemHaltController)
    for name, value in {
        "_halted": False, "_halted_by": None, "_halted_at": None,
        "_halt_reason": None, "_history": [],
    }.items():
        monkeypatch.setattr(SystemHaltController, name, value)
    config = {"eu_ai_act_mode": False, "safety_threshold": 0.8}

    def update_config(**patch):
        config.update(patch)
        return dict(config)

    monkeypatch.setattr(routes_system, "get_runtime_config", lambda: dict(config))
    monkeypatch.setattr(routes_system, "update_runtime_config", update_config)
    intents = []
    monkeypatch.setattr(bind_core, "append_execution_intent_trustlog", intents.append)
    monkeypatch.setattr(bind_core, "append_bind_receipt_trustlog", lambda receipt: receipt)
    client = TestClient(server.app)
    try:
        yield client, config, intents
    finally:
        client.close()


def _request(client, operation: str, key: str):
    headers = {"X-API-Key": key, "X-Role": "claimed-other-person"}
    if operation == "config":
        return client.put(
            "/v1/compliance/config", headers=headers,
            json={"eu_ai_act_mode": True, "safety_threshold": 0.77},
        )
    return client.post(
        f"/v1/system/{operation}", headers=headers,
        json={"operator": "claimed-other-person", "reason": "test halt", "comment": "test resume"},
    )


@pytest.mark.parametrize("operation", ["halt", "resume", "config"])
@pytest.mark.parametrize("key", ["management-actor-one", "management-actor-two"])
def test_management_effect_actor_is_authenticated(management_state, operation, key):
    client, config, intents = management_state
    SystemHaltController._halted = operation == "resume"
    response = _request(client, operation, key)
    assert response.status_code == 200
    assert response.json()["bind_outcome"] == "COMMITTED"
    expected = auth._derive_api_user_id(key)
    assert response.json()["bind_receipt"]["actor_identity"] == expected
    assert len(intents) == 1
    assert intents[0].actor_identity == expected
    if operation == "config":
        assert config == {"eu_ai_act_mode": True, "safety_threshold": 0.77}
    else:
        assert SystemHaltController.is_halted() is (operation == "halt")
        assert SystemHaltController._history[-1]["operator"] == expected
        action = {"operator": expected}
        action.update({"reason": "test halt"} if operation == "halt" else {"comment": "test resume"})
        assert response.json()["bind_receipt"]["decision_hash"] == sha256_of_canonical_json(action)
        if operation == "halt":
            assert response.json()["halted_by"] == expected


@pytest.mark.parametrize("operation", ["halt", "resume", "config"])
def test_management_effect_refuses_missing_principal(
    monkeypatch, management_state, operation,
):
    client, config, intents = management_state
    SystemHaltController._halted = operation == "resume"
    before = SystemHaltController.status()
    monkeypatch.setattr(auth, "_bind_authenticated_principal", lambda request, key: None)
    response = _request(client, operation, "management-actor-one")
    assert response.status_code == 403
    assert intents == []
    assert config == {"eu_ai_act_mode": False, "safety_threshold": 0.8}
    assert SystemHaltController.status() == before
    assert SystemHaltController._history == []
