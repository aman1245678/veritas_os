from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from veritas_os.api import routes_system, server
from veritas_os.api.pipeline_orchestrator import (
    get_runtime_config,
    update_runtime_config,
)
from veritas_os.policy.bind_artifacts import BindReceipt, FinalOutcome
from veritas_os.policy.bind_core import core as bind_core


@pytest.mark.parametrize("missing_signal, outcome", [("block", "BLOCKED"), ("escalate", "ESCALATED")])
@pytest.mark.parametrize("required, reason", [
    ("ttl_required", "BIND_TTL_MISSING"),
    ("approval_freshness_required", "BIND_APPROVAL_FRESHNESS_MISSING"),
])
def test_compliance_put_enforces_current_governance_policy(
    monkeypatch, missing_signal, outcome, required, reason,
) -> None:
    """Actual HTTP/Bind evaluation must refuse missing policy-required signals."""
    state = {"eu_ai_act_mode": False, "safety_threshold": 0.8}
    updates = []

    def update_config(**patch):
        updates.append(patch)
        state.update(patch)
        return dict(state)

    monkeypatch.setenv("VERITAS_API_KEY", "compliance-policy-test-key")
    monkeypatch.delenv("VERITAS_API_KEYS", raising=False)
    monkeypatch.setattr(server, "API_KEY_DEFAULT", "compliance-policy-test-key")
    monkeypatch.setattr(server, "get_policy", lambda: {
        "version": "governance-test-v2",
        "bind_adjudication": {required: True, "missing_signal_default": missing_signal},
    })
    monkeypatch.setattr(routes_system, "get_runtime_config", lambda: dict(state))
    monkeypatch.setattr(routes_system, "update_runtime_config", update_config)
    # Keep the real route, adapter and adjudication; isolate only audit storage.
    monkeypatch.setattr(bind_core, "append_execution_intent_trustlog", lambda intent: None)
    monkeypatch.setattr(bind_core, "append_bind_receipt_trustlog", lambda receipt: receipt)

    client = TestClient(server.app)
    try:
        response = client.put(
            "/v1/compliance/config",
            headers={"X-API-Key": "compliance-policy-test-key"},
            json={"eu_ai_act_mode": True, "safety_threshold": 0.77},
        )
    finally:
        client.close()
    assert response.status_code == 403
    payload = response.json()
    receipt = payload["bind_receipt"]
    assert payload["bind_outcome"] == outcome
    assert reason in receipt["admissibility_result"]["reason_codes"]
    assert receipt["policy_snapshot_id"] == "governance-test-v2"
    assert receipt["revalidation_context"][required] is True
    assert payload["config"] == state
    assert updates == []


def test_compliance_config_get_and_put(monkeypatch) -> None:
    """Compliance config endpoint should be authenticated and state-safe.

    This test restores global runtime config after execution so it does not
    affect other API tests that expect EU mode to be disabled by default.
    """
    client = TestClient(server.app)
    headers = {"X-API-Key": "test-key"}

    original = server.API_KEY_DEFAULT
    original_cfg = get_runtime_config()
    server.API_KEY_DEFAULT = "test-key"
    monkeypatch.setenv("VERITAS_API_KEY", "test-key")
    monkeypatch.setattr(server, "get_policy", lambda: {
        "version": "governance-default-test",
        "bind_adjudication": {"ttl_required": False, "approval_freshness_required": False},
    })
    try:
        put_resp = client.put(
            "/v1/compliance/config",
            headers=headers,
            json={"eu_ai_act_mode": True, "safety_threshold": 0.77},
        )
        assert put_resp.status_code == 200
        put_payload = put_resp.json()
        assert put_payload["config"]["eu_ai_act_mode"] is True
        assert put_payload["config"]["safety_threshold"] == 0.77
        assert put_payload["bind_outcome"] == "COMMITTED"
        assert put_payload["bind_receipt_id"]
        assert put_payload["execution_intent_id"]
        assert put_payload["bind_receipt"]["final_outcome"] == "COMMITTED"
        assert put_payload["bind_receipt"]["policy_snapshot_id"] == "governance-default-test"
        assert put_payload["bind_receipt"]["target_path_type"] in {"compliance_config_update", "other"}
        assert put_payload["target_metadata"]["target_path_type"] == put_payload["bind_receipt"]["target_path_type"]
        assert put_payload["bind_summary"]["bind_outcome"] == put_payload["bind_outcome"]
        assert put_payload["bind_summary"]["bind_receipt_id"] == put_payload["bind_receipt_id"]

        get_resp = client.get("/v1/compliance/config", headers=headers)
        assert get_resp.status_code == 200
        get_payload = get_resp.json()
        assert get_payload["config"]["eu_ai_act_mode"] is True
        assert get_payload.get("bind_outcome") is None
    finally:
        server.API_KEY_DEFAULT = original
        update_runtime_config(
            eu_ai_act_mode=bool(original_cfg["eu_ai_act_mode"]),
            safety_threshold=float(original_cfg["safety_threshold"]),
        )


def test_compliance_config_put_bind_blocked(monkeypatch) -> None:
    """Bind BLOCKED outcome should preserve route-level error semantics."""
    client = TestClient(server.app)
    headers = {"X-API-Key": "test-key"}

    original = server.API_KEY_DEFAULT
    server.API_KEY_DEFAULT = "test-key"
    monkeypatch.setenv("VERITAS_API_KEY", "test-key")

    blocked_receipt = replace(
        BindReceipt(
            bind_receipt_id="br-comp-blocked",
            execution_intent_id="ei-comp-blocked",
            decision_id="dec-comp-blocked",
            final_outcome=FinalOutcome.BLOCKED,
        ),
        admissibility_result={
            "admissible": False,
            "reason_codes": ["BIND_AUTHORITY_DENIED"],
            "reason": "authority denied",
        },
    )
    monkeypatch.setattr(
        "veritas_os.api.routes_system.update_compliance_config_with_bind_boundary",
        lambda **kwargs: blocked_receipt,
    )
    try:
        resp = client.put(
            "/v1/compliance/config",
            headers=headers,
            json={"eu_ai_act_mode": True, "safety_threshold": 0.77},
        )
        assert resp.status_code == 403
        body = resp.json()
        assert body["ok"] is False
        assert body["bind_outcome"] == "BLOCKED"
        assert body["bind_receipt_id"] == "br-comp-blocked"
        assert body["bind_receipt"]["target_path_type"] == "other"
        assert body["bind_summary"]["bind_outcome"] == body["bind_outcome"]
    finally:
        server.API_KEY_DEFAULT = original
