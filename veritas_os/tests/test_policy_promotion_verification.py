"""Public promotion must verify bundle bytes before writing the active pointer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from veritas_os.api import server
from veritas_os.policy import bind_boundary_adapters as adapters
from veritas_os.policy.bind_core import core as bind_core
from veritas_os.policy.compiler import compile_policy_to_bundle
from veritas_os.policy.signing import generate_keypair


@pytest.mark.parametrize("damage", [
    "signature", "manifest", "body", "wrong_key", "missing_key", "missing_signature",
])
def test_http_promotion_rejects_unverified_bundle_before_any_write(
    monkeypatch, tmp_path: Path, damage: str,
) -> None:
    client, bundle, pointer, writes = _promotion_fixture(monkeypatch, tmp_path)
    if damage == "signature":
        (bundle / "manifest.sig").write_text("not-a-signature", encoding="utf-8")
    elif damage == "manifest":
        manifest = json.loads((bundle / "manifest.json").read_text())
        manifest["version"] = "attacker-version"
        (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    elif damage == "body":
        canonical = bundle / "compiled" / "canonical_ir.json"
        payload = json.loads(canonical.read_text())
        payload["outcome"]["decision"] = "allow"
        canonical.write_text(json.dumps(payload), encoding="utf-8")
    elif damage == "wrong_key":
        _, wrong_key = generate_keypair()
        (tmp_path / "trusted-public.pem").write_bytes(wrong_key)
    elif damage == "missing_key":
        monkeypatch.delenv("VERITAS_POLICY_VERIFY_KEY")
    else:
        (bundle / "manifest.sig").unlink()
    before = pointer.read_bytes()
    try:
        response = client.post(URL, headers=HEADERS, json=_request(bundle))
    finally:
        client.close()
    assert writes == []
    assert pointer.read_bytes() == before
    assert response.status_code == 200  # Promotion returns a receipt for refusal.
    assert response.json()["bind_outcome"] == "BLOCKED"


def test_http_promotion_accepts_verified_ed25519_bundle(monkeypatch, tmp_path: Path) -> None:
    client, bundle, pointer, writes = _promotion_fixture(monkeypatch, tmp_path)
    try:
        response = client.post(URL, headers=HEADERS, json=_request(bundle))
    finally:
        client.close()
    assert response.status_code == 200
    assert response.json()["bind_outcome"] == "COMMITTED"
    assert len(writes) == 1
    assert json.loads(pointer.read_text())["active_bundle_dir"] == str(bundle)


def test_promotion_rechecks_bundle_immediately_before_write(monkeypatch, tmp_path: Path) -> None:
    client, bundle, pointer, writes = _promotion_fixture(monkeypatch, tmp_path)
    before = pointer.read_bytes()

    def change_after_constraints(self, intent, snapshot):
        (bundle / "manifest.sig").write_text("changed-after-validation", encoding="utf-8")
        return True

    monkeypatch.setattr(adapters.PolicyBundlePromotionAdapter, "assess_runtime_risk", change_after_constraints)
    try:
        response = client.post(URL, headers=HEADERS, json=_request(bundle))
    finally:
        client.close()
    assert response.json()["bind_outcome"] == "APPLY_FAILED"
    assert writes == []
    assert pointer.read_bytes() == before


def test_promotion_postcondition_still_rolls_back(monkeypatch, tmp_path: Path) -> None:
    client, bundle, pointer, writes = _promotion_fixture(monkeypatch, tmp_path)
    tracked_write = adapters.atomic_write_json

    def change_after_write(path, payload, **kwargs):
        result = tracked_write(path, payload, **kwargs)
        (bundle / "manifest.sig").write_text("changed-after-write", encoding="utf-8")
        return result

    monkeypatch.setattr(adapters, "atomic_write_json", change_after_write)
    try:
        response = client.post(URL, headers=HEADERS, json=_request(bundle))
    finally:
        client.close()
    assert response.json()["bind_outcome"] == "ROLLED_BACK"
    assert len(writes) == 2
    assert json.loads(pointer.read_text())["active_bundle_dir"] == "previous-bundle"


URL = "/v1/governance/policy-bundles/promote"
HEADERS = {"X-API-Key": "promotion-verification-test", "X-Role": "admin"}


def _request(bundle: Path) -> dict:
    return {
        "bundle_id": bundle.name, "decision_id": "verify-promotion",
        "request_id": "verify-promotion", "policy_snapshot_id": "fixture-policy",
        "decision_hash": "a" * 64,
        "approval_context": {"policy_bundle_promotion_approved": True},
    }


def _promotion_fixture(monkeypatch, tmp_path: Path):
    private_key, public_key = generate_keypair()
    result = compile_policy_to_bundle(
        Path("policies/examples/external_tool_usage_denied.yaml"),
        tmp_path / "compiled", signing_key=private_key,
    )
    bundle = result.bundle_dir.resolve()
    pointer = tmp_path / "active.json"
    pointer.write_text('{"active_bundle_dir":"previous-bundle"}', encoding="utf-8")
    key_path = tmp_path / "trusted-public.pem"
    key_path.write_bytes(public_key)
    monkeypatch.setenv("VERITAS_API_KEY", HEADERS["X-API-Key"])
    monkeypatch.delenv("VERITAS_API_KEYS", raising=False)
    monkeypatch.setattr(server, "API_KEY_DEFAULT", HEADERS["X-API-Key"])
    monkeypatch.setenv("VERITAS_POLICY_VERIFY_KEY", str(key_path))
    monkeypatch.setenv("VERITAS_POLICY_REQUIRE_ED25519", "true")
    monkeypatch.setenv("VERITAS_POLICY_BUNDLES_ROOT", str(bundle.parent))
    monkeypatch.setenv("VERITAS_POLICY_ACTIVE_POINTER_PATH", str(pointer))
    monkeypatch.setattr(server, "get_policy", lambda: {"bind_adjudication": {}})
    monkeypatch.setattr(bind_core, "append_execution_intent_trustlog", lambda intent: None)
    monkeypatch.setattr(bind_core, "append_bind_receipt_trustlog", lambda receipt: receipt)
    writes = []
    real_write = adapters.atomic_write_json

    def tracked_write(path, payload, **kwargs):
        writes.append(path)
        return real_write(path, payload, **kwargs)

    monkeypatch.setattr(adapters, "atomic_write_json", tracked_write)
    return TestClient(server.app), bundle, pointer, writes
