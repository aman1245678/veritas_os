"""Real native signed IAM approval -> consume -> permit -> target SQLite.

Entirely synthetic and offline; real production verifiers and target handler
are exercised, but mTLS is a controlled peer fixture, not a network session.
The in-memory native store is explicitly TEST ONLY.
"""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import BytesIO
import importlib.util
from pathlib import Path
import sqlite3
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from scripts.enterprise_iam_lab import native_permit_bridge as bridge
from scripts.enterprise_iam_lab.signed_permit import EXPECTED, verify_permit
from veritas_os.policy.canonical_verified_decision_promotion import (
    build_canonical_verified_decision_promotion_packet,
)
from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
    InMemoryAtomicAuthorizationConsumptionStore,
)
from veritas_os.tests.helpers.native_approval_source import build_native_authority_source
from veritas_os.tests.test_native_bind_authorization import _setup
from veritas_os.tests.test_native_bind_authorization_consumption import _fresh
from veritas_os.tests.test_promotion_human_approval_requirement_satisfaction import _contract

pytestmark = pytest.mark.slow
ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "scripts/enterprise_iam_lab/target_service.py"


@pytest.fixture(scope="module")
def iam_native(tmp_path_factory):
    """Use the real HTTP decide fixture capture, native chain and Ed25519 verifiers."""
    output = tmp_path_factory.mktemp("iam-native-capture") / "capture.json"
    subprocess.run(
        [
            sys.executable, "-m", "veritas_os.tests.helpers.live_decision_capture",
            str(output), "--synthetic-iam-grant",
        ],
        cwd=ROOT, check=True, capture_output=True, text=True, timeout=180,
    )
    captured = json.loads(output.read_text(encoding="utf-8"))
    assert captured["pipeline_ok"] is True
    assert captured["candidate"]["intended_action"] == bridge.ACTION
    assert captured["candidate"]["required_human_approval"] is True
    now = datetime.fromisoformat(captured["observed_at"])
    promotion = build_canonical_verified_decision_promotion_packet(
        captured["canonical_decision_artifact"],
        captured["candidate"],
        promoted_at=now,
        ttl_seconds=300,
        expected_state_fingerprint="synthetic:observed-state:one",
    )
    source = build_native_authority_source(
        promotion, now,
        endpoint_overrides={
            "endpoint_candidate_id": "endpoint:isolated:iam:2373",
            "endpoint_host": "iam-target",
            "endpoint_port": 8443,
            "endpoint_path_prefix": EXPECTED["path"],
            "endpoint_environment": "isolated-lab",
            "endpoint_purpose": "synthetic-iam-proof",
        },
        credential_overrides={
            "credential_reference_id": "credential:isolated:iam:2373",
            "credential_scope": EXPECTED["scope"],
            "credential_environment": "isolated-lab",
            "credential_purpose": "synthetic-iam-proof",
        },
    )
    contract = replace(
        _contract(action=bridge.ACTION, required=True),
        allowed_scope=[EXPECTED["scope"]],
        prohibited_scope=[],
        description="Synthetic administrator role grant with explicit human approval",
    )
    contract.irreversibility["boundary"] = "future-bind-consumption"
    artifact, issuance, *_ = _setup(source, contract, now)
    assert artifact.human_approval_requirement_status == "VERIFIED"
    assert artifact.signed_human_approval_artifact is not None
    assert artifact.execution_intent["intended_action"] == bridge.ACTION
    assert issuance["source_inputs"].required_credential_scope == EXPECTED["scope"]
    consume_at = issuance["governance_inputs"].verification_now + timedelta(seconds=1)
    risk, current_source = _fresh(issuance, consume_at)
    return artifact, {
        "issuance_source_inputs": issuance["source_inputs"],
        "governance_inputs": issuance["governance_inputs"],
        "trust_inputs": issuance["trust_inputs"],
        "current_source_inputs": current_source,
        "current_runtime_risk_packet": risk,
        "now": consume_at,
    }


def params_for(artifact, values, signer, store):
    return {
        **values,
        "deployment_pin": bridge.IAMPermitDeploymentPin(
            execution_intent_id=artifact.execution_intent_id,
            execution_intent_hash=artifact.execution_intent_hash,
            bind_context_hash=artifact.bind_context_hash,
            action_contract_digest=artifact.action_contract_digest,
        ),
        "signer": signer,
        "consumption_store": store,
        "allow_in_memory_for_testing": True,
    }


@pytest.fixture
def isolated_target(monkeypatch, tmp_path, iam_native):
    """Same handler and SQLite transaction as the target, no network/cloud calls."""
    _, values = iam_native
    synthetic_now = values["now"]
    monkeypatch.syspath_prepend(str(TARGET.parent))
    monkeypatch.setenv("LAB_DB_PATH", str(tmp_path / "target.sqlite3"))
    monkeypatch.setenv("LAB_ALLOW_MUTATIONS", "1")
    monkeypatch.setenv("LAB_TEST_PERMIT_GATE", "1")
    monkeypatch.setenv("LAB_PERMIT_ISSUER", bridge.ISSUER)
    signer = Ed25519PrivateKey.generate()
    pub = tmp_path / "pinned-public.pem"
    pub.write_bytes(
        signer.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    monkeypatch.setenv("LAB_PERMIT_VERIFIER_PEM", str(pub))
    spec = importlib.util.spec_from_file_location("isolated_iam_target_2373", TARGET)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.init_db()

    class TrustedTestClock:
        @staticmethod
        def now(tz):
            assert tz is timezone.utc
            return synthetic_now

    monkeypatch.setattr(module, "datetime", TrustedTestClock)
    return module, signer


def attempt(module, envelope, *, actor="scoped-executor"):
    raw = json.dumps({"role": "admin", "permit": envelope}).encode("utf-8")

    class Peer:
        def getpeercert(self):
            return {"subject": ((("commonName", actor),),)}

    class Request:
        connection = Peer()
        headers = {"Content-Type": "application/json", "Content-Length": str(len(raw))}
        path = module.TARGET_PATH
        rfile = BytesIO(raw)
        def __init__(self):
            self.responses = []
        def respond(self, status, reason):
            self.responses.append((status, reason))

    req = Request()
    module.Handler.do_POST(req)
    assert len(req.responses) == 1
    return req.responses[0]


def observed(module):
    """Read target-owned tables, not an issuer's or handler's return value."""
    with sqlite3.connect(module.DB_PATH) as db:
        return {
            "grants": db.execute("SELECT user_id, role FROM grants").fetchall(),
            "consumptions": db.execute(
                "SELECT permit_id, authorization_id, execution_intent_id,"
                " request_id, actor, audit_id FROM permit_consumptions"
            ).fetchall(),
            "audit": db.execute(
                "SELECT id, actor, status, reason FROM audit ORDER BY id"
            ).fetchall(),
        }


@pytest.mark.asyncio
async def test_genuine_native_approved_iam_permit_commits_once(
    iam_native, isolated_target,
):
    artifact, values = iam_native
    target, signer = isolated_target
    store = InMemoryAtomicAuthorizationConsumptionStore()
    inputs = params_for(artifact, values, signer, store)
    envelope = await bridge.issue_iam_permit_after_native_consumption(
        artifact, **inputs,
    )
    verified = verify_permit(envelope, signer.public_key(), values["now"])
    assert verified["authorization_id"] == artifact.authorization_id
    assert verified["execution_intent_id"] == artifact.execution_intent_id
    assert await store.get(artifact.authorization_id) is not None
    assert observed(target)["grants"] == []

    assert attempt(target, envelope) == (201, "committed")
    snapshot = observed(target)
    assert snapshot["grants"] == [("contractor-001", "admin")]
    assert len(snapshot["consumptions"]) == 1
    assert snapshot["consumptions"][0][:5] == (
        verified["permit_id"], artifact.authorization_id,
        artifact.execution_intent_id, artifact.idempotency_key, "scoped-executor",
    )
    assert snapshot["audit"] == [
        (snapshot["consumptions"][0][5], "scoped-executor", 201, "committed")
    ]
    assert attempt(target, envelope) == (409, "permit_replayed")
    replay = observed(target)
    assert replay["grants"] == snapshot["grants"]
    assert replay["consumptions"] == snapshot["consumptions"]
    with pytest.raises(ValueError, match="NABC_ALREADY_CONSUMED"):
        await bridge.issue_iam_permit_after_native_consumption(artifact, **inputs)
    assert observed(target)["grants"] == snapshot["grants"]


@pytest.mark.asyncio
async def test_approval_withdrawal_does_not_mint_permit_or_consume(iam_native, monkeypatch):
    artifact, values = iam_native
    store = InMemoryAtomicAuthorizationConsumptionStore()
    signer = Ed25519PrivateKey.generate()
    params = params_for(artifact, values, signer, store)
    def no_sign(*args, **kwargs):
        pytest.fail("unsigned/withdrawn approval must never reach effect signer")
    monkeypatch.setattr(bridge, "sign_permit", no_sign)
    altered = artifact.model_copy(update={"signed_human_approval_artifact": None})
    with pytest.raises(bridge.IAMPermitBridgeDenied, match="IAM_VERIFIED_HUMAN_APPROVAL_REQUIRED"):
        await bridge.issue_iam_permit_after_native_consumption(altered, **params)
    assert await store.get(artifact.authorization_id) is None


@pytest.mark.asyncio
async def test_changed_target_denied_before_consumption(iam_native):
    artifact, values = iam_native
    store = InMemoryAtomicAuthorizationConsumptionStore()
    signer = Ed25519PrivateKey.generate()
    params = params_for(artifact, values, signer, store)
    src = params["current_source_inputs"]
    params["current_source_inputs"] = replace(
        src, current_endpoint={**src.current_endpoint, "endpoint_host": "untrusted.invalid"},
    )
    with pytest.raises(bridge.IAMPermitBridgeDenied, match="IAM_TARGET_OR_SCOPE_MISMATCH"):
        await bridge.issue_iam_permit_after_native_consumption(artifact, **params)
    assert await store.get(artifact.authorization_id) is None


@pytest.mark.asyncio
async def test_consumption_store_uncertainty_never_signs(iam_native, monkeypatch):
    artifact, values = iam_native
    store = InMemoryAtomicAuthorizationConsumptionStore()
    params = params_for(artifact, values, Ed25519PrivateKey.generate(), store)
    real = store.consume_once
    async def commit_without_ack(receipt):
        await real(receipt)
        raise RuntimeError("sensitive backend detail")
    def forbidden_sign(*args, **kwargs):
        pytest.fail("lost acknowledgement must never produce an effect permit")
    monkeypatch.setattr(store, "consume_once", commit_without_ack)
    monkeypatch.setattr(bridge, "sign_permit", forbidden_sign)
    with pytest.raises(ValueError, match="NABC_STORE_FAILED_OR_UNKNOWN"):
        await bridge.issue_iam_permit_after_native_consumption(artifact, **params)
    assert await store.get(artifact.authorization_id) is not None
    monkeypatch.setattr(store, "consume_once", real)
    with pytest.raises(ValueError, match="NABC_ALREADY_CONSUMED"):
        await bridge.issue_iam_permit_after_native_consumption(artifact, **params)
