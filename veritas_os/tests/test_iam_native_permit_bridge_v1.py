"""Native IAM permit bridge negative proofs with REAL native verifiers.

These fixtures authorize a different synthetic action, so their signed
authorization MUST NOT mint an IAM grant permit. This suite does not
construct a genuine native IAM grant or prove ALLOW_01.
"""
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from scripts.enterprise_iam_lab import native_permit_bridge as bridge
from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
    InMemoryAtomicAuthorizationConsumptionStore,
)
from veritas_os.tests.test_native_bind_authorization_consumption import (
    consumable,
)
from veritas_os.tests.test_native_bind_authorization import issued
from veritas_os.tests.test_promotion_requirement_runtime_risk import (
    api_risk_source,
)

pytestmark = pytest.mark.slow


def inputs_for(artifact, original):
    store = InMemoryAtomicAuthorizationConsumptionStore()
    values = dict(
        deployment_pin=bridge.IAMPermitDeploymentPin(
            execution_intent_id=artifact.execution_intent_id,
            execution_intent_hash=artifact.execution_intent_hash,
            bind_context_hash=artifact.bind_context_hash,
            action_contract_digest=artifact.action_contract_digest,
        ),
        signer=Ed25519PrivateKey.generate(),
        consumption_store=store,
        allow_in_memory_for_testing=True,
        **original,
    )
    return store, values


@pytest.mark.asyncio
async def test_real_native_signed_non_iam_intent_never_mints_permit(
    consumable, monkeypatch,
):
    artifact, original, _ = consumable
    store, values = inputs_for(artifact, original)

    def must_not_sign(*args, **kwargs):
        pytest.fail("unrelated native intent reached IAM permit signer")

    monkeypatch.setattr(bridge, "sign_permit", must_not_sign)
    with pytest.raises(
        bridge.IAMPermitBridgeDenied,
        match="IAM_EFFECT_NOT_AUTHORIZED_BY_NATIVE_CONTRACT",
    ):
        await bridge.issue_iam_permit_after_native_consumption(artifact, **values)
    assert await store.get(artifact.authorization_id) is None


@pytest.mark.asyncio
async def test_wrong_deployment_pin_rejected_before_native_consumption(
    consumable,
):
    artifact, original, _ = consumable
    store, values = inputs_for(artifact, original)
    values["deployment_pin"] = replace(
        values["deployment_pin"], bind_context_hash="0" * 64
    )
    with pytest.raises(bridge.IAMPermitBridgeDenied, match="IAM_NATIVE_LINEAGE_MISMATCH"):
        await bridge.issue_iam_permit_after_native_consumption(artifact, **values)
    assert await store.get(artifact.authorization_id) is None


@pytest.mark.asyncio
async def test_caller_cannot_supply_result_bool_or_fake_signer(consumable):
    artifact, original, _ = consumable
    store, values = inputs_for(artifact, original)
    values["signer"] = object()
    with pytest.raises(bridge.IAMPermitBridgeDenied, match="IAM_PINNED_SIGNER_REQUIRED"):
        await bridge.issue_iam_permit_after_native_consumption(artifact, **values)
    assert await store.get(artifact.authorization_id) is None


@pytest.mark.asyncio
async def test_unapproved_iam_claim_never_consumes_native(consumable):
    artifact, original, _ = consumable
    if artifact.human_approval_requirement_status != "NOT_REQUIRED":
        pytest.skip("this parametrization already has verified approval")
    store, values = inputs_for(artifact, original)
    claimed = artifact.model_copy(
        update={"execution_intent": {**artifact.execution_intent, "intended_action": bridge.ACTION}}
    )
    contract = original["governance_inputs"].action_contract
    values["governance_inputs"] = replace(
        original["governance_inputs"],
        action_contract=replace(
            contract, action_class=bridge.ACTION,
            allowed_scope=["saas:grant_admin"], prohibited_scope=[],
        ),
    )
    with pytest.raises(bridge.IAMPermitBridgeDenied, match="IAM_VERIFIED_HUMAN_APPROVAL_REQUIRED"):
        await bridge.issue_iam_permit_after_native_consumption(claimed, **values)
    assert await store.get(artifact.authorization_id) is None


@pytest.mark.asyncio
async def test_rebuilt_iam_claim_cannot_replace_signed_native_evidence(consumable):
    artifact, original, _ = consumable
    if artifact.human_approval_requirement_status != "VERIFIED":
        pytest.skip("human approval required for this negative variant")
    store, values = inputs_for(artifact, original)
    forged = artifact.model_copy(
        update={"execution_intent": {**artifact.execution_intent, "intended_action": bridge.ACTION}}
    )
    contract = original["governance_inputs"].action_contract
    values["governance_inputs"] = replace(
        original["governance_inputs"],
        action_contract=replace(
            contract, action_class=bridge.ACTION,
            allowed_scope=["saas:grant_admin"], prohibited_scope=[],
        ),
    )
    endpoint = {
        **original["current_source_inputs"].current_endpoint,
        "endpoint_scheme": "https",
        "endpoint_host": "iam-target",
        "endpoint_port": 8443,
        "endpoint_path_prefix": "/v1/iam/users/contractor-001/roles",
    }
    values["current_source_inputs"] = replace(
        original["current_source_inputs"], current_endpoint=endpoint,
        required_credential_scope="saas:grant_admin",
    )
    # The application-level precheck now sees matching claimed attributes,
    # but the actual native verifier MUST reject the tampered lineage.
    bridge._validate_preconsume(
        forged,
        deployment_pin=values["deployment_pin"],
        governance_inputs=values["governance_inputs"],
        current_source_inputs=values["current_source_inputs"],
        now=values["now"], signer=values["signer"],
    )
    with pytest.raises(ValueError):
        await bridge.issue_iam_permit_after_native_consumption(forged, **values)
    assert await store.get(artifact.authorization_id) is None
