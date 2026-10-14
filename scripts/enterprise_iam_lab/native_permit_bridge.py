"""Test-only native-consumption to isolated IAM effect-permit issuer bridge.

This is NOT the live adapter dispatcher and does not execute target effects.
There is deliberately no function accepting a caller-provided 'consumed=True'
flag or a serialized consumption result as authority.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.enterprise_iam_lab.signed_permit import (
    EXPECTED,
    sign_permit,
    verify_permit,
)
from veritas_os.policy.native_bind_authorization import NativeBindAuthorizationArtifact
from veritas_os.policy.native_bind_authorization_consumption import (
    NativeAuthorizationConsumptionResult,
    consume_native_bind_authorization,
)

ISSUER = "isolated-iam-test-issuer"
ACTION = "grant_admin_role"
TTL = timedelta(seconds=10)


class IAMPermitBridgeDenied(ValueError):
    """Fail-closed IAM effect-permit bridge error without backend secrets."""


@dataclass(frozen=True)
class IAMPermitDeploymentPin:
    """Deployment-owned expected native lineage; never sourced from an agent.

    A valid signature for another contract/intent is NOT authority to grant
    IAM admin. The pin must come from an independently reviewed deployment.
    """

    execution_intent_id: str
    execution_intent_hash: str
    bind_context_hash: str
    action_contract_digest: str


def _validate_preconsume(artifact, *, deployment_pin, governance_inputs,
                         current_source_inputs, now, signer) -> None:
    if type(artifact) is not NativeBindAuthorizationArtifact:
        raise IAMPermitBridgeDenied("IAM_NATIVE_ARTIFACT_REQUIRED")
    if type(deployment_pin) is not IAMPermitDeploymentPin or any(
        type(value) is not str or not value.strip()
        for value in vars(deployment_pin).values()
    ):
        raise IAMPermitBridgeDenied("IAM_DEPLOYMENT_PIN_REQUIRED")
    if type(signer) is not Ed25519PrivateKey:
        raise IAMPermitBridgeDenied("IAM_PINNED_SIGNER_REQUIRED")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise IAMPermitBridgeDenied("IAM_TRUSTED_CLOCK_REQUIRED")
    if (
        artifact.execution_intent_id != deployment_pin.execution_intent_id
        or artifact.execution_intent_hash != deployment_pin.execution_intent_hash
        or artifact.bind_context_hash != deployment_pin.bind_context_hash
        or artifact.action_contract_digest != deployment_pin.action_contract_digest
    ):
        raise IAMPermitBridgeDenied("IAM_NATIVE_LINEAGE_MISMATCH")

    # This target action must be explicitly present in the signed/native
    # execution intent, the independently supplied contract, and source.
    intent = artifact.execution_intent
    contract = getattr(governance_inputs, "action_contract", None)
    if (
        not isinstance(intent, dict)
        or intent.get("intended_action") != ACTION
        or getattr(contract, "action_class", None) != ACTION
        or EXPECTED["scope"] not in getattr(contract, "allowed_scope", ())
        or "admin" in getattr(contract, "prohibited_scope", ())
    ):
        raise IAMPermitBridgeDenied("IAM_EFFECT_NOT_AUTHORIZED_BY_NATIVE_CONTRACT")

    rules = getattr(contract, "human_approval_rules", None)
    if (
        not isinstance(rules, dict)
        or rules.get("required") is not True
        or rules.get("minimum_approvals") != 1
        or artifact.human_approval_requirement_status != "VERIFIED"
        or artifact.signed_human_approval_artifact is None
        or not artifact.human_approval_verification_proof_digest
    ):
        raise IAMPermitBridgeDenied("IAM_VERIFIED_HUMAN_APPROVAL_REQUIRED")

    source = current_source_inputs
    endpoint = getattr(source, "current_endpoint", None)
    if (
        not isinstance(endpoint, dict)
        or endpoint.get("endpoint_scheme") != "https"
        or endpoint.get("endpoint_host") != "iam-target"
        or endpoint.get("endpoint_port") != 8443
        or endpoint.get("endpoint_path_prefix") != EXPECTED["path"]
        or getattr(source, "required_credential_scope", None) != EXPECTED["scope"]
    ):
        raise IAMPermitBridgeDenied("IAM_TARGET_OR_SCOPE_MISMATCH")


async def issue_iam_permit_after_native_consumption(
    artifact,
    *,
    deployment_pin: IAMPermitDeploymentPin,
    issuance_source_inputs,
    governance_inputs,
    trust_inputs,
    current_source_inputs,
    current_runtime_risk_packet,
    now: datetime,
    consumption_store,
    signer: Ed25519PrivateKey,
    allow_in_memory_for_testing: bool = False,
) -> dict:
    """Reverify/consume native authorization IN THIS FUNCTION before signing.

    The signer and deployment_pin are service-owned inputs. Native consume
    errors propagate fail-closed; storage uncertainty is never a retry grant.
    No permit is issued from a separately supplied result/record/boolean.
    """
    _validate_preconsume(
        artifact, deployment_pin=deployment_pin,
        governance_inputs=governance_inputs,
        current_source_inputs=current_source_inputs, now=now, signer=signer,
    )
    valid_until = datetime.fromisoformat(artifact.valid_until)
    if valid_until.tzinfo is None:
        raise IAMPermitBridgeDenied("IAM_INVALID_NATIVE_WINDOW")
    expiration = min(now.astimezone(timezone.utc) + TTL, valid_until.astimezone(timezone.utc))
    if not now.astimezone(timezone.utc) < expiration:
        raise IAMPermitBridgeDenied("IAM_NATIVE_WINDOW_EXPIRED")

    result = await consume_native_bind_authorization(
        artifact,
        issuance_source_inputs=issuance_source_inputs,
        governance_inputs=governance_inputs,
        trust_inputs=trust_inputs,
        current_source_inputs=current_source_inputs,
        current_runtime_risk_packet=current_runtime_risk_packet,
        now=now,
        consumption_store=consumption_store,
        allow_in_memory_for_testing=allow_in_memory_for_testing,
    )
    if (
        type(result) is not NativeAuthorizationConsumptionResult
        or result.authorization_consumed is not True
        or result.current_human_approval_proof_digest is None
        or result.authorization.authorization_id != artifact.authorization_id
        or result.consumption_record.live_adapter_bind_authorization_id
        != artifact.authorization_id
        or result.consumption_record.execution_intent_id != artifact.execution_intent_id
        or (not result.durable_store_used and not allow_in_memory_for_testing)
    ):
        raise IAMPermitBridgeDenied("IAM_NATIVE_CONSUMPTION_NOT_VERIFIED")

    native_link = {
        "authorization_hash": result.authorization.authorization_hash,
        "consumption_id": result.consumption_record.consumption_id,
    }
    permit_id = "iam-permit:v1:sha256:" + hashlib.sha256(
        json.dumps(native_link, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    payload = {
        **EXPECTED,
        "issuer": ISSUER,
        "permit_id": permit_id,
        "authorization_id": artifact.authorization_id,
        "execution_intent_id": artifact.execution_intent_id,
        "request_id": artifact.idempotency_key,
        "not_before": now.astimezone(timezone.utc).isoformat(),
        "expires_at": expiration.isoformat(),
    }
    # Validate fully before returning even if the signing implementation
    # changes. Does not dispatch, fetch credentials, or claim target effect.
    envelope = sign_permit(payload, signer)
    verify_permit(envelope, signer.public_key(), now)
    return envelope
