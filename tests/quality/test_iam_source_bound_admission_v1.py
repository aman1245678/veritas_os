"""#2383: adversarial source-bound admission before native issuer can consume.

Unit negatives do not establish independence of the same-host source signer,
live RCC connectivity, or production source-digest target enforcement.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from copy import deepcopy
import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from scripts.enterprise_iam_lab import source_bound_iam_origin as src
from scripts.enterprise_iam_lab import native_docker_issuer as issuer


def fixture():
    now = datetime.now(timezone.utc)
    candidate = {
        "candidate_id": "synthetic-iam-selected-001",
        "actor_identity": "synthetic-iam-test-operator",
        **src.TARGET,
    }
    request = {
        "source": "rcc-revas-controlled-synthetic-iam-request",
        "actor_identity": candidate["actor_identity"],
        "target_system": candidate["target_system"],
        "target_resource": candidate["target_resource"],
        "intended_action": candidate["intended_action"],
        "scope": "saas:grant_admin",
        "role": "admin",
        "user_request": "Grant admin to contractor-001 in isolated synthetic IAM.",
    }
    payload = {
        "schema": src.SCHEMA,
        "original_request": request,
        "original_request_digest": src.sha(request),
        "candidate": candidate,
        "candidate_digest": src.sha(candidate),
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=90)).isoformat(),
        "nonce": "a" * 64,
        "production_claim": False,
    }
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    envelope = sign(payload, signer)
    return now, signer, public, envelope


def sign(payload, key):
    return {"payload": payload,
            "signature": base64.b64encode(key.sign(src.canonical(payload))).decode()}


def test_signed_source_can_be_verified_but_is_not_execution_authority():
    now, _, public, e = fixture()
    payload = src.verify_origin(e, public, now=now)
    src.verify_selected_candidate(payload, deepcopy(payload["candidate"]))
    assert payload["production_claim"] is False
    assert payload["original_request_digest"] != payload["candidate_digest"]


@pytest.mark.parametrize("mutate", [
    lambda x: x["candidate"].update(target_resource="privileged-user"),
    lambda x: x["candidate"].update(intended_action="read_data"),
    lambda x: x["candidate"].update(required_authority=["saas:read"]),
    lambda x: x["candidate"].update(required_human_approval=False),
    lambda x: x["original_request"].update(target_resource="alternate"),
    lambda x: x["original_request"].update(source="benchmark-scorer-gold"),
    lambda x: x.update(production_claim=True),
    lambda x: x.update(original_request_digest="0" * 64),
    lambda x: x.update(candidate_digest="0" * 64),
    lambda x: x.update(nonce="X" * 64),
])
def test_mutation_or_authority_drift_is_not_accepted(mutate):
    now, _, public, envelope = fixture()
    bad = deepcopy(envelope)
    mutate(bad["payload"])
    with pytest.raises(src.SourceAdmissionDenied):
        src.verify_origin(bad, public, now=now)


def test_attacker_cannot_re_sign_with_untrusted_key():
    now, _, public, e = fixture()
    bad = sign(e["payload"], Ed25519PrivateKey.generate())
    with pytest.raises(src.SourceAdmissionDenied, match="SIGNATURE_INVALID"):
        src.verify_origin(bad, public, now=now)


def test_expired_future_or_overlong_attestation_denied():
    now, signer, public, e = fixture()
    for start, end in (
        (now - timedelta(seconds=130), now - timedelta(seconds=5)),
        (now + timedelta(seconds=5), now + timedelta(seconds=35)),
        (now, now + timedelta(seconds=121)),
        (now, now),
    ):
        bad = deepcopy(e["payload"])
        bad["issued_at"] = start.isoformat()
        bad["expires_at"] = end.isoformat()
        with pytest.raises(src.SourceAdmissionDenied):
            src.verify_origin(sign(bad, signer), public, now=now)


def test_signed_counter_permission_cannot_be_reclassified_as_iam():
    now, signer, public, e = fixture()
    bad = deepcopy(e["payload"])
    bad["candidate"]["intended_action"] = "increment"
    bad["candidate"]["target_system"] = "local-counter"
    bad["candidate"]["target_resource"] = "counter"
    bad["candidate"]["required_authority"] = ["counter:increment"]
    bad["candidate_digest"] = src.sha(bad["candidate"])
    with pytest.raises(src.SourceAdmissionDenied, match="IAM_ACTION_SCOPE_DRIFT"):
        src.verify_origin(sign(bad, signer), public, now=now)


def test_source_attestation_cannot_substitute_native_selected_candidate():
    now, _, public, e = fixture()
    payload = src.verify_origin(e, public, now=now)
    for name, value in (
        ("candidate_id", "different-selected"),
        ("target_resource", "executive-account"),
        ("actor_identity", "different-actor"),
        ("required_authority", ["saas:read"]),
        ("required_human_approval", False),
    ):
        selected = deepcopy(payload["candidate"])
        selected[name] = value
        with pytest.raises(src.SourceAdmissionDenied,
                           match="RCC_CANDIDATE_NOT_ACTUAL_NATIVE_SELECTION"):
            src.verify_selected_candidate(payload, selected)


def test_native_bridge_requires_consumed_native_approval_and_signs_exact_lineage():
    now, source_signer, _, e = fixture()
    payload = e["payload"]
    receipt = {
        "native_authorization_consumed": True,
        "native_signed_human_approval_verified": True,
        "native_store_durable": True,
        "external_iam_provider_called": False,
        "request_id": "native-idem:v2:sha256:" + "a" * 64,
        "execution_intent_id": "ei:v1:sha256:" + "b" * 64,
        "authorization_id": "laba:v2:sha256:" + "c" * 64,
        "consumption_id": "labac:v1:sha256:" + "d" * 64,
        "permit_id": "iam-permit:v1:sha256:" + "e" * 64,
    }
    issuer_key = Ed25519PrivateKey.generate()
    public = issuer_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    bridge = src.signed_native_bridge(payload, receipt, issuer_key)
    verified = src.verify_native_bridge(bridge, public, payload, receipt)
    assert verified["target_enforces_source_digest"] is False
    assert verified["actual_rcc_canonical_416_imported"] is False
    assert verified["source_attestation_digest"] == src.sha(payload)
    for name in ("request_id", "execution_intent_id",
                 "authorization_id", "consumption_id", "permit_id"):
        bad = deepcopy(receipt)
        bad[name] += ":changed"
        with pytest.raises(src.SourceAdmissionDenied,
                           match="NATIVE_BRIDGE_ID_DRIFT"):
            src.verify_native_bridge(bridge, public, payload, bad)
    bad = deepcopy(bridge)
    bad["payload"]["target_enforces_source_digest"] = True
    with pytest.raises(src.SourceAdmissionDenied, match="SIGNATURE_INVALID"):
        src.verify_native_bridge(bad, public, payload, receipt)
    bad = deepcopy(receipt)
    bad["native_store_durable"] = False
    with pytest.raises(src.SourceAdmissionDenied, match="NATIVE_BIND_NOT_VERIFIED"):
        src.signed_native_bridge(payload, bad, issuer_key)
    bad = deepcopy(payload)
    bad["original_request_digest"] = "0" * 64
    with pytest.raises(src.SourceAdmissionDenied, match="NATIVE_BRIDGE_SOURCE_CHANGED"):
        src.verify_native_bridge(bridge, public, bad, receipt)


@pytest.mark.asyncio
async def test_issuer_requires_both_source_and_verifier_before_key_or_native(tmp_path):
    att = tmp_path / "signed.json"
    att.write_text("{}")
    with pytest.raises(ValueError, match="SOURCE_ATTESTATION_AND_TRUST_KEY_REQUIRED"):
        await issuer.issue(tmp_path, tmp_path, tmp_path, tmp_path,
                           durable_postgres=False, source_attestation=att)
    with pytest.raises(ValueError, match="SOURCE_REQUIRES_NATIVE_DURABLE_EFFECT_PATH"):
        await issuer.issue(tmp_path, tmp_path, tmp_path, tmp_path,
                           durable_postgres=False, source_attestation=att,
                           source_trust_key=att)


def test_opt_in_mode_does_not_alter_legacy_native_path():
    from pathlib import Path
    script = Path("scripts/enterprise_iam_lab/run_native_docker.sh").read_text()
    assert 'LAB_SOURCE_BOUND_IAM_ADMISSION:-0' in script
    assert 'IAM2383_SOURCE_REQUIRES_FULL_SIGNED_POSTGRES_RECONCILIATION' in script
    assert 'IAM_SOURCE_BOUND_ARGS=()' in script
    source = Path("scripts/enterprise_iam_lab/native_docker_issuer.py").read_text()
    assert "origin.verify_selected_candidate(source_payload, captured" in source
    assert 'source_payload = None' in source
    assert "allow_in_memory_for_testing=not durable_postgres" in source
