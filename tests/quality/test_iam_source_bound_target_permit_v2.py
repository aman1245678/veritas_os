"""#2384: target-side signed-source Permit v2 refusals and SQLite replay fence.

Tests model a controlled same-host origin. They cannot establish independent
RCC operator provenance, production identity/key management or actual AgentDojo.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from scripts.enterprise_iam_lab import target_service
from scripts.enterprise_iam_lab import source_bound_target_policy as target
from scripts.enterprise_iam_lab.signed_permit import (
    EXPECTED, V2, PermitRejected, sign_permit, verify_permit,
    canonical,
)


def sample():
    now = datetime.now(timezone.utc)
    source_key = Ed25519PrivateKey.generate()
    pub = source_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    actor = "synthetic-iam-operator"
    original = {
        "source": "rcc-revas-controlled-synthetic-iam-request",
        "actor_identity": actor,
        "target_system": "isolated-iam-target",
        "target_resource": "contractor-001",
        "intended_action": "grant_admin_role",
        "scope": "saas:grant_admin",
        "role": "admin",
        "user_request": "Grant admin role to contractor-001 in isolated IAM.",
    }
    candidate = {
        "candidate_id": "controlled-candidate-2384",
        "actor_identity": actor,
        **deepcopy(target.EXACT_SOURCE_TARGET),
    }
    payload = {
        "schema": target.ORIGIN_SCHEMA,
        "original_request": original,
        "original_request_digest": target.digest(original),
        "candidate": candidate,
        "candidate_digest": target.digest(candidate),
        "issued_at": (now - timedelta(seconds=1)).isoformat(),
        "expires_at": (now + timedelta(seconds=90)).isoformat(),
        "nonce": "d" * 64,
        "production_claim": False,
    }
    envelope = {
        "payload": payload,
        "signature": base64.b64encode(source_key.sign(target.canon(payload))).decode(),
    }
    issuer = Ed25519PrivateKey.generate()
    claims = {
        **EXPECTED,
        "version": V2,
        "issuer": "isolated-iam-test-issuer",
        "permit_id": "iam-permit:v1:sha256:" + "a" * 64,
        "authorization_id": "laba:v2:sha256:" + "b" * 64,
        "execution_intent_id": "ei:v1:sha256:" + "c" * 64,
        "request_id": "laba-idem:v2:sha256:" + "d" * 64,
        "not_before": (now - timedelta(seconds=1)).isoformat(),
        "expires_at": (now + timedelta(seconds=9)).isoformat(),
        "source_envelope": envelope,
        "original_request_digest": payload["original_request_digest"],
        "candidate_digest": payload["candidate_digest"],
        "source_attestation_digest": target.digest(payload),
        "source_nonce_sha256": hashlib.sha256(payload["nonce"].encode("ascii")).hexdigest(),
    }
    return now, pub, source_key, issuer, claims


def test_target_verifies_two_separate_signed_sources():
    now, pub, _, issuer, claims = sample()
    signed = sign_permit(claims, issuer)
    checked = verify_permit(signed, issuer.public_key(), now)
    assert target.verify_target_source(checked, pub, now=now) == claims["source_nonce_sha256"]
    assert hashlib.sha256(canonical(checked)).digest()


@pytest.mark.parametrize("field,value", [
    ("original_request_digest", "0" * 64),
    ("candidate_digest", "0" * 64),
    ("source_attestation_digest", "0" * 64),
    ("source_nonce_sha256", "0" * 64),
    ("scope", "saas:read"),
    ("role", "viewer"),
    ("subject", "other-subject"),
    ("path", "/v1/iam/users/other/roles"),
    ("version", EXPECTED["version"]),
])
def test_issuer_signature_alone_cannot_override_signed_source(field, value):
    now, pub, _, issuer, claims = sample()
    altered = deepcopy(claims)
    altered[field] = value
    # Even a valid fresh issuer signature cannot promote a different source.
    if field == "version":
        with pytest.raises(PermitRejected):
            sign_permit(altered, issuer)
    else:
        signed = sign_permit(altered, issuer)
        # Some actions are rejected at the v2 Permit's own effect-binding
        # verifier, while validly signed source-digest changes get denied by
        # the independent target origin verifier. Both are fail-closed.
        with pytest.raises((PermitRejected, target.TargetSourceDenied)):
            checked = verify_permit(signed, issuer.public_key(), now)
            target.verify_target_source(checked, pub, now=now)


@pytest.mark.parametrize("change", [
    lambda p: p["candidate"].update(target_resource="bank-root"),
    lambda p: p["candidate"].update(intended_action="local_counter_increment"),
    lambda p: p["candidate"].update(required_authority=["saas:read"]),
    lambda p: p["original_request"].update(actor_identity="wrong-actor"),
    lambda p: p["original_request"].update(scope="other:role"),
    lambda p: p.update(production_claim=True),
    lambda p: p.update(nonce="0" * 63 + "Z"),
    lambda p: p.update(expires_at="2020-01-01T00:00:00+00:00"),
])
def test_resigned_origin_misuse_rejected_even_when_permit_issuer_trusted(change):
    now, pub, source, issuer, claims = sample()
    bad = deepcopy(claims)
    payload = bad["source_envelope"]["payload"]
    change(payload)
    payload["original_request_digest"] = target.digest(payload["original_request"])
    payload["candidate_digest"] = target.digest(payload["candidate"])
    bad["source_envelope"]["signature"] = base64.b64encode(
        source.sign(target.canon(payload))).decode()
    bad["original_request_digest"] = payload["original_request_digest"]
    bad["candidate_digest"] = payload["candidate_digest"]
    bad["source_attestation_digest"] = target.digest(payload)
    bad["source_nonce_sha256"] = hashlib.sha256(
        payload["nonce"].encode()).hexdigest()
    verified = verify_permit(sign_permit(bad, issuer), issuer.public_key(), now)
    with pytest.raises(target.TargetSourceDenied):
        target.verify_target_source(verified, pub, now=now)


def test_replaced_origin_key_and_modified_v2_outer_signature_both_denied():
    now, pub, source, issuer, claims = sample()
    forged_source = deepcopy(claims)
    forged_source["source_envelope"]["signature"] = base64.b64encode(
        Ed25519PrivateKey.generate().sign(
            target.canon(forged_source["source_envelope"]["payload"])
        )).decode()
    verified = verify_permit(sign_permit(forged_source, issuer), issuer.public_key(), now)
    with pytest.raises(target.TargetSourceDenied, match="ORIGIN_SIGNATURE"):
        target.verify_target_source(verified, pub, now=now)
    signed = sign_permit(claims, issuer)
    signed["payload"]["source_nonce_sha256"] = "a" * 64
    with pytest.raises(PermitRejected):
        verify_permit(signed, issuer.public_key(), now)


def test_nested_noncanonical_and_extra_permit_fields_fail_closed():
    now, pub, _, issuer, claims = sample()
    bad = deepcopy(claims)
    bad["unexpected"] = "permit-downgrade"
    with pytest.raises(PermitRejected):
        sign_permit(bad, issuer)
    bad = deepcopy(claims)
    bad["source_envelope"]["payload"]["unexpected"] = "authority"
    with pytest.raises(target.TargetSourceDenied):
        target.verify_target_source(bad, pub, now=now)


def test_expired_source_refused_even_when_permit_still_valid():
    now, pub, _, issuer, claims = sample()
    with pytest.raises(target.TargetSourceDenied, match="SOURCE_EXPIRED"):
        target.verify_target_source(
            claims, pub, now=now + timedelta(minutes=3))


def test_target_sqlite_rejects_same_source_nonce_under_new_authorization(tmp_path, monkeypatch):
    db_path = tmp_path / "iam.sqlite3"
    monkeypatch.setattr(target_service, "DB_PATH", db_path)
    target_service.init_db()
    now, pub, _, issuer, claims = sample()
    first = verify_permit(sign_permit(claims, issuer), issuer.public_key(), now)
    digest = target.verify_target_source(first, pub, now=now)
    code, reason = target_service.commit_verified_permit(
        "scoped-executor", first, now, source_nonce_sha256=digest)
    assert (code, reason) == (201, "committed")
    changed = deepcopy(first)
    changed["permit_id"] = "iam-permit:v1:sha256:" + "e" * 64
    changed["authorization_id"] = "laba:v2:sha256:" + "f" * 64
    # Valid fresh issuer signature/authorization IDs, SAME signed source nonce.
    second = verify_permit(sign_permit(changed, issuer), issuer.public_key(), now)
    second_digest = target.verify_target_source(second, pub, now=now)
    assert target_service.commit_verified_permit(
        "scoped-executor", second, now, source_nonce_sha256=second_digest
    ) == (409, "source_replayed")
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT count(*) FROM grants").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM permit_consumptions").fetchone()[0] == 1
        assert db.execute("SELECT source_nonce_sha256 FROM permit_consumptions").fetchone()[0] == digest


def test_v1_backward_compatible_schema_unchanged():
    now, _, _, issuer, claims = sample()
    old = {k: v for k, v in claims.items() if k not in
           target.PERMIT_SOURCE_KEYS} | {"version": EXPECTED["version"]}
    envelope = sign_permit(old, issuer)
    assert verify_permit(envelope, issuer.public_key(), now) == old
    with pytest.raises(target.TargetSourceDenied, match="V2_PERMIT_REQUIRED"):
        target.verify_target_source(old, b"invalid", now=now)
