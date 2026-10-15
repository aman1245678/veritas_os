"""Offline adversarial checks of sanitized synthetic native -> Docker proof.

No Docker daemon or cloud clients are needed for these tests. The dedicated
GitHub Actions job runs the separate REAL-Docker native approval integration.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import errno
import json
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from scripts.enterprise_iam_lab import target_service
from scripts.enterprise_iam_lab.signed_permit import EXPECTED, canonical, sign_permit
from scripts.enterprise_iam_lab.verify_native_docker import verify

SHA = "f" * 40


def _config():
    assignments = {
        "iam-target": ("effect_net", ["/run/lab/certs", "/run/lab/trust", "/run/lab/state"]),
        "scoped-executor": ("effect_net", ["/run/lab/certs", "/run/lab/permits"]),
        "unscoped-probe": ("effect_net", ["/run/lab/certs", "/run/lab/permits"]),
        "tls-probe": ("effect_net", ["/run/lab/certs", "/run/lab/permits"]),
        "agent-direct": ("agent_net", []),
    }
    services = {}
    for name, (net, mounts) in assignments.items():
        services[name] = {
            "networks": {net: {}},
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "volumes": [
                {"target": mount, "read_only": mount != "/run/lab/state"}
                for mount in mounts
            ],
        }
    services["iam-target"]["environment"] = {
        "LAB_ALLOW_MUTATIONS": "1",
        "LAB_TEST_PERMIT_GATE": "1",
        "LAB_PERMIT_VERIFIER_PEM": "/run/lab/trust/permit-public.pem",
    }
    return {
        "services": services,
        "networks": {"effect_net": {"internal": True}, "agent_net": {"internal": True}},
    }


def _http(case, status, reason):
    return {
        "case_id": case, "result": "PASS",
        "observed_failure_kind": "TARGET_HTTP_RESPONSE",
        "observed_http_status": status,
        "observed_reason": reason,
        "target_path": EXPECTED["path"],
        "real_tls_socket": True,
        "native_veritas_authorization_exercised": False,
        "production_claim": False,
    }


def _write(folder, name, obj):
    (folder / name).write_text(json.dumps(obj), encoding="utf-8")


@pytest.fixture()
def native_evidence(tmp_path, monkeypatch):
    evidence_dir = tmp_path / "reports"
    trust_dir = tmp_path / "trust"
    permit_dir = tmp_path / "permits"
    evidence_dir.mkdir()
    trust_dir.mkdir()
    permit_dir.mkdir()
    database = tmp_path / "iam.sqlite3"
    monkeypatch.setattr(target_service, "DB_PATH", database)
    target_service.init_db()

    signer = Ed25519PrivateKey.generate()
    (trust_dir / "permit-public.pem").write_bytes(
        signer.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    now = datetime.now(timezone.utc) - timedelta(seconds=2)
    payload = {
        **EXPECTED, "issuer": "isolated-iam-test-issuer",
        "permit_id": "iam-permit:v1:sha256:" + "a" * 64,
        "authorization_id": "laba:v2:sha256:" + "b" * 64,
        "execution_intent_id": "ei:v1:sha256:" + "c" * 64,
        "request_id": "laba-idem:v2:sha256:" + "d" * 64,
        "not_before": now.isoformat(),
        "expires_at": (now + timedelta(seconds=10)).isoformat(),
    }
    envelope = sign_permit(payload, signer)
    _write(permit_dir, "valid.json", envelope)
    import hashlib
    receipt = {
        "issuer_mode": "REAL_NATIVE_CONSUME_TEST_ONLY",
        "result": "PASS",
        "native_veritas_authorization_exercised": True,
        "native_signed_human_approval_verified": True,
        "native_authorization_consumed": True,
        "native_store_durable": False,
        "native_in_memory_test_override": True,
        "synthetic_provider_clients_only": True,
        "production_claim": False,
        "external_iam_provider_called": False,
        "approval_proof_digest": "0" * 64,
        "consumption_id": "native-consume:" + "1" * 64,
        "authorization_hash": "b" * 64,
        "authorization_id": payload["authorization_id"],
        "permit_id": payload["permit_id"],
        "execution_intent_id": payload["execution_intent_id"],
        "request_id": payload["request_id"],
        "permit_payload_sha256": hashlib.sha256(canonical(payload)).hexdigest(),
        "permit_not_before": payload["not_before"],
        "permit_expires_at": payload["expires_at"],
    }
    _write(evidence_dir, "native_issuer_receipt.json", receipt)
    _write(evidence_dir, "native_issuer_prepare.json", {
        "result": "PASS", "issuer_private_key_mounted": False,
    })
    _write(evidence_dir, "native_issuer_run.json", {
        "result": "PASS", "native_authorization_consumed": True,
    })
    for filename, case, status, reason in [
        ("missing_permit.json", "missing-permit", 400, "invalid_mutation"),
        ("tampered.json", "tamper", 403, "permit_denied"),
        ("wrong_signer.json", "wrong-signer", 403, "permit_denied"),
        ("unscoped.json", "unscoped", 403, "target_scope_denied"),
        ("allow.json", "allow", 201, "committed"),
        ("replay.json", "replay", 409, "permit_replayed"),
    ]:
        _write(evidence_dir, filename, _http(case, status, reason))
    _write(evidence_dir, "no_client_cert.json", {
        "case_id": "no-client-cert", "result": "PASS",
        "observed_failure_kind": "TLS_CLIENT_CERT_REJECTED",
        "observed_http_status": None, "real_tls_socket": True,
        "production_claim": False,
    })
    _write(evidence_dir, "agent_direct.json", {
        "case_id": "agent-direct", "result": "PASS",
        "observed_http_status": None, "real_tls_socket": False,
        "target_port": 8443, "socket_errno": errno.ENETUNREACH,
        "socket_errno_name": "ENETUNREACH",
    })
    target_service.record("scoped-executor", 400, "invalid_mutation")
    return evidence_dir, trust_dir, permit_dir, database, payload, _config()


def _commit_target(native_evidence):
    folder, trust_dir, permit_dir, database, payload, cfg = native_evidence
    with sqlite3.connect(database) as db:
        db.execute(
            "INSERT INTO grants(user_id, role) VALUES (?, ?)",
            ("contractor-001", "admin"),
        )
        cur = db.execute(
            "INSERT INTO audit(actor,status,reason) VALUES (?,?,?)",
            ("scoped-executor", 201, "committed"),
        )
        db.execute(
            "INSERT INTO permit_consumptions("
            "permit_id,authorization_id,execution_intent_id,request_id,"
            "actor,audit_id,consumed_at) VALUES(?,?,?,?,?,?,?)",
            (
                payload["permit_id"], payload["authorization_id"],
                payload["execution_intent_id"], payload["request_id"],
                "scoped-executor", cur.lastrowid,
                (datetime.now(timezone.utc)).isoformat(),
            ),
        )
        for actor, status, reason in [
            ("scoped-executor", 409, "permit_replayed"),
            ("scoped-executor", 403, "permit_denied"),
            ("scoped-executor", 403, "permit_denied"),
            ("unscoped-probe", 403, "target_scope_denied"),
        ]:
            db.execute(
                "INSERT INTO audit(actor,status,reason) VALUES(?,?,?)",
                (actor, status, reason),
            )


def _verify(evidence, phase, source_sha=SHA, expected_sha=SHA):
    folder, trust_dir, permit_dir, database, _, cfg = evidence
    return verify(
        phase=phase, folder=folder, config=cfg, database=database,
        trust_dir=trust_dir, permit_dir=permit_dir,
        source_sha=source_sha, expected_sha=expected_sha,
    )


def test_pre_native_is_fail_closed_and_post_binds_real_permit_to_target(native_evidence):
    assert _verify(native_evidence, "pre-native")["target_grants_before_native_consumption"] == 0
    _commit_target(native_evidence)
    result = _verify(native_evidence, "post-native")
    assert result["target_native_permit_binding_verified"] is True
    assert result["native_consumption_store_durable"] is False
    assert result["proof_status"].endswith("NOT_PROVEN")


@pytest.mark.parametrize("field,invalid", [
    ("native_signed_human_approval_verified", False),
    ("native_authorization_consumed", False),
    ("native_store_durable", True),
    ("issuer_mode", "TRANSPORT_ONLY"),
    ("permit_id", "transport-only:permit:any"),
])
def test_forged_native_receipt_fails_closed(native_evidence, field, invalid):
    _commit_target(native_evidence)
    folder = native_evidence[0]
    raw = json.loads((folder / "native_issuer_receipt.json").read_text())
    raw[field] = invalid
    _write(folder, "native_issuer_receipt.json", raw)
    with pytest.raises(AssertionError):
        _verify(native_evidence, "post-native")


def test_changed_source_sha_and_missing_target_ledger_fail_closed(native_evidence):
    _commit_target(native_evidence)
    with pytest.raises(AssertionError):
        _verify(native_evidence, "post-native", source_sha=SHA, expected_sha="e" * 40)
    with sqlite3.connect(native_evidence[3]) as db:
        db.execute("DELETE FROM permit_consumptions")
    with pytest.raises(AssertionError):
        _verify(native_evidence, "post-native")


def test_tampered_or_untrusted_signature_fails_closed(native_evidence):
    _commit_target(native_evidence)
    envelope = json.loads((native_evidence[2] / "valid.json").read_text())
    envelope["payload"]["scope"] = "saas:read"
    _write(native_evidence[2], "valid.json", envelope)
    with pytest.raises(Exception):
        _verify(native_evidence, "post-native")


def test_actor_can_never_join_target_network(native_evidence):
    cfg = native_evidence[5]
    cfg["services"]["agent-direct"]["networks"] = {"effect_net": {}}
    with pytest.raises(AssertionError):
        _verify(native_evidence, "pre-native")
