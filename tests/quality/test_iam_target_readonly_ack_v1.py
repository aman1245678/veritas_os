"""#2379: adversarial target-owned signed read-only reconciliation receipt tests."""
from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from unittest.mock import patch

import pytest

from scripts.enterprise_iam_lab.target_readonly_receipt import (
    SOURCE_IDENTITY, SCHEMA, UnknownEffect, canonical,
    committed_from_target, generate_disposable_key, sign_committed,
)
from scripts.enterprise_iam_lab.verify_readonly_ack import (
    verify_target_signature, verify_readonly_topology, verify_probes,
)


def db_fixture(path: Path, permit_id: str) -> None:
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE grants (user_id TEXT PRIMARY KEY,role TEXT NOT NULL)")
        db.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT,status INTEGER,reason TEXT)")
        db.execute("CREATE TABLE permit_consumptions (permit_id TEXT PRIMARY KEY, authorization_id TEXT UNIQUE,execution_intent_id TEXT,request_id TEXT,actor TEXT,audit_id INTEGER,consumed_at TEXT)")
        db.execute("INSERT INTO grants VALUES ('contractor-001','admin')")
        db.execute("INSERT INTO audit(actor,status,reason) VALUES ('scoped-executor',201,'committed')")
        db.execute("INSERT INTO permit_consumptions VALUES (?,?,?,?,?,?,?)",(
            permit_id, "authorization-" + "a" * 64, "intent-" + "b" * 64,
            "request-" + "c" * 64, "scoped-executor", 1,
            datetime.now(timezone.utc).isoformat(),
        ))


@pytest.fixture()
def sample(tmp_path):
    permit = "iam-permit:v1:sha256:" + "f" * 64
    target = tmp_path / "target.sqlite3"
    db_fixture(target, permit)
    return target, permit


def test_real_target_key_signs_verified_committed_row(sample, tmp_path):
    target, permit = sample
    private = tmp_path / "key.pem"
    public = tmp_path / "pub.pem"
    generate_disposable_key(private, public)
    envelope = sign_committed(committed_from_target(target, permit), private)
    verified = verify_target_signature(envelope, public.read_bytes())
    assert verified["schema"] == SCHEMA
    assert verified["source_identity"] == SOURCE_IDENTITY
    assert verified["status"] == "committed"
    assert verified["permit_id"] == permit
    assert verified["audit_status"] == 201
    assert private.stat().st_mode & 0o077 == 0


def test_target_signer_is_single_use(tmp_path):
    private = tmp_path / "key.pem"
    public = tmp_path / "pub.pem"
    generate_disposable_key(private, public)
    with pytest.raises(ValueError, match="IAM2379_SIGNER_ALREADY_EXISTS"):
        generate_disposable_key(private, public)


def test_unknown_reference_never_gets_signed_noeffect(sample):
    path, _ = sample
    with pytest.raises(UnknownEffect, match="IAM2379_TARGET_EFFECT_NOT_CONFIRMED"):
        committed_from_target(path, "iam-permit:v1:sha256:" + "0" * 64)


@pytest.mark.parametrize("bad", [
    "a" * 64, "iam-permit:v1:sha256:" + "F" * 64,
    "iam-permit:v1:sha256:" + "f" * 63 + "/",
    "iam-permit:v1:sha256:" + "f" * 64 + "?s=1",
])
def test_unexpected_reference_cannot_be_queried(sample, bad):
    path, _ = sample
    with pytest.raises(ValueError, match="IAM2379_REFERENCE_INVALID"):
        committed_from_target(path, bad)


@pytest.mark.parametrize("tamper", [
    "wrong_actor", "different_grant", "wrong_audit_status", "extra_consumption",
])
def test_target_denies_inconsistent_commit_state(sample, tamper):
    path, permit = sample
    with sqlite3.connect(path) as db:
        if tamper == "wrong_actor":
            db.execute("UPDATE permit_consumptions SET actor='unscoped-probe'")
        elif tamper == "different_grant":
            db.execute("UPDATE grants SET role='reader'")
        elif tamper == "wrong_audit_status":
            db.execute("UPDATE audit SET status=202")
        elif tamper == "extra_consumption":
            db.execute("INSERT INTO permit_consumptions VALUES (?,?,?,?,?,?,?)",(
                "iam-permit:v1:sha256:" + "e" * 64,
                "authorization2", "intent2", "request2", "scoped-executor", 2,
                datetime.now(timezone.utc).isoformat(),
            ))
    with pytest.raises(UnknownEffect, match="IAM2379_TARGET_EFFECT_LINEAGE_NOT_CONFIRMED"):
        committed_from_target(path, permit)


@pytest.mark.parametrize("field,value", [
    ("status", "not_applied"),
    ("authorization_id", "forged"),
    ("source_identity", "forged-source"),
    ("audit_status", 202),
    ("request_id", "forged-request"),
])
def test_modified_signed_ack_fails_cryptographic_verification(sample, tmp_path, field, value):
    target, permit = sample
    private = tmp_path / "key.pem"
    public = tmp_path / "pub.pem"
    generate_disposable_key(private, public)
    envelope = sign_committed(committed_from_target(target, permit), private)
    envelope["payload"][field] = value
    with pytest.raises(ValueError, match="IAM2379_ACK_SIGNATURE_INVALID"):
        verify_target_signature(envelope, public.read_bytes())


def test_signed_false_success_refused_even_if_signed(sample, tmp_path):
    target, permit = sample
    private = tmp_path / "key.pem"
    public = tmp_path / "pub.pem"
    generate_disposable_key(private, public)
    payload = committed_from_target(target, permit)
    payload["status"] = "not_applied"
    fake = sign_committed(payload, private)
    with pytest.raises(ValueError, match="IAM2379_ACK_UNTRUSTED_STATUS_OR_SCOPE"):
        verify_target_signature(fake, public.read_bytes())


def test_signed_no_effect_claim_is_never_admitted(sample, tmp_path):
    target, permit = sample
    private = tmp_path / "key.pem"
    public = tmp_path / "pub.pem"
    generate_disposable_key(private, public)
    payload = committed_from_target(target, permit)
    payload["status"] = "rejected"
    fake = sign_committed(payload, private)
    with pytest.raises(ValueError, match="IAM2379_ACK_UNTRUSTED_STATUS_OR_SCOPE"):
        verify_target_signature(fake, public.read_bytes())


def test_wrong_public_key_denies_target_ack(sample, tmp_path):
    target, permit = sample
    private = tmp_path / "key.pem"
    public = tmp_path / "pub.pem"
    private2 = tmp_path / "key2.pem"
    public2 = tmp_path / "pub2.pem"
    generate_disposable_key(private, public)
    generate_disposable_key(private2, public2)
    fake = sign_committed(committed_from_target(target, permit), private)
    with pytest.raises(ValueError, match="IAM2379_ACK_SIGNATURE_INVALID"):
        verify_target_signature(fake, public2.read_bytes())


def test_missing_signed_envelope_fails_closed():
    with pytest.raises(ValueError, match="IAM2379_ACK_ENVELOPE_INVALID"):
        verify_target_signature({"payload": {}}, b"bogus")


def test_readonly_probe_requires_three_denials_and_one_valid(tmp_path):
    with pytest.raises(ValueError, match="IAM2379_EVIDENCE_MISSING"):
        verify_probes(tmp_path)


def test_reader_topology_does_not_accept_target_sqlite_mount():
    services = {
        name: {"networks": {"effect_net": {}}, "volumes": []}
        for name in ("iam-target", "reconciliation-reader", "agent-direct",
                     "scoped-executor", "unscoped-probe", "tls-probe",
                     "reconciliation-wrong-scope", "reconciliation-no-cert")
    }
    services["iam-target"]["environment"] = {"LAB_TEST_READONLY_ACK": "1"}
    services["iam-target"]["volumes"] = [{"target": "/run/lab/ack-private"}]
    services["reconciliation-reader"].update(
        {"read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
         "volumes": [
             {"target": "/run/lab/certs"}, {"target": "/run/lab/refs"},
             {"target": "/run/lab/state"},
         ]}
    )
    with patch("scripts.enterprise_iam_lab.verify_readonly_ack.verify_topology"):
        with pytest.raises(ValueError, match="IAM2379_READER_CROSS_BOUNDARY_MOUNT_OR_NETWORK"):
            verify_readonly_topology({"services": services})


def test_target_get_only_allowed_with_separate_reader_scope():
    source = Path("scripts/enterprise_iam_lab/target_service.py").read_text(encoding="utf-8")
    assert 'os.getenv("LAB_TEST_READONLY_ACK", "0") != "1"' in source
    assert 'actor != "reconciliation-reader"' in source
    assert 'self.respond(403, "reconciliation_reader_not_authorized")' in source
    assert 'self.respond(404, "effect_not_confirmed")' in source
    assert "signed_no_effect" not in source
