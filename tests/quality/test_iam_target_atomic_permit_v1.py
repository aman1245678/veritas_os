"""Isolated target-side permit integration, with no network or provider calls.

The mTLS identity is a synthetic fixture. This does not exercise the
native VERITAS approval/consume-to-issuer bridge or Docker effect network.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import BytesIO
import importlib.util
import json
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

TARGET = Path(__file__).resolve().parents[2] / "scripts/enterprise_iam_lab/target_service.py"
NOW = datetime.now(timezone.utc)


@pytest.fixture
def lab(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(TARGET.parent))
    monkeypatch.setenv("LAB_DB_PATH", str(tmp_path / "iam.sqlite3"))
    monkeypatch.setenv("LAB_ALLOW_MUTATIONS", "1")
    monkeypatch.setenv("LAB_TEST_PERMIT_GATE", "1")
    monkeypatch.setenv("LAB_PERMIT_ISSUER", "isolated-iam-test-issuer")
    signer = Ed25519PrivateKey.generate()
    pem = tmp_path / "trusted-public.pem"
    pem.write_bytes(signer.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setenv("LAB_PERMIT_VERIFIER_PEM", str(pem))
    spec = importlib.util.spec_from_file_location("isolated_iam_target_2371", TARGET)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.init_db()
    return module, signer


def claims(module, **changes):
    from signed_permit import EXPECTED
    payload = {
        **EXPECTED,
        "issuer": "isolated-iam-test-issuer",
        "permit_id": "permit-001",
        "authorization_id": "authorization-001",
        "execution_intent_id": "intent-001",
        "request_id": "request-001",
        "not_before": (NOW - timedelta(minutes=3)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=3)).isoformat(),
    }
    payload.update(changes)
    return payload


def call(module, envelope=None, *, actor="scoped-executor", role="admin", path=None, raw=None):
    if raw is None:
        raw = json.dumps({"role": role, "permit": envelope}).encode()

    class Connection:
        def getpeercert(self):
            return {"subject": ((("commonName", actor),),)}

    class Request:
        connection = Connection()
        headers = {"Content-Type": "application/json", "Content-Length": str(len(raw))}
        rfile = BytesIO(raw)
        def __init__(self):
            self.path = path or module.TARGET_PATH
            self.responses = []
        def respond(self, status, reason):
            self.responses.append((status, reason))

    request = Request()
    module.Handler.do_POST(request)
    assert len(request.responses) == 1
    return request.responses[0]


def snapshot(module):
    with sqlite3.connect(module.DB_PATH) as db:
        return {
            "grants": db.execute("SELECT user_id, role FROM grants").fetchall(),
            "permits": db.execute(
                "SELECT permit_id, authorization_id, execution_intent_id,"
                " request_id, actor, audit_id FROM permit_consumptions"
            ).fetchall(),
            "audit": db.execute("SELECT id, actor, status, reason FROM audit ORDER BY id").fetchall(),
        }


def test_signed_permit_commits_once_with_target_owned_receipt(lab):
    module, signer = lab
    from signed_permit import sign_permit
    envelope = sign_permit(claims(module), signer)
    assert call(module, envelope) == (201, "committed")
    result = snapshot(module)
    assert result["grants"] == [("contractor-001", "admin")]
    assert len(result["permits"]) == 1
    assert result["permits"][0][:5] == (
        "permit-001", "authorization-001", "intent-001", "request-001", "scoped-executor"
    )
    assert result["audit"] == [
        (result["permits"][0][5], "scoped-executor", 201, "committed")
    ]
    assert call(module, envelope) == (409, "permit_replayed")
    assert snapshot(module)["grants"] == result["grants"]
    assert snapshot(module)["permits"] == result["permits"]


def test_concurrent_replay_has_exactly_one_commit(lab):
    module, signer = lab
    from signed_permit import sign_permit
    envelope = sign_permit(claims(module), signer)
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: call(module, envelope), range(8)))
    assert outcomes.count((201, "committed")) == 1
    assert outcomes.count((409, "permit_replayed")) == 7
    result = snapshot(module)
    assert len(result["grants"]) == len(result["permits"]) == 1


@pytest.mark.parametrize("change", [
    {"scope": "saas:read"}, {"path": "/different"}, {"role": "viewer"},
    {"audience": "other"}, {"issuer": "impostor"},
    {"expires_at": (NOW - timedelta(minutes=1)).isoformat()},
    {"not_before": (NOW + timedelta(minutes=1)).isoformat()},
])
def test_wrong_signed_permit_is_denied_without_effect(lab, change):
    module, signer = lab
    from signed_permit import sign_permit
    assert call(module, sign_permit(claims(module, **change), signer)) == (403, "permit_denied")
    assert snapshot(module)["grants"] == []
    assert snapshot(module)["permits"] == []


def test_untrusted_key_and_changed_signed_content_fail_closed(lab):
    module, signer = lab
    from signed_permit import sign_permit
    wrong_key = Ed25519PrivateKey.generate()
    assert call(module, sign_permit(claims(module), wrong_key)) == (403, "permit_denied")
    envelope = sign_permit(claims(module), signer)
    envelope["payload"]["role"] = "viewer"
    assert call(module, envelope) == (403, "permit_denied")
    assert snapshot(module)["grants"] == []


def test_wrong_body_path_unscoped_and_missing_permit_denied(lab):
    module, signer = lab
    from signed_permit import sign_permit
    envelope = sign_permit(claims(module), signer)
    assert call(module, envelope, actor="unscoped-probe") == (403, "target_scope_denied")
    assert call(module, envelope, role="viewer") == (400, "invalid_mutation")
    assert call(module, envelope, path="/wrong") == (400, "invalid_mutation")
    assert call(module, None) == (400, "invalid_mutation")
    raw = b'{"role":"admin","role":"admin","permit":null}'
    assert call(module, raw=raw) == (400, "invalid_mutation")
    assert snapshot(module)["grants"] == []
    assert snapshot(module)["permits"] == []


def test_no_public_key_fail_closed(lab, monkeypatch):
    module, signer = lab
    from signed_permit import sign_permit
    monkeypatch.delenv("LAB_PERMIT_VERIFIER_PEM")
    assert call(module, sign_permit(claims(module), signer)) == (503, "permit_verifier_unavailable")
    assert snapshot(module)["grants"] == []


def test_ledger_failure_rolls_back_grant_and_success_audit(lab):
    module, signer = lab
    from signed_permit import sign_permit
    with sqlite3.connect(module.DB_PATH) as db:
        db.execute(
            "CREATE TRIGGER fail_ledger BEFORE INSERT ON permit_consumptions "
            "BEGIN SELECT RAISE(ABORT, 'ledger unavailable'); END"
        )
    assert call(module, sign_permit(claims(module), signer)) == (503, "target_commit_unavailable")
    assert snapshot(module) == {"grants": [], "permits": [], "audit": []}


def test_new_permit_cannot_reuse_consumed_authorization(lab):
    module, signer = lab
    from signed_permit import sign_permit
    assert call(module, sign_permit(claims(module), signer)) == (201, "committed")
    second = claims(module, permit_id="permit-002", request_id="request-002")
    assert call(module, sign_permit(second, signer)) == (409, "permit_replayed")
    assert len(snapshot(module)["permits"]) == 1
