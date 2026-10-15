"""Reject forged isolated Docker mTLS transport evidence, without Docker itself."""
from __future__ import annotations

import errno
import json
from pathlib import Path
import sqlite3

import pytest

from scripts.enterprise_iam_lab import target_service
from scripts.enterprise_iam_lab.verify_transport import verify

SHA = "a" * 40


def config():
    networks = {
        "iam-target": "effect_net", "scoped-executor": "effect_net",
        "unscoped-probe": "effect_net", "tls-probe": "effect_net",
        "agent-direct": "agent_net",
    }
    services = {}
    for name, net in networks.items():
        volumes = {
            "iam-target": ["/run/lab/certs", "/run/lab/trust", "/run/lab/state"],
            "scoped-executor": ["/run/lab/certs", "/run/lab/permits"],
            "unscoped-probe": ["/run/lab/certs", "/run/lab/permits"],
            "tls-probe": ["/run/lab/certs", "/run/lab/permits"],
            "agent-direct": [],
        }[name]
        services[name] = {
            "networks": {net: {}}, "read_only": True,
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
            "volumes": [
                {"target": item, "read_only": item != "/run/lab/state"}
                for item in volumes
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


def dump(folder: Path, name: str, data: dict):
    (folder / name).write_text(json.dumps(data), encoding="utf-8")


def observation(case, code, reason):
    return {
        "case_id": case,
        "result": "PASS",
        "observed_failure_kind": "TARGET_HTTP_RESPONSE",
        "observed_http_status": code,
        "observed_reason": reason,
        "target_path": "/v1/iam/users/contractor-001/roles",
        "real_tls_socket": True,
        "native_veritas_authorization_exercised": False,
        "production_claim": False,
    }


@pytest.fixture
def evidence(tmp_path, monkeypatch):
    db = tmp_path / "state.sqlite3"
    monkeypatch.setattr(target_service, "DB_PATH", db)
    target_service.init_db()
    for filename, case, status, reason in [
        ("missing_permit.json", "missing-permit", 400, "invalid_mutation"),
        ("tampered.json", "tamper", 403, "permit_denied"),
        ("wrong_signer.json", "wrong-signer", 403, "permit_denied"),
        ("unscoped.json", "unscoped", 403, "target_scope_denied"),
        ("allow.json", "allow", 201, "committed"),
        ("replay.json", "replay", 409, "permit_replayed"),
    ]:
        dump(tmp_path, filename, observation(case, status, reason))
    dump(tmp_path, "no_client_cert.json", {
        "case_id": "no-client-cert", "result": "PASS",
        "observed_failure_kind": "TLS_CLIENT_CERT_REJECTED",
        "observed_http_status": None, "real_tls_socket": True,
        "production_claim": False,
    })
    dump(tmp_path, "agent_direct.json", {
        "case_id": "agent-direct", "result": "PASS",
        "observed_http_status": None, "real_tls_socket": False,
        "target_port": 8443, "socket_errno": errno.ENETUNREACH,
        "socket_errno_name": "ENETUNREACH",
    })
    for actor, status, reason in [
        ("scoped-executor", 400, "invalid_mutation"),
        ("scoped-executor", 403, "permit_denied"),
        ("scoped-executor", 403, "permit_denied"),
        ("unscoped-probe", 403, "target_scope_denied"),
    ]:
        target_service.record(actor, status, reason)
    return tmp_path, db, config()


def commit(evidence):
    folder, database, configuration = evidence
    with sqlite3.connect(database) as db:
        db.execute(
            "INSERT INTO grants(user_id, role) VALUES (?, ?)",
            ("contractor-001", "admin"),
        )
        cur = db.execute(
            "INSERT INTO audit(actor, status, reason) VALUES (?, ?, ?)",
            ("scoped-executor", 201, "committed"),
        )
        db.execute(
            "INSERT INTO permit_consumptions(permit_id, authorization_id,"
            "execution_intent_id, request_id, actor, audit_id, consumed_at)"
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "transport-only:permit:1", "transport-only:authorization:1",
                "transport-only:intent:1", "transport-only:request:1",
                "scoped-executor", cur.lastrowid, "2026-10-15T00:00:00+00:00",
            ),
        )
        db.execute(
            "INSERT INTO audit(actor, status, reason) VALUES (?, ?, ?)",
            ("scoped-executor", 409, "permit_replayed"),
        )


def test_topology_and_denials_then_exactly_one_grant(evidence):
    folder, database, configuration = evidence
    assert verify(folder, configuration, database, "topology")["result"] == "PASS"
    assert verify(folder, configuration, database, "pre-allow")["observed_iam_grants"] == 0
    commit(evidence)
    report = verify(folder, configuration, database, "post-allow", SHA, SHA)
    assert report["result"] == "PASS"
    assert report["observed_iam_grants"] == 1
    assert report["native_veritas_authorization_exercised"] is False


def test_agent_adjacency_or_missing_mtls_rejected(evidence):
    folder, database, configuration = evidence
    configuration["services"]["agent-direct"]["networks"] = {"effect_net": {}}
    with pytest.raises(AssertionError):
        verify(folder, configuration, database, "topology")
    configuration = config()
    configuration["services"]["scoped-executor"]["volumes"] = []
    with pytest.raises(AssertionError):
        verify(folder, configuration, database, "topology")


def test_forged_tls_or_http_observation_rejected(evidence):
    folder, database, configuration = evidence
    certless = json.loads((folder / "no_client_cert.json").read_text())
    certless["observed_failure_kind"] = "CERTLESS_HTTP_REACHED"
    dump(folder, "no_client_cert.json", certless)
    with pytest.raises(AssertionError):
        verify(folder, configuration, database, "pre-allow")


def test_false_tcp_denial_is_rejected(evidence):
    folder, database, configuration = evidence
    record = json.loads((folder / "agent_direct.json").read_text())
    record.update({"socket_errno": errno.ECONNREFUSED, "socket_errno_name": "ECONNREFUSED"})
    dump(folder, "agent_direct.json", record)
    with pytest.raises(AssertionError):
        verify(folder, configuration, database, "pre-allow")


def test_replay_missing_and_sha_mismatch_are_rejected(evidence):
    folder, database, configuration = evidence
    commit(evidence)
    with pytest.raises(AssertionError):
        verify(folder, configuration, database, "post-allow", SHA, "b" * 40)
    with sqlite3.connect(database) as db:
        db.execute("DELETE FROM audit WHERE status=409")
    with pytest.raises(AssertionError):
        verify(folder, configuration, database, "post-allow", SHA, SHA)


def test_duplicate_or_missing_target_effects_rejected(evidence):
    folder, database, configuration = evidence
    commit(evidence)
    with sqlite3.connect(database) as db:
        db.execute("DELETE FROM grants")
    with pytest.raises(AssertionError):
        verify(folder, configuration, database, "post-allow", SHA, SHA)
