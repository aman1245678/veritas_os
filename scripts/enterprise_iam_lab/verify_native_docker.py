#!/usr/bin/env python3
"""Independent target-owned SQLite and issuer-permit binding proof for #2375.

The trusted host issuer asserts native consume, but this verifier never
elevates that assertion to production PROVEN. It rechecks the target receipt,
the pinned public-key signature, real wall-clock ledger, exact source SHA,
mTLS/network denials, and absence of agent key mounts.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3

from cryptography.hazmat.primitives.serialization import load_pem_public_key

import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.enterprise_iam_lab.signed_permit import canonical, verify_permit
from veritas_os.security.hash import sha256_of_canonical_json
from scripts.enterprise_iam_lab.verify_transport import (
    PATH, _load, _require_http, _target_state, verify_denials, verify_topology,
)


def _pre_native(folder: Path, database: Path) -> dict:
    _require_http(_load(folder / "missing_permit.json"), "missing-permit", 400, "invalid_mutation")
    agent = _load(folder / "agent_direct.json")
    assert agent["case_id"] == "agent-direct"
    assert agent["result"] == "PASS"
    assert agent["real_tls_socket"] is False
    assert agent["observed_http_status"] is None
    assert agent["target_port"] == 8443
    assert agent["socket_errno"] in (
        errno.ENETUNREACH, errno.EHOSTUNREACH,
        errno.EACCES, errno.EPERM, errno.ETIMEDOUT,
    )
    assert agent["socket_errno_name"] == errno.errorcode[agent["socket_errno"]]
    state = _target_state(database)
    assert state["grants"] == [], "effect happened without native authorization"
    assert state["consumptions"] == [], "permit consumed before native authorization"
    assert state["audit"] == [(1, "scoped-executor", 400, "invalid_mutation")]
    return {
        "result": "PASS", "phase": "pre-native",
        "target_grants_before_native_consumption": 0,
        "target_permit_uses_before_native_consumption": 0,
        "unauthorized_scoped_request_denied": True,
        "agent_direct_tcp_denied": True,
        "production_claim": False,
    }


def _verify_postgres_pre_native() -> None:
    """A disposable native PostgreSQL authority ledger starts with zero writes."""
    url = os.getenv("VERITAS_DATABASE_URL", "")
    if not url.startswith(("postgresql://", "postgresql+psycopg://")):
        raise AssertionError("REAL_POSTGRES_URL_REQUIRED")
    import psycopg
    from veritas_os.storage.db import _normalize_dsn

    with psycopg.connect(_normalize_dsn(url), connect_timeout=5) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM bind_authorization_consumptions")
            assert cursor.fetchone()[0] == 0, "PRE_NATIVE_POSTGRES_ALREADY_CONSUMED"


def _verified_native_postgres_join(receipt: dict, permit: dict, database: Path) -> dict:
    """Independently read durable native DB + target-owned effect; never trust receipt alone."""
    url = os.getenv("VERITAS_DATABASE_URL", "")
    if not url.startswith(("postgresql://", "postgresql+psycopg://")):
        raise AssertionError("REAL_POSTGRES_URL_REQUIRED")
    import psycopg
    from veritas_os.storage.db import _normalize_dsn

    with psycopg.connect(_normalize_dsn(url), connect_timeout=5) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT consumption_id, consumption_hash, authorization_id, "
                "authorization_hash, idempotency_key, execution_intent_id, "
                "execution_intent_hash, consumed_at, record "
                "FROM bind_authorization_consumptions WHERE authorization_id = %s",
                (permit["authorization_id"],),
            )
            rows = cursor.fetchall()
            assert len(rows) == 1, "NATIVE_POSTGRES_ROW_MISSING_OR_DUPLICATED"
            (consumption_id, consumption_hash, authorization_id,
             authorization_hash, idem, intent_id, intent_hash, consumed_at, record) = rows[0]
            cursor.execute(
                "SELECT count(*) FROM bind_authorization_consumptions "
                "WHERE idempotency_key = %s", (permit["request_id"],),
            )
            assert cursor.fetchone()[0] == 1, "NATIVE_POSTGRES_IDEMPOTENCY_DRIFT"
    assert isinstance(record, dict), "NATIVE_POSTGRES_RECORD_NOT_OBJECT"
    assert (
        authorization_id == receipt["authorization_id"] == permit["authorization_id"]
        and authorization_hash == receipt["authorization_hash"]
        and idem == receipt["request_id"] == permit["request_id"]
        and intent_id == receipt["execution_intent_id"] == permit["execution_intent_id"]
        and consumption_id == receipt["consumption_id"] == record["consumption_id"]
        and consumption_hash == receipt["consumption_hash"] == record["consumption_hash"]
        and record["live_adapter_bind_authorization_id"] == authorization_id
        and record["live_adapter_bind_authorization_hash"] == authorization_hash
        and record["idempotency_key"] == idem
        and record["execution_intent_id"] == intent_id
        and record["execution_intent_hash"] == intent_hash
        and record["consumption_state"] == "CONSUMED"
        and record["single_use_enforced"] is True
    ), "NATIVE_POSTGRES_LINEAGE_MISMATCH"
    unsigned = {
        key: value for key, value in record.items()
        if key not in ("consumption_hash", "consumption_id")
    }
    assert sha256_of_canonical_json(unsigned) == consumption_hash
    assert consumption_id == "labac:v1:sha256:" + consumption_hash
    native_consumed_at = datetime.fromisoformat(record["consumed_at"])
    assert native_consumed_at.tzinfo is not None
    assert native_consumed_at.astimezone(timezone.utc) == consumed_at.astimezone(timezone.utc)
    assert receipt["consumption_recorded_at"] == record["consumed_at"]
    assert native_consumed_at <= datetime.fromisoformat(permit["not_before"])

    # The separate synthetic IAM SQLite ledger must record the same exact
    # verified permit AFTER PostgreSQL's authorization consumption.
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as conn:
        target_rows = conn.execute(
            "SELECT consumed_at FROM permit_consumptions WHERE permit_id = ? "
            "AND authorization_id = ? AND execution_intent_id = ? AND request_id = ?",
            (
                permit["permit_id"], authorization_id, intent_id, idem,
            ),
        ).fetchall()
    assert len(target_rows) == 1, "TARGET_NOT_LINKED_TO_POSTGRES_CONSUMPTION"
    target_consumed_at = datetime.fromisoformat(target_rows[0][0])
    assert native_consumed_at <= target_consumed_at < datetime.fromisoformat(permit["expires_at"])
    return {
        "native_postgres_consumption_rows": 1,
        "native_postgres_idempotency_rows": 1,
        "target_effects_linked_to_postgres": 1,
        "native_consumed_before_target_effect": True,
        "native_record_digest_verified": True,
    }


def verify(
    *, phase: str, folder: Path, config: dict, database: Path,
    trust_dir: Path | None = None, permit_dir: Path | None = None,
    source_sha: str = "", expected_sha: str = "",
    require_native_postgres: bool = False,
) -> dict:
    top = verify_topology(config)
    assert top["target_verifier_key_not_mounted_on_executor_or_agent"]
    assert top["scoped_client_credential_not_mounted_on_agent"]
    if phase == "pre-native":
        pre = _pre_native(folder, database)
        if require_native_postgres:
            _verify_postgres_pre_native()
            pre["native_postgres_consumptions_before_issuance"] = 0
        return pre

    assert phase == "post-native"
    assert trust_dir is not None and permit_dir is not None
    assert re.fullmatch(r"[0-9a-f]{40}", source_sha)
    assert source_sha == expected_sha

    verify_denials(folder)
    _require_http(_load(folder / "allow.json"), "allow", 201, "committed")
    _require_http(_load(folder / "replay.json"), "replay", 409, "permit_replayed")

    prep = _load(folder / "native_issuer_prepare.json")
    assert prep["result"] == "PASS" and prep["issuer_private_key_mounted"] is False
    run = _load(folder / "native_issuer_run.json")
    assert run["result"] == "PASS" and run["native_authorization_consumed"] is True
    receipt = _load(folder / "native_issuer_receipt.json")
    assert receipt["issuer_mode"] == (
        "REAL_NATIVE_POSTGRES_CONSUME_TEST_ONLY"
        if require_native_postgres else "REAL_NATIVE_CONSUME_TEST_ONLY"
    )
    assert receipt["result"] == "PASS"
    assert receipt["native_veritas_authorization_exercised"] is True
    assert receipt["native_signed_human_approval_verified"] is True
    assert receipt["native_authorization_consumed"] is True
    assert receipt["native_store_durable"] is require_native_postgres
    assert receipt["native_in_memory_test_override"] is (not require_native_postgres)
    assert receipt["synthetic_provider_clients_only"] is True
    assert receipt["production_claim"] is False
    assert receipt["external_iam_provider_called"] is False
    for field in ("approval_proof_digest", "consumption_id", "authorization_hash"):
        assert isinstance(receipt[field], str) and len(receipt[field]) >= 32
    assert receipt["authorization_id"].startswith("laba:v2:sha256:")
    assert receipt["permit_id"].startswith("iam-permit:v1:sha256:")
    assert not receipt["permit_id"].startswith("transport-only:")
    assert not receipt["authorization_id"].startswith("transport-only:")

    envelope = _load(permit_dir / "valid.json")
    public_key = load_pem_public_key((trust_dir / "permit-public.pem").read_bytes())
    issued_at = datetime.fromisoformat(receipt["permit_not_before"])
    assert issued_at.tzinfo is not None
    verified = verify_permit(envelope, public_key, issued_at)
    assert hashlib.sha256(canonical(verified)).hexdigest() == receipt["permit_payload_sha256"]
    assert verified["issuer"] == "isolated-iam-test-issuer"
    assert verified["authorization_id"] == receipt["authorization_id"]
    assert verified["execution_intent_id"] == receipt["execution_intent_id"]
    assert verified["request_id"] == receipt["request_id"]
    assert verified["permit_id"] == receipt["permit_id"]
    assert verified["not_before"] == receipt["permit_not_before"]
    assert verified["expires_at"] == receipt["permit_expires_at"]
    expiration = datetime.fromisoformat(verified["expires_at"])
    assert timedelta(0) < expiration - issued_at <= timedelta(seconds=10)

    state = _target_state(database)
    assert state["grants"] == [("contractor-001", "admin")]
    assert len(state["consumptions"]) == 1
    consumption = state["consumptions"][0]
    assert consumption[:5] == (
        verified["permit_id"], verified["authorization_id"],
        verified["execution_intent_id"], verified["request_id"],
        "scoped-executor",
    )
    success = [item for item in state["audit"] if item[2] == 201]
    assert success == [(consumption[5], "scoped-executor", 201, "committed")]
    assert len([item for item in state["audit"] if item[2] == 409 and item[3] == "permit_replayed"]) == 1
    assert len([item for item in state["audit"] if item[2] == 400 and item[3] == "invalid_mutation"]) == 1
    assert len([item for item in state["audit"] if item[2] == 403 and item[3] == "permit_denied"]) == 2
    assert len([item for item in state["audit"] if item[2] == 403 and item[3] == "target_scope_denied"]) == 1

    # Inspect original target-owned consumption timestamp, not issuer's
    # self-reported outcome or an arbitrary fixture-time clock.
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
        consumed_at_str = db.execute(
            "SELECT consumed_at FROM permit_consumptions WHERE permit_id = ?",
            (verified["permit_id"],),
        ).fetchone()[0]
    consumed_at = datetime.fromisoformat(consumed_at_str)
    assert consumed_at.tzinfo is not None
    assert issued_at <= consumed_at.astimezone(timezone.utc) < expiration

    postgres_evidence = (
        _verified_native_postgres_join(receipt, verified, database)
        if require_native_postgres else {}
    )
    return {
        "result": "PASS",
        "phase": "post-native",
        "proof_status": (
            "SYNTHETIC_NATIVE_POSTGRES_CONSUME_TO_REAL_DOCKER_MTLS_NOT_PROVEN"
            if require_native_postgres
            else "SYNTHETIC_NATIVE_CONSUME_TO_REAL_DOCKER_MTLS_WITH_IN_MEMORY_STORE_NOT_PROVEN"
        ),
        "source_sha": source_sha, "expected_sha": expected_sha,
        "native_signed_approval_and_consumption_observed": True,
        "native_consumption_store_durable": require_native_postgres,
        **postgres_evidence,
        "target_native_permit_binding_verified": True,
        "real_mtls_allowed_exactly_once": True,
        "replay_rejected": True,
        "target_grants": len(state["grants"]),
        "target_permit_consumptions": len(state["consumptions"]),
        "target_audit_linked_successes": len(success),
        "agent_direct_tcp_denied": True,
        "unscoped_and_certless_denied": True,
        "unauthorized_and_tampered_requests_denied": True,
        "production_claim": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("pre-native", "post-native"), required=True)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--trust-dir", type=Path)
    parser.add_argument("--permit-dir", type=Path)
    parser.add_argument("--source-sha", default="")
    parser.add_argument("--expected-sha", default="")
    parser.add_argument("--require-native-postgres", action="store_true")
    args = parser.parse_args()
    result = verify(
        phase=args.phase, folder=args.report_dir,
        config=_load(args.compose), database=args.database,
        trust_dir=args.trust_dir, permit_dir=args.permit_dir,
        source_sha=args.source_sha, expected_sha=args.expected_sha,
        require_native_postgres=args.require_native_postgres,
    )
    output = args.report_dir / ("verification_" + args.phase.replace("-", "_") + ".json")
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
