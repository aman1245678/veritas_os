"""Synthetic IAM target-owned, read-only signed acknowledgement.

This module runs ONLY within disposable iam-target. No missing row can certify
CONFIRMED_NO_EFFECT; unknown stays unknown. The target signs a COMMITTED
receipt only after reading its own SQLite ledger. No grant mutation here.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key,
)

PREFIX = "/v1/iam/reconciliation/"
REF_PATTERN = re.compile(r"iam-permit:v1:sha256:[0-9a-f]{64}\Z")
FIELDS = frozenset({
    "schema", "source_identity", "external_operation_reference", "status",
    "permit_id", "authorization_id", "execution_intent_id", "request_id",
    "actor", "grant_subject", "grant_role", "audit_id", "audit_status",
    "audit_reason", "consumed_at",
})
SOURCE_IDENTITY = "isolated-iam-target:readonly-mtls"
SCHEMA = "isolated-iam-target-committed-ack/v1"


class UnknownEffect(ValueError):
    pass


def canonical(payload: dict) -> bytes:
    if type(payload) is not dict or set(payload) != FIELDS:
        raise ValueError("IAM2379_ACK_FIELDS_INVALID")
    if any(type(value) is not str or not value for key, value in payload.items()
           if key not in {"audit_id", "audit_status"}):
        raise ValueError("IAM2379_ACK_VALUE_INVALID")
    if type(payload["audit_id"]) is not int or type(payload["audit_status"]) is not int:
        raise ValueError("IAM2379_ACK_AUDIT_SHAPE_INVALID")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def committed_from_target(db_path: Path, permit_id: str) -> dict:
    """Query exact committed effect from target-owned SQLite, never host data."""
    if type(permit_id) is not str or not REF_PATTERN.fullmatch(permit_id):
        raise ValueError("IAM2379_REFERENCE_INVALID")
    with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
        rows = db.execute(
            "SELECT permit_id, authorization_id, execution_intent_id, request_id, "
            "actor, audit_id, consumed_at FROM permit_consumptions WHERE permit_id=?",
            (permit_id,),
        ).fetchall()
        if len(rows) != 1:
            raise UnknownEffect("IAM2379_TARGET_EFFECT_NOT_CONFIRMED")
        row = rows[0]
        audit = db.execute(
            "SELECT actor,status,reason FROM audit WHERE id=?", (row[5],)
        ).fetchone()
        grants = db.execute("SELECT user_id,role FROM grants").fetchall()
        successes = db.execute("SELECT count(*) FROM audit WHERE status=201").fetchone()[0]
        total_consumptions = db.execute("SELECT count(*) FROM permit_consumptions").fetchone()[0]
    if not (
        total_consumptions == successes == 1
        and grants == [("contractor-001", "admin")]
        and row[4] == "scoped-executor"
        and audit == ("scoped-executor", 201, "committed")
        and all(type(value) is str and value for value in (row[1], row[2], row[3], row[6]))
    ):
        raise UnknownEffect("IAM2379_TARGET_EFFECT_LINEAGE_NOT_CONFIRMED")
    observed = datetime.fromisoformat(row[6])
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise UnknownEffect("IAM2379_TARGET_TIMESTAMP_INVALID")
    payload = {
        "schema": SCHEMA, "source_identity": SOURCE_IDENTITY,
        "external_operation_reference": row[0], "status": "committed",
        "permit_id": row[0], "authorization_id": row[1],
        "execution_intent_id": row[2], "request_id": row[3],
        "actor": row[4], "grant_subject": "contractor-001",
        "grant_role": "admin", "audit_id": row[5],
        "audit_status": audit[1], "audit_reason": audit[2],
        "consumed_at": row[6],
    }
    canonical(payload)
    return payload


def sign_committed(payload: dict, private_pem: Path) -> dict:
    key = load_pem_private_key(private_pem.read_bytes(), password=None)
    if type(key) is not Ed25519PrivateKey:
        raise ValueError("IAM2379_TARGET_SIGNER_TYPE_INVALID")
    return {
        "payload": payload,
        "signature": base64.b64encode(key.sign(canonical(payload))).decode("ascii"),
    }


def generate_disposable_key(private_path: Path, public_path: Path) -> None:
    """Host-only test fixture setup. Host sees key; NOT independent custody."""
    if private_path.exists() or public_path.exists():
        raise ValueError("IAM2379_SIGNER_ALREADY_EXISTS")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    signer = Ed25519PrivateKey.generate()
    key = signer.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub = signer.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    private_fd = os.open(private_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(private_fd, "wb") as f:
        f.write(key)
    public_fd = os.open(public_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    with os.fdopen(public_fd, "wb") as f:
        f.write(pub)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--private", required=True, type=Path)
    parser.add_argument("--public", required=True, type=Path)
    args = parser.parse_args()
    if not args.generate:
        raise ValueError("IAM2379_ONLY_DISPOSABLE_KEY_GENERATION_SUPPORTED")
    generate_disposable_key(args.private, args.public)
    print(json.dumps({
        "status": "SYNTHETIC_TARGET_ACK_SIGNER_GENERATED",
        "independent_key_custody": False, "production_claim": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
