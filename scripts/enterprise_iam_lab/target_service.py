#!/usr/bin/env python3
"""Disposable IAM effect sink for isolated external-enforcement probes.

NOT VERITAS authorization, NOT an enterprise IdP, NOT production-ready.
The service independently requires a trusted client certificate and a
locally pinned synthetic role scope before any effect can be committed.
Mutations default OFF until real VERITAS execution integration exists.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sqlite3
import ssl
from threading import Lock
from urllib.parse import quote, unquote

TARGET_PATH = "/v1/iam/users/contractor-001/roles"
TARGET_USER = "contractor-001"
MUTATION_BODY = {"role": "admin"}
SCOPE_GRANTS = {
    "scoped-executor": frozenset({"saas:grant_admin"}),
    "unscoped-probe": frozenset(),
}
DB_PATH = Path(os.environ.get("LAB_DB_PATH", "/run/lab/state/iam.sqlite3"))
DB_LOCK = Lock()


def client_cn(peer: dict) -> str:
    for rdns in peer.get("subject", ()):
        for key, value in rdns:
            if key == "commonName":
                return str(value)
    return ""


def scope_allows(actor: str) -> bool:
    return "saas:grant_admin" in SCOPE_GRANTS.get(actor, frozenset())


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        db.execute("CREATE TABLE IF NOT EXISTS grants (user_id TEXT PRIMARY KEY, role TEXT NOT NULL)")
        db.execute(
            "CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " actor TEXT NOT NULL, status INTEGER NOT NULL, reason TEXT NOT NULL)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS permit_consumptions ("
            " permit_id TEXT PRIMARY KEY,"
            " authorization_id TEXT UNIQUE NOT NULL,"
            " execution_intent_id TEXT NOT NULL,"
            " request_id TEXT NOT NULL,"
            " actor TEXT NOT NULL,"
            " audit_id INTEGER UNIQUE NOT NULL,"
            " consumed_at TEXT NOT NULL)"
        )


def record(actor: str, status: int, reason: str, *, grant: bool = False) -> None:
    with DB_LOCK, sqlite3.connect(DB_PATH) as db:
        if grant:
            db.execute(
                "INSERT INTO grants(user_id, role) VALUES(?, ?)",
                (TARGET_USER, "admin"),
            )
        db.execute(
            "INSERT INTO audit(actor, status, reason) VALUES(?, ?, ?)",
            (actor, status, reason),
        )


def commit_verified_permit(actor: str, payload: dict[str, str], now: datetime) -> tuple[int, str]:
    """Atomic, target-owned commit. Caller MUST verify the permit first.

    A duplicate permit or authorization cannot commit a second effect, even
    with concurrent connections or multiple processes sharing SQLite.
    """
    with DB_LOCK, sqlite3.connect(DB_PATH, timeout=10) as db:
        db.execute("BEGIN IMMEDIATE")
        replay = db.execute(
            "SELECT 1 FROM permit_consumptions WHERE permit_id = ? OR authorization_id = ?",
            (payload["permit_id"], payload["authorization_id"]),
        ).fetchone()
        if replay is not None:
            db.rollback()
            return 409, "permit_replayed"
        try:
            db.execute(
                "INSERT INTO grants(user_id, role) VALUES(?, ?)",
                (TARGET_USER, "admin"),
            )
        except sqlite3.IntegrityError:
            db.rollback()
            return 409, "duplicate_grant"
        try:
            receipt = db.execute(
                "INSERT INTO audit(actor, status, reason) VALUES(?, ?, ?)",
                (actor, 201, "committed"),
            )
            db.execute(
                "INSERT INTO permit_consumptions("
                "permit_id, authorization_id, execution_intent_id, request_id,"
                "actor, audit_id, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (payload["permit_id"], payload["authorization_id"],
                 payload["execution_intent_id"], payload["request_id"],
                 actor, receipt.lastrowid, now.isoformat()),
            )
            db.commit()
            return 201, "committed"
        except sqlite3.Error:
            db.rollback()
            raise


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


class Handler(BaseHTTPRequestHandler):
    def respond(self, status: int, reason: str) -> None:
        body = json.dumps({"status": status, "reason": reason}, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        # /health remains unchanged for all existing isolated IAM tests.
        if self.path == "/health":
            self.respond(200, "health")
            return
        if os.getenv("LAB_TEST_READONLY_ACK", "0") != "1":
            self.respond(404, "not_found")
            return
        from target_readonly_receipt import (
            PREFIX, UnknownEffect, committed_from_target, sign_committed,
        )
        if not self.path.startswith(PREFIX):
            self.respond(404, "not_found")
            return
        # The read-only credential is distinct from scoped-executor and
        # unscoped-probe, even though all may have CA-trusted client certs.
        actor = client_cn(self.connection.getpeercert() or {})
        if actor != "reconciliation-reader":
            self.respond(403, "reconciliation_reader_not_authorized")
            return
        suffix = self.path[len(PREFIX):]
        ref = unquote(suffix, errors="strict")
        if quote(ref, safe="") != suffix:
            self.respond(400, "reconciliation_reference_not_canonical")
            return
        try:
            payload = committed_from_target(DB_PATH, ref)
        except ValueError:
            # No signed NO_EFFECT response is ever issued from absence.
            self.respond(404, "effect_not_confirmed")
            return
        except (sqlite3.Error, OSError):
            self.respond(503, "reconciliation_target_unavailable")
            return
        try:
            envelope = sign_committed(
                payload, Path(os.environ["LAB_TARGET_ACK_SIGNER_PEM"]),
            )
        except (ValueError, TypeError, OSError, KeyError):
            self.respond(503, "reconciliation_signer_unavailable")
            return
        body = json.dumps(envelope, sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        actor = client_cn(self.connection.getpeercert() or {})
        if not scope_allows(actor):
            record(actor, 403, "target_scope_denied")
            self.respond(403, "target_scope_denied")
            return
        # This must remain OFF until the VERITAS consent/consume path is wired.
        if os.getenv("LAB_ALLOW_MUTATIONS", "0") != "1":
            record(actor, 503, "governed_executor_not_integrated")
            self.respond(503, "governed_executor_not_integrated")
            return
        # Test-only opt-in. A scoped certificate + mutation toggle alone
        # are NEVER sufficient; the trusted verification key stays target-side.
        if os.getenv("LAB_TEST_PERMIT_GATE", "0") != "1":
            record(actor, 503, "veritas_target_permit_gate_not_integrated")
            self.respond(503, "veritas_target_permit_gate_not_integrated")
            return
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from signed_permit import PermitRejected, verify_permit

            key_path = os.environ["LAB_PERMIT_VERIFIER_PEM"]
            verifier = load_pem_public_key(Path(key_path).read_bytes())
            if not isinstance(verifier, Ed25519PublicKey):
                raise ValueError("non-Ed25519 verifier")
        except (ImportError, KeyError, OSError, ValueError, TypeError):
            record(actor, 503, "permit_verifier_unavailable")
            self.respond(503, "permit_verifier_unavailable")
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if (self.path != TARGET_PATH or
                    self.headers.get("Content-Type") != "application/json" or
                    not 1 <= length <= 8192):
                raise ValueError("invalid request metadata")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("incomplete request")
            body = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
            if (not isinstance(body, dict) or set(body) != {"role", "permit"} or
                    body["role"] != MUTATION_BODY["role"] or
                    not isinstance(body["permit"], dict)):
                raise ValueError("invalid effect envelope")
        except (ValueError, UnicodeError, TypeError):
            record(actor, 400, "invalid_mutation")
            self.respond(400, "invalid_mutation")
            return
        try:
            now = datetime.now(timezone.utc)
            permit = verify_permit(body["permit"], verifier, now)
            if permit["issuer"] != os.getenv("LAB_PERMIT_ISSUER", "isolated-iam-test-issuer"):
                raise PermitRejected("untrusted_permit_issuer")
        except (PermitRejected, KeyError, TypeError):
            record(actor, 403, "permit_denied")
            self.respond(403, "permit_denied")
            return
        try:
            status, reason = commit_verified_permit(actor, permit, now)
        except sqlite3.Error:
            # A failed transaction never becomes an ALLOW.
            self.respond(503, "target_commit_unavailable")
            return
        if status != 201:
            record(actor, status, reason)
        self.respond(status, reason)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def main() -> None:
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/run/lab/certs/server.crt", "/run/lab/certs/server.key")
    context.load_verify_locations(cafile="/run/lab/certs/ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
