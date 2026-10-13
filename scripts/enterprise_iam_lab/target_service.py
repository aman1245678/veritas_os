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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sqlite3
import ssl
from threading import Lock

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


class Handler(BaseHTTPRequestHandler):
    def respond(self, status: int, reason: str) -> None:
        body = json.dumps({"status": status, "reason": reason}, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        # Still protected by mTLS, but not by role scope.
        self.respond(200 if self.path == "/health" else 404, "health" if self.path == "/health" else "not_found")

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
        # A scoped mTLS credential and an environment toggle do not prove
        # VERITAS authorization. A target-verifiable one-time permit protocol
        # is required before any effect may be enabled.
        record(actor, 503, "veritas_target_permit_gate_not_integrated")
        self.respond(503, "veritas_target_permit_gate_not_integrated")

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
