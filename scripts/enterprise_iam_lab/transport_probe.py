#!/usr/bin/env python3
"""Real Docker-network, TLS and target-response observations; no provider APIs."""
from __future__ import annotations

import errno
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

URL = "https://iam-target:8443/v1/iam/users/contractor-001/roles"
PATH = "/v1/iam/users/contractor-001/roles"
CA = "/run/lab/certs/ca.crt"
CLIENT_CRT = "/run/lab/certs/client.crt"
CLIENT_KEY = "/run/lab/certs/client.key"

EXPECTED = {
    "allow": (201, "committed"),
    "replay": (409, "permit_replayed"),
    "missing-permit": (400, "invalid_mutation"),
    "tamper": (403, "permit_denied"),
    "wrong-signer": (403, "permit_denied"),
    "legacy-v1": (403, "permit_denied"),
    "unscoped": (403, "target_scope_denied"),
}


def report(case: str, *, passed: bool, kind: str, code: int | None = None,
           reason: str | None = None, details: dict | None = None) -> int:
    print(json.dumps({
        "case_id": case,
        "result": "PASS" if passed else "FAIL",
        "observed_failure_kind": kind,
        "observed_http_status": code,
        "observed_reason": reason,
        "target_path": PATH,
        "real_tls_socket": case != "agent-direct",
        "native_veritas_authorization_exercised": False,
        "production_claim": False,
        **(details or {}),
    }, sort_keys=True), flush=True)
    return 0 if passed else 1


def agent_direct() -> int:
    ip = os.environ.get("TARGET_IP", "")
    if not ip:
        return report("agent-direct", passed=False, kind="MISSING_TARGET_IP")
    try:
        with socket.create_connection((ip, 8443), timeout=3):
            return report("agent-direct", passed=False, kind="TCP_REACHABLE")
    except (TimeoutError, OSError) as exc:
        code = getattr(exc, "errno", None)
        blocked = code in {
            errno.ENETUNREACH, errno.EHOSTUNREACH,
            errno.EACCES, errno.EPERM, errno.ETIMEDOUT,
        }
        return report(
            "agent-direct", passed=blocked, kind=type(exc).__name__,
            details={
                "socket_errno": code, "socket_errno_name": errno.errorcode.get(code, "UNKNOWN"),
                "target_ip": ip, "target_port": 8443,
            },
        )


def send_without_reading_ack() -> int:
    """Send one real mTLS POST then discard the HTTP response.

    Socket send completion is *not* proof that a target effect committed.
    The independent post-restart ledger reader must determine that later.
    Do not retry the write or inspect any status/body from the response.
    """
    context = ssl.create_default_context(cafile=CA)
    context.load_cert_chain(CLIENT_CRT, CLIENT_KEY)
    envelope = json.loads(
        (Path("/run/lab/permits") / "valid.json").read_text(encoding="utf-8")
    )
    data = json.dumps(
        {"role": "admin", "permit": envelope}, sort_keys=True
    ).encode("utf-8")
    connection = http.client.HTTPSConnection(
        "iam-target", 8443, context=context, timeout=6
    )
    try:
        connection.request(
            "POST", PATH, body=data, headers={"Content-Type": "application/json"}
        )
    except (OSError, ssl.SSLError, http.client.HTTPException):
        return report(
            "allow-no-ack", passed=False,
            kind="REQUEST_SEND_FAILED_OUTCOME_UNKNOWN",
            details={"request_send_completed": False},
        )
    finally:
        # IMPORTANT: deliberately never call getresponse() or read().
        connection.close()
    return report(
        "allow-no-ack", passed=True,
        kind="HTTP_RESPONSE_NOT_OBSERVED",
        details={
            "request_send_completed": True,
            "observed_http_status": None,
            "acknowledgement_discarded": True,
            "target_effect_claimed_from_transport": False,
        },
    )


def send(case: str) -> int:
    if case not in (*EXPECTED, "no-client-cert"):
        return report(case, passed=False, kind="UNKNOWN_CASE")

    context = ssl.create_default_context(cafile=CA)
    if case != "no-client-cert":
        context.load_cert_chain(CLIENT_CRT, CLIENT_KEY)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))

    if case == "missing-permit":
        body = {"role": "admin"}
    else:
        variant = (
            "legacy-v1" if case == "legacy-v1" else
            "tampered" if case == "tamper" else
            "wrong-signer" if case == "wrong-signer" else "valid"
        )
        envelope = json.loads(
            (Path("/run/lab/permits") / (variant + ".json")).read_text(encoding="utf-8")
        )
        body = {"role": "admin", "permit": envelope}
    raw = json.dumps(body, sort_keys=True).encode("utf-8")
    request = Request(
        URL, data=raw, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with opener.open(request, timeout=6) as response:
            actual = response.status
            reason = json.loads(response.read())["reason"]
    except HTTPError as exc:
        actual = exc.code
        try:
            reason = json.loads(exc.read())["reason"]
        except (KeyError, ValueError, UnicodeError):
            reason = "MALFORMED_TARGET_RESPONSE"
    except (URLError, ssl.SSLError, ConnectionResetError,
            http.client.RemoteDisconnected, BrokenPipeError) as exc:
        root = exc.reason if isinstance(exc, URLError) else exc
        expected_tls_denial = isinstance(
            root, (ssl.SSLError, ConnectionResetError, http.client.RemoteDisconnected)
        )
        return report(
            case, passed=case == "no-client-cert" and expected_tls_denial,
            kind="TLS_CLIENT_CERT_REJECTED" if expected_tls_denial else type(root).__name__,
            details={"exception_class": type(root).__name__},
        )
    if case == "no-client-cert":
        return report(case, passed=False, kind="CERTLESS_HTTP_REACHED", code=actual, reason=reason)
    expected = EXPECTED[case]
    return report(
        case, passed=(actual, reason) == expected,
        kind="TARGET_HTTP_RESPONSE", code=actual, reason=reason,
    )


if __name__ == "__main__":
    case = os.environ.get("CASE", "")
    raise SystemExit(
        agent_direct() if case == "agent-direct" else
        send_without_reading_ack() if case == "allow-no-ack" else
        send(case)
    )
