#!/usr/bin/env python3
"""Real socket probes against the isolated IAM target, with strict outcome checks."""
from __future__ import annotations

import argparse
import errno
import http.client
import json
import os
import socket
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

TARGET = "https://iam-target:8443/v1/iam/users/contractor-001/roles"
PAYLOAD = b'{"role":"admin"}'


def result(case: str, status: str, *, kind: str, http_status: int | None = None, details: dict | None = None) -> int:
    passed = status == "DENIED"
    print(json.dumps({
        "case_id": case,
        "result": "PASS" if passed else "FAIL",
        "observed": status,
        "observed_failure_kind": kind,
        "observed_http_status": http_status,
        "target": "/v1/iam/users/contractor-001/roles",
        "production_claim": False,
        "veritas_authorization_exercised": False,
        **(details or {}),
    }, sort_keys=True), flush=True)
    return 0 if passed else 1


def probe_network(target_ip: str) -> int:
    # IP-level test: DNS failure alone is not evidence of unreachable effect_net.
    try:
        with socket.create_connection((target_ip, 8443), timeout=3):
            return result("DENY_02", "REACHABLE", kind="TCP_CONNECTED")
    except (TimeoutError, OSError) as exc:
        # A refused connection to a non-running target would be a false PASS;
        # the driver first requires a valid mTLS HTTP 403 from the same target.
        code = getattr(exc, "errno", None)
        allowed = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM, errno.ETIMEDOUT}
        return result("DENY_02", "DENIED" if code in allowed else "WRONG_DENIAL", kind=type(exc).__name__, details={"socket_errno": code, "socket_errno_name": errno.errorcode.get(code, "UNKNOWN"), "target_ip": target_ip, "target_port": 8443})


def probe_https(with_cert: bool) -> int:
    context = ssl.create_default_context(cafile="/run/lab/certs/ca.crt")
    if with_cert:
        context.load_cert_chain(
            "/run/lab/certs/client.crt", "/run/lab/certs/client.key"
        )
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    request = Request(
        TARGET, data=PAYLOAD, method="POST",
        headers={"Content-Type": "application/json"},
    )
    case = "DENY_04" if with_cert else "DENY_03"
    try:
        with opener.open(request, timeout=5) as response:
            return result(case, "REACHABLE", kind="HTTP_UNEXPECTED", http_status=response.status)
    except HTTPError as exc:
        if with_cert and exc.code == 403:
            return result(case, "DENIED", kind="TARGET_POLICY_403", http_status=403)
        return result(case, "WRONG_DENIAL", kind="HTTP_ERROR", http_status=exc.code)
    except (URLError, ssl.SSLError, ConnectionResetError, http.client.RemoteDisconnected, BrokenPipeError) as exc:
        if with_cert:
            return result(case, "WRONG_DENIAL", kind=type(exc).__name__)
        root = exc.reason if isinstance(exc, URLError) else exc
        if not isinstance(root, (ssl.SSLError, ConnectionResetError, http.client.RemoteDisconnected, BrokenPipeError)):
            return result(case, "WRONG_DENIAL", kind=type(root).__name__)
        return result(case, "DENIED" if isinstance(root, (ssl.SSLError, http.client.RemoteDisconnected, ConnectionResetError)) else "WRONG_DENIAL", kind="TLS_CLIENT_IDENTITY_REJECTED" if isinstance(root, (ssl.SSLError, http.client.RemoteDisconnected, ConnectionResetError)) else type(root).__name__, details={"tls_exception_type": type(root).__name__, "tls_reason": getattr(root, "reason", None), "tls_errno": getattr(root, "errno", None)})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("network", "tls", "scope"), required=True)
    args = parser.parse_args()
    if args.mode == "network":
        ip = os.environ.get("TARGET_IP", "")
        if not ip:
            raise SystemExit("TARGET_IP required for direct IP network probe")
        return probe_network(ip)
    return probe_https(with_cert=args.mode == "scope")


if __name__ == "__main__":
    sys.exit(main())
