#!/usr/bin/env python3
"""Disposable scoped read-only reconciliation mTLS probes.

Runs in a separate Docker container with NO SQLite, issuer private key or
bearer Permit mount. The reference is non-authorizing and permits only GET.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE = "https://iam-target:8443/v1/iam/reconciliation/"
CASE = os.getenv("LAB_READONLY_CASE", "")
CA = "/run/lab/certs/ca.crt"
CRT = "/run/lab/certs/client.crt"
KEY = "/run/lab/certs/client.key"
PUB = "/run/lab/refs/target-ack-public.pem"
REFERENCE_FILE = "/run/lab/refs/lookup.json"


def stop(reason: str, **kwargs) -> int:
    print(json.dumps({
        "case_id": CASE, "result": "FAIL", "error": reason,
        "production_claim": False, **kwargs,
    }, sort_keys=True), flush=True)
    return 1


def run() -> int:
    if CASE not in {"valid", "wrong-scope", "missing", "no-certificate"}:
        return stop("IAM2379_PROBE_UNSUPPORTED_CASE")
    source = json.loads(Path(REFERENCE_FILE).read_text(encoding="utf-8"))
    ref = source.get("permit_id")
    if type(ref) is not str or not ref.startswith("iam-permit:v1:sha256:"):
        return stop("IAM2379_LOOKUP_REFERENCE_INVALID")
    if CASE == "missing":
        ref = "iam-permit:v1:sha256:" + "0" * 64
    context = ssl.create_default_context(cafile=CA)
    if CASE != "no-certificate":
        context.load_cert_chain(CRT, KEY)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    request = Request(BASE + quote(ref, safe=""), method="GET")
    status = None
    body = None
    try:
        with opener.open(request, timeout=8) as response:
            status = response.status
            raw = response.read(4096)
            body = json.loads(raw)
    except HTTPError as exc:
        status = exc.code
        body = json.loads(exc.read(2048))
    except (URLError, ssl.SSLError, ConnectionResetError, BrokenPipeError) as exc:
        if CASE == "no-certificate":
            print(json.dumps({
                "case_id": CASE, "result": "PASS", "observed_http_status": None,
                "expected_tls_denial_observed": True,
                "production_claim": False,
            }, sort_keys=True), flush=True)
            return 0
        return stop("IAM2379_MTLS_GET_ERROR", exception=type(exc).__name__)

    if CASE == "valid":
        if status != 200 or type(body) is not dict or set(body) != {"payload", "signature"}:
            return stop("IAM2379_EXPECTED_SIGNED_COMMIT_NOT_RETURNED", status=status)
        # Both the independent reader container AND host later verify the
        # target-owned signature; neither has access to target's private key.
        from cryptography.exceptions import InvalidSignature
        from target_readonly_receipt import canonical as ack_canonical
        key = load_pem_public_key(Path(PUB).read_bytes())
        if type(key) is not Ed25519PublicKey:
            return stop("IAM2379_PUBLIC_KEY_INVALID")
        try:
            key.verify(base64.b64decode(body["signature"], validate=True),
                       ack_canonical(body["payload"]))
        except (InvalidSignature, ValueError, TypeError):
            return stop("IAM2379_TARGET_SIGNATURE_INVALID")
        if (body["payload"].get("permit_id") != ref
                or body["payload"].get("status") != "committed"):
            return stop("IAM2379_SIGNED_RECEIPT_MISMATCH")
        print(json.dumps({
            "case_id": CASE, "result": "PASS",
            "status": 200, "signed_ack": body,
            "reader_has_target_sqlite_mount": False,
            "reader_has_target_signer_private_key": False,
            "target_http_response_authenticated_via_mtls": True,
            "target_receipt_signature_verified": True,
            "production_claim": False,
        }, sort_keys=True), flush=True)
        return 0
    expected = (403, "reconciliation_reader_not_authorized") if CASE == "wrong-scope" else (404, "effect_not_confirmed")
    if status != expected[0] or type(body) is not dict or body.get("reason") != expected[1]:
        return stop("IAM2379_READ_DENIAL_NOT_ENFORCED", status=status)
    print(json.dumps({
        "case_id": CASE, "result": "PASS",
        "observed_http_status": status, "reason": expected[1],
        "signed_no_effect_proof_generated": False,
        "production_claim": False,
    }, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
