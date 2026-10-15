#!/usr/bin/env python3
"""Create synthetic TRANSPORT-ONLY signed permits outside Docker.

This file deliberately DOES NOT invoke VERITAS native authorization.
Only used to prove real mTLS and target-owned effect enforcement. Never
provide this signing helper or its ephemeral private key to an agent.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from signed_permit import EXPECTED, sign_permit


def issue(*, trust_directory: Path, permit_directory: Path) -> dict[str, str]:
    if not trust_directory.is_dir() or not permit_directory.is_dir():
        raise ValueError("disposable output folders must exist")
    private_key = Ed25519PrivateKey.generate()
    public = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    (trust_directory / "permit-public.pem").write_bytes(public)

    now = datetime.now(timezone.utc)
    nonce = secrets.token_hex(16)
    payload = {
        **EXPECTED,
        "issuer": "isolated-iam-test-issuer",
        "permit_id": "transport-only:permit:" + nonce,
        "authorization_id": "transport-only:authorization:" + nonce,
        "execution_intent_id": "transport-only:intent:" + nonce,
        "request_id": "transport-only:request:" + nonce,
        "not_before": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=15)).isoformat(),
    }
    valid = sign_permit(payload, private_key)
    tampered = {
        "payload": {**valid["payload"], "scope": "saas:read"},
        "signature": valid["signature"],
    }
    invalid_signature = sign_permit(payload, Ed25519PrivateKey.generate())
    for filename, envelope in (
        ("valid.json", valid), ("tampered.json", tampered),
        ("wrong-signer.json", invalid_signature),
    ):
        (permit_directory / filename).write_text(
            json.dumps(envelope, sort_keys=True), encoding="utf-8"
        )
    # No private signing key written anywhere on disk.
    return {
        "fixture": "SYNTHETIC_TRANSPORT_ONLY_NOT_NATIVE_VERITAS",
        "issuer_private_key_exported": "false",
        "permit_count": "1",
        "negative_permits": "2",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trust-directory", type=Path, required=True)
    parser.add_argument("--permit-directory", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(issue(
        trust_directory=arguments.trust_directory,
        permit_directory=arguments.permit_directory,
    ), sort_keys=True))


if __name__ == "__main__":
    main()
