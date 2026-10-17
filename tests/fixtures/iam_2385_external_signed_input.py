"""CI-only separate-process signed synthetic IAM fixture for external import.

The fixture signer is NOT an independently operated RCC signer; it runs in
the same ephemeral GitHub runner trust domain and uses controlled inputs.
Never export private key material or user payload in uploaded artifacts.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts import run_decision_to_external_bind_poc as poc
from scripts.enterprise_iam_lab import source_bound_iam_origin as origin
from scripts.enterprise_iam_lab.external_rcc_source_import import key_fingerprint
from scripts.enterprise_iam_lab.signed_permit import EXPECTED


def write_separate_process_test_source(folder: Path) -> str:
    assert folder.is_absolute() and folder.is_dir() and not folder.is_symlink()
    assert not any(folder.iterdir()), "dedicated synthetic source directory must be empty"
    # Mirror the documented #2383 selected synthetic /v1/decide candidate
    # projection. This is NOT sourced from Ben or the RCC benchmark.
    selected = poc._candidate()
    selected = replace(
        selected,
        evidence_refs=["synthetic:local-review-input"],
        required_human_approval=True,
        intended_action=origin.TARGET["intended_action"],
        target_system=origin.TARGET["target_system"],
        target_resource=origin.TARGET["target_resource"],
        required_authority=list(origin.TARGET["required_authority"]),
    )
    candidate = origin.project(selected.to_dict())
    request = {
        "source": "rcc-revas-controlled-synthetic-iam-request",
        "actor_identity": candidate["actor_identity"],
        "target_system": candidate["target_system"],
        "target_resource": candidate["target_resource"],
        "intended_action": candidate["intended_action"],
        "scope": EXPECTED["scope"],
        "role": EXPECTED["role"],
        "user_request": "Grant admin to contractor-001 in isolated synthetic IAM.",
    }
    clock = datetime.now(timezone.utc)
    payload = {
        "schema": origin.SCHEMA,
        "original_request": request,
        "original_request_digest": origin.sha(request),
        "candidate": candidate,
        "candidate_digest": origin.sha(candidate),
        "issued_at": clock.isoformat(),
        "expires_at": (clock + timedelta(seconds=120)).isoformat(),
        "nonce": secrets.token_hex(32),
        "production_claim": False,
    }
    origin.validate_source(payload, now=clock)
    signer = Ed25519PrivateKey.generate()
    pem = signer.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo,
    )
    envelope = {
        "payload": payload,
        "signature": base64.b64encode(
            signer.sign(origin.canonical(payload)),
        ).decode("ascii"),
    }
    (folder / "external-signed.json").write_text(
        json.dumps(envelope, sort_keys=True, indent=2) + "\n", encoding="utf-8",
    )
    (folder / "external-public.pem").write_bytes(pem)
    (folder / "external-signed.json").chmod(0o600)
    (folder / "external-public.pem").chmod(0o600)
    # Only fingerprint is printed. Private key is never serialized.
    return key_fingerprint(pem)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    print(write_separate_process_test_source(args.out_dir))


if __name__ == "__main__":
    main()
