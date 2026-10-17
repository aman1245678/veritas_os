"""#2385 fail-closed import of an externally supplied, pre-signed IAM origin.

DOES NOT generate signer keys, requests, or signatures.
Only verifies an out-of-band public-key fingerprint and the #2383 exact
IAM-specific synthetic-origin shape. This is a new *acceptance interface*,
NOT evidence that Ben or another independent RCC operator has used it.

Inputs are always explicit; never trust a key bundled in the attestation.
The source signature is provenance DATA, not execution authority.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_public_key,
)

from scripts.enterprise_iam_lab import source_bound_iam_origin as origin

HEX = re.compile(r"^[0-9a-f]{64}$")
MAX_ATTESTATION_BYTES = 16384
MAX_PUBLIC_KEY_BYTES = 2048


class ExternalSourceDenied(ValueError):
    """External material was absent, unpinned, stale or invalid."""


def must(ok: bool, code: str) -> None:
    if not ok:
        raise ExternalSourceDenied("IAM2385_" + code)


def key_fingerprint(pem: bytes) -> str:
    """SHA256 of DER SubjectPublicKeyInfo, not variable PEM formatting."""
    must(type(pem) is bytes and 0 < len(pem) <= MAX_PUBLIC_KEY_BYTES,
         "TRUST_KEY_SIZE_INVALID")
    try:
        key = load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        raise ExternalSourceDenied("IAM2385_TRUST_KEY_INVALID") from exc
    must(isinstance(key, Ed25519PublicKey), "TRUST_KEY_NOT_ED25519")
    der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def verify_trust(pem: bytes, expected_sha256: str) -> str:
    must(type(expected_sha256) is str and
         HEX.fullmatch(expected_sha256) is not None,
         "OUT_OF_BAND_PIN_REQUIRED")
    actual = key_fingerprint(pem)
    must(actual == expected_sha256, "OUT_OF_BAND_PIN_MISMATCH")
    return actual


def _read_regular_file(path: Path, limit: int, code: str) -> bytes:
    must(isinstance(path, Path) and path.is_absolute(),
         code + "_ABSOLUTE_PATH_REQUIRED")
    must(not path.is_symlink() and path.is_file(), code + "_MISSING_OR_SYMLINK")
    size = path.stat().st_size
    must(0 < size <= limit, code + "_SIZE_INVALID")
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    must(0 < len(value) <= limit, code + "_READ_SIZE_INVALID")
    return value


def admit(attestation_path: Path, public_key_path: Path, pinned_key_sha256: str,
          *, now: datetime) -> dict:
    """Verify externally supplied bytes, without issuing any authority."""
    must(type(now) is datetime and now.tzinfo is not None,
         "TRUSTED_CLOCK_REQUIRED")
    public_pem = _read_regular_file(public_key_path, MAX_PUBLIC_KEY_BYTES,
                                    "PUBLIC_KEY")
    key_sha = verify_trust(public_pem, pinned_key_sha256)
    raw = _read_regular_file(attestation_path, MAX_ATTESTATION_BYTES,
                             "ATTESTATION")
    try:
        envelope = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
        )
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        raise ExternalSourceDenied("IAM2385_ATTESTATION_JSON_INVALID") from exc
    payload = origin.verify_origin(envelope, public_pem, now=now)
    # Origin and action remain SYNTHETIC. Source repository or operator
    # custody cannot be inferred from a sender-provided filename or a
    # signature accepted against a locally configured pin.
    return {
        "result": "PASS",
        "schema": "iam-2385-external-origin-import-preflight/v1",
        "trust_spki_sha256": key_sha,
        "source_envelope_sha256": hashlib.sha256(origin.canonical(envelope)).hexdigest(),
        "source_payload_sha256": origin.sha(payload),
        "original_request_digest": payload["original_request_digest"],
        "candidate_digest": payload["candidate_digest"],
        "source_nonce_sha256":
            hashlib.sha256(payload["nonce"].encode("ascii")).hexdigest(),
        "input_signer_generated_by_veritas_this_run": False,
        "source_signature_valid": True,
        "pin_verified_out_of_band_configuration": True,
        "no_native_authorization_issued": True,
        "independent_rcc_operator_proven": False,
        "actual_rcc_original_request_proven": False,
        "production_claim": False,
    }


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate JSON field")
        result[k] = v
    return result


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--attestation", required=True, type=Path)
    p.add_argument("--trusted-public", required=True, type=Path)
    p.add_argument("--pinned-spki-sha256", required=True)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    must(not args.output.exists(), "OUTPUT_ALREADY_EXISTS")
    report = admit(args.attestation, args.trusted_public,
                   args.pinned_spki_sha256, now=datetime.now(timezone.utc))
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
