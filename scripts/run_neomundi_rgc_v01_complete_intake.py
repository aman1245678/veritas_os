#!/usr/bin/env python3
"""Verify one explicit NeoMundi RGC v0.1.0 COMPLETE packet (not v0.2)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from veritas_os.governance.neomundi_real_observation_poc import (
    NeoMundiRealObservationPocError,
)
from veritas_os.governance.neomundi_rgc_v01_complete_intake import (
    verify_neomundi_v01_complete_packet,
)


def _load_json(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()

    def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("neomundi_v01_intake_duplicate_json_key")
            result[key] = value
        return result

    def _no_nonfinite(_value: str) -> Any:
        raise ValueError("neomundi_v01_intake_nonfinite_json_value")

    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_no_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("neomundi_v01_intake_json_invalid") from exc
    if not isinstance(parsed, dict):
        raise ValueError("neomundi_v01_intake_json_object_required")
    return parsed, hashlib.sha256(raw).hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    data = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()

def _publish_outputs(
    output_dir: Path, outputs: dict[str, dict[str, Any]]
) -> None:
    """Stage every report before atomically making the result directory visible.

    This prevents normal write/rename failures from leaving an externally
    visible success report without its complete evidence set. A consumed
    replay marker is intentionally never reversed after a publication failure.
    """
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("neomundi_v01_intake_output_dir_exists")
    stage = Path(
        tempfile.mkdtemp(
            prefix=f".{output_dir.name}.pending-",
            dir=output_dir.parent,
        )
    )
    try:
        for name, payload in outputs.items():
            _write_json(stage / f"{name}.json", payload)
        if output_dir.exists() or output_dir.is_symlink():
            raise ValueError("neomundi_v01_intake_output_dir_exists")
        # Stage and destination share the same parent / filesystem.
        os.rename(stage, output_dir)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def _report_failed_intake(
    output_dir: Path, report: dict[str, Any]
) -> None:
    """Best-effort atomic publication of a failure-only report."""
    try:
        _publish_outputs(output_dir, {"verification_report": report})
    except (OSError, ValueError) as exc:
        print(
            f"NeoMundi v0.1 intake could not publish failure report: {exc}",
            file=sys.stderr,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--jwks", required=True, type=Path)
    parser.add_argument("--trusted-key-provenance", required=True, type=Path)
    parser.add_argument("--intake-manifest", required=True, type=Path)
    parser.add_argument("--replay-state-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--accepted-measurement-version",
        required=True,
        help="Exactly one operator-approved measurement version, e.g. 3.3.0",
    )
    parser.add_argument(
        "--max-age-seconds", required=True, type=int, help="Freshness policy in seconds"
    )
    parser.add_argument("--max-future-skew-seconds", type=int, default=60)
    parser.add_argument(
        "--allow-no-expiry",
        action="store_true",
        help="Explicit no-expiry exception; mandatory to accept an RGC without expires_at",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    # An output path must be new, never reused from a previous attempt.
    # Do not consume the replay key if this precondition already fails.
    try:
        if args.output_dir.exists() or args.output_dir.is_symlink():
            raise ValueError("neomundi_v01_intake_output_dir_exists")
        args.output_dir.parent.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError) as exc:
        print(f"NeoMundi v0.1 intake output location rejected: {exc}", file=sys.stderr)
        return 2

    try:
        artifact, artifact_hash = _load_json(args.artifact)
        jwks, jwks_hash = _load_json(args.jwks)
        receipt, receipt_hash = _load_json(args.trusted_key_provenance)
        manifest, manifest_hash = _load_json(args.intake_manifest)
        outputs = verify_neomundi_v01_complete_packet(
            artifact=artifact,
            artifact_file_sha256=artifact_hash,
            trusted_jwks=jwks,
            trusted_jwks_file_sha256=jwks_hash,
            provenance_receipt=receipt,
            provenance_receipt_file_sha256=receipt_hash,
            intake_manifest=manifest,
            intake_manifest_file_sha256=manifest_hash,
            replay_state_dir=args.replay_state_dir,
            accepted_measurement_version=args.accepted_measurement_version,
            max_age_seconds=args.max_age_seconds,
            max_future_skew_seconds=args.max_future_skew_seconds,
            allow_no_expiry=args.allow_no_expiry,
        )
    except NeoMundiRealObservationPocError as exc:
        _report_failed_intake(args.output_dir, exc.report)
        print(f"NeoMundi v0.1 intake rejected: {exc.reason}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        report = {
            "status": "failed",
            "stage": "input",
            "reason": str(exc),
            "claim_boundary": {
                "measurement_only": True,
                "authority_created": False,
                "governance_decision_created": False,
                "external_effect_performed": False,
            },
        }
        _report_failed_intake(args.output_dir, report)
        print(f"NeoMundi v0.1 intake failed: {exc}", file=sys.stderr)
        return 2

    try:
        _publish_outputs(
            args.output_dir,
            {
                "verification_report": outputs["verification_report"],
                "verified_external_measurement_evidence": outputs[
                    "verified_external_measurement_evidence"
                ],
                "evidence_manifest": outputs["evidence_manifest"],
            },
        )
    except (OSError, ValueError) as exc:
        print(
            "NeoMundi v0.1 intake could not publish the complete evidence "
            f"packet (replay state remains consumed): {exc}",
            file=sys.stderr,
        )
        return 2
    print("NeoMundi RGC v0.1 COMPLETE-only packet verified as measurement evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
