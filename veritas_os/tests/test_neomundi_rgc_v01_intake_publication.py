"""Fail-closed publication tests for the standalone historical RGC v0.1 CLI.

Only synthetic test data is used. The standalone CLI must not expose
a successful verification report until all required artifacts exist.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts import run_neomundi_rgc_v01_complete_intake as cli


def _complete_outputs() -> dict[str, dict[str, Any]]:
    return {
        "verification_report": {"status": "verified"},
        "verified_external_measurement_evidence": {"evidence": {"id": "fake"}},
        "evidence_manifest": {"status": "complete"},
    }


def test_publish_complete_set_only_after_staging(tmp_path: Path) -> None:
    output_dir = tmp_path / "result"
    cli._publish_outputs(output_dir, _complete_outputs())

    assert sorted(x.name for x in output_dir.iterdir()) == [
        "evidence_manifest.json",
        "verification_report.json",
        "verified_external_measurement_evidence.json",
    ]
    assert json.loads((output_dir / "verification_report.json").read_text()) == {
        "status": "verified"
    }
    assert not list(tmp_path.glob(".result.pending-*"))


@pytest.mark.parametrize("failed_file", [
    "verification_report.json",
    "verified_external_measurement_evidence.json",
    "evidence_manifest.json",
])
def test_write_failure_never_publishes_partial_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_file: str
) -> None:
    actual_write = cli._write_json

    def failing_write(path: Path, payload: dict[str, Any]) -> None:
        if path.name == failed_file:
            raise OSError("synthetic staged-write failure")
        actual_write(path, payload)

    monkeypatch.setattr(cli, "_write_json", failing_write)
    output_dir = tmp_path / "result"

    with pytest.raises(OSError, match="synthetic staged-write failure"):
        cli._publish_outputs(output_dir, _complete_outputs())

    assert not output_dir.exists()
    assert not list(tmp_path.glob(".result.pending-*"))


def test_rename_failure_does_not_expose_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_rename(_source: Path, _target: Path) -> None:
        raise OSError("synthetic atomic-rename failure")

    monkeypatch.setattr(cli.os, "rename", failing_rename)

    with pytest.raises(OSError, match="synthetic atomic-rename failure"):
        cli._publish_outputs(tmp_path / "result", _complete_outputs())

    assert not (tmp_path / "result").exists()
    assert not list(tmp_path.glob(".result.pending-*"))


def test_existing_output_rejected_without_overwrite(tmp_path: Path) -> None:
    result = tmp_path / "result"
    result.mkdir()
    (result / "previous.json").write_text('{"status":"verified"}')

    with pytest.raises(ValueError, match="neomundi_v01_intake_output_dir_exists"):
        cli._publish_outputs(result, _complete_outputs())

    assert (result / "previous.json").exists()
    assert not list(tmp_path.glob(".result.pending-*"))


def _fake_input_paths(tmp_path: Path) -> list[str]:
    args: list[str] = []
    for flag, filename in [
        ("--artifact", "artifact.json"),
        ("--jwks", "jwks.json"),
        ("--trusted-key-provenance", "provenance.json"),
        ("--intake-manifest", "manifest.json"),
    ]:
        path = tmp_path / filename
        path.write_text("{}\n")
        args += [flag, str(path)]
    return args + [
        "--replay-state-dir", str(tmp_path / "replay"),
        "--output-dir", str(tmp_path / "result"),
        "--accepted-measurement-version", "3.3.0",
        "--max-age-seconds", "3600",
        "--allow-no-expiry",
    ]


def test_cli_returns_failure_when_evidence_publication_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cli, "verify_neomundi_v01_complete_packet", lambda **_kw: _complete_outputs()
    )
    original_write = cli._write_json

    def failed_manifest_write(path: Path, payload: dict[str, Any]) -> None:
        if path.name == "evidence_manifest.json":
            raise OSError("synthetic storage failure")
        original_write(path, payload)

    monkeypatch.setattr(cli, "_write_json", failed_manifest_write)

    assert cli.main(_fake_input_paths(tmp_path)) == 2
    assert not (tmp_path / "result").exists()


def test_failed_verification_publishes_failure_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from veritas_os.governance.neomundi_real_observation_poc import (
        NeoMundiRealObservationPocError,
    )

    def verification_failure(**_kw: Any) -> dict[str, dict[str, Any]]:
        raise NeoMundiRealObservationPocError(
            "synthetic_reject",
            report={"status": "failed", "stage": "provider_verification"},
        )

    monkeypatch.setattr(cli, "verify_neomundi_v01_complete_packet", verification_failure)
    assert cli.main(_fake_input_paths(tmp_path)) == 2

    result = tmp_path / "result"
    assert sorted(p.name for p in result.iterdir()) == ["verification_report.json"]
    assert json.loads((result / "verification_report.json").read_text())[
        "status"
    ] == "failed"
