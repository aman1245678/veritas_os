"""Execute publication refusal paths with controlled scanner/copy processes.

Real OCI scanning/copy compatibility belongs to Image Publication Gate PR CI.
These tests invoke the production shell script, never a registry or provider.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/publish_scanned_oci.sh"

STUB = r'''
import hashlib, json, os, pathlib, sys
args = sys.argv[1:]
log = pathlib.Path(os.environ["CALL_LOG"])
with log.open("a") as f:
    f.write(json.dumps([pathlib.Path(sys.argv[0]).name, *args]) + "\n")
if pathlib.Path(sys.argv[0]).name == "trivy":
    if os.environ.get("MUTATE_LAYOUT") == "1":
        (pathlib.Path(args[args.index("--input") + 1]) / "blob").write_bytes(b"changed")
    sys.exit(int(os.environ.get("SCAN_EXIT", "0")))
if args[0] == "inspect":
    sys.stdout.write('{"schemaVersion":2}')
    sys.exit(int(os.environ.get("INSPECT_EXIT", "0")))
if args[0] == "copy":
    if os.environ.get("COPY_EXIT"):
        sys.exit(int(os.environ["COPY_EXIT"]))
    digest = "sha256:" + hashlib.sha256(b'{"schemaVersion":2}').hexdigest()
    if os.environ.get("WRONG_DIGEST") == "1":
        digest = "sha256:wrong"
    pathlib.Path(args[args.index("--digestfile") + 1]).write_text(digest)
'''


def run_gate(tmp_path, **settings):
    tools = tmp_path / "bin"
    tools.mkdir()
    for name in ("trivy", "skopeo"):
        path = tools / name
        path.write_text(f"#!{sys.executable}\n" + STUB)
        path.chmod(0o755)
    layout = tmp_path / "image"
    layout.mkdir()
    (layout / "blob").write_bytes(b"synthetic layout")
    if settings.get("SYMLINK_LAYOUT") == "1":
        (layout / "link").symlink_to(tmp_path / "outside")
    log = tmp_path / "calls.jsonl"
    env = {**os.environ, "PATH": f"{tools}:{os.defpath}", "CALL_LOG": str(log), **settings}
    result = subprocess.run(
        ["bash", str(SCRIPT), str(layout), str(tmp_path / "reports"),
         "docker://synthetic.example/image:sha", "docker://synthetic.example/image:latest"],
        env=env, capture_output=True, text=True, check=False,
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    copies = [call for call in calls if call[:2] == ["skopeo", "copy"]]
    return result, calls, copies


@pytest.mark.parametrize("exit_code", ["1", "2", "127"])
def test_vulnerability_or_scanner_error_never_copies(tmp_path, exit_code):
    result, calls, copies = run_gate(tmp_path, SCAN_EXIT=exit_code)
    assert result.returncode == int(exit_code)
    assert any(call[0] == "trivy" for call in calls)
    assert copies == []


def test_success_copies_exact_scanned_layout_with_attestations(tmp_path):
    result, calls, copies = run_gate(tmp_path)
    assert result.returncode == 0, result.stderr
    assert len(copies) == 2
    scanner = next(call for call in calls if call[0] == "trivy")
    assert scanner[scanner.index("--exit-code") + 1] == "1"
    assert scanner[scanner.index("--severity") + 1] == "CRITICAL"
    source = scanner[scanner.index("--input") + 1]
    for copy in copies:
        assert "--all" in copy and "--preserve-digests" in copy
        assert copy[-2] == f"oci:{source}"
        assert calls.index(copy) > calls.index(scanner)
    assert copies[0][-1].endswith(":sha")
    assert copies[1][-1].endswith(":latest")


def test_layout_mutation_after_scan_never_copies(tmp_path):
    result, _, copies = run_gate(tmp_path, MUTATE_LAYOUT="1")
    assert result.returncode != 0
    assert copies == []


def test_manifest_read_failure_never_scans_or_copies(tmp_path):
    result, calls, copies = run_gate(tmp_path, INSPECT_EXIT="2")
    assert result.returncode == 2
    assert not any(call[0] == "trivy" for call in calls)
    assert copies == []


@pytest.mark.parametrize("settings", [{"COPY_EXIT": "2"}, {"WRONG_DIGEST": "1"}])
def test_failed_sha_copy_or_digest_mismatch_never_updates_latest(tmp_path, settings):
    result, _, copies = run_gate(tmp_path, **settings)
    assert result.returncode != 0
    assert len(copies) == 1
    assert copies[0][-1].endswith(":sha")


def test_workflows_keep_unpublished_build_and_pr_without_write_permissions():
    production = yaml.safe_load((ROOT / ".github/workflows/publish-ghcr.yml").read_text())
    verification = yaml.safe_load((ROOT / ".github/workflows/image-publication-pr.yml").read_text())
    assert "pull_request" not in production.get("on", production.get(True))
    assert verification["permissions"] == {"contents": "read"}
    for workflow in (production, verification):
        steps = next(iter(workflow["jobs"].values()))["steps"]
        builds = [s for s in steps if s.get("uses", "").startswith("docker/build-push-action@")]
        assert len(builds) == 1
        config = builds[0]["with"]
        assert config["push"] is False
        assert config["provenance"] is True and config["sbom"] is True
        assert config["platforms"] == "linux/amd64"
        assert config["outputs"].startswith("type=oci,")
        assert config["outputs"].endswith(",tar=false")
        assert any("bash scripts/ci/publish_scanned_oci.sh" in s.get("run", "") for s in steps)
        assert not any(s.get("continue-on-error") for s in steps)
    pr_text = (ROOT / ".github/workflows/image-publication-pr.yml").read_text()
    assert "docker/login-action" not in pr_text
    assert "docker://" not in pr_text


def test_layout_symlink_never_scans_or_copies(tmp_path):
    result, calls, copies = run_gate(tmp_path, SYMLINK_LAYOUT="1")
    assert result.returncode != 0
    assert "symlinks" in result.stderr
    assert not any(call[0] == "trivy" for call in calls)
    assert copies == []


@pytest.mark.parametrize("workflow_name", ["publish-ghcr.yml", "image-publication-pr.yml"])
def test_advisory_and_publication_scans_share_the_same_cache(workflow_name):
    """The gate must reuse the DB cache populated by the advisory action."""
    workflow = yaml.safe_load((ROOT / ".github/workflows" / workflow_name).read_text())
    steps = next(iter(workflow["jobs"].values()))["steps"]
    advisory = next(s for s in steps if s.get("uses", "").startswith("aquasecurity/trivy-action@"))
    gate = next(s for s in steps if "bash scripts/ci/publish_scanned_oci.sh" in s.get("run", ""))
    assert advisory["with"].get("cache-dir")
    assert gate.get("env", {}).get("TRIVY_CACHE_DIR") == advisory["with"]["cache-dir"]
    assert "TRIVY_SKIP_DB_UPDATE" not in gate.get("env", {})
