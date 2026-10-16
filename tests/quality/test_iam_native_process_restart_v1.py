"""#2378: malformed restart and spoofed SIGKILL evidence fail-closed tests.

Only synthetic Docker-inspect fixtures are used here. The dedicated workflow
performs the real SIGKILL and Docker process stop/start on a disposable runner.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from scripts.enterprise_iam_lab.native_process_restart_probe import (
    CHECKPOINT_SCHEMA, _read_json, _write_once_synced, validate_inspect,
)


def synthetic_inspects() -> tuple[dict, dict]:
    before = {
        "Id": "c" * 64,
        "State": {
            "Running": True, "Pid": 1001,
            "StartedAt": "2026-10-16T00:00:00.000000001Z",
            "Health": {"Status": "healthy"},
        },
        "Mounts": [
            {"Destination": "/run/lab/state", "Source": "/tmp/isolated-target-state", "RW": True}
        ],
        "NetworkSettings": {
            "Networks": {"project_effect_net": {"IPAddress": "172.27.0.4"}}
        },
        "HostConfig": {"PortBindings": {}},
    }
    after = deepcopy(before)
    after["State"]["Pid"] = 1002
    after["State"]["StartedAt"] = "2026-10-16T00:00:05.000000001Z"
    return before, after


def test_real_docker_inspect_contract_minimum():
    before, after = synthetic_inspects()
    verified = validate_inspect(before, after)
    assert verified["same_docker_container_restarted"] is True
    assert verified["target_process_pid_changed"] is True
    assert verified["same_target_owned_sqlite_mount"] is True
    assert verified["target_has_no_published_port"] is True


@pytest.mark.parametrize(
    "tamper",
    (
        "same_pid", "same_start", "different_container", "target_stopped",
        "unhealthy_target", "lost_state_mount", "readonly_state_mount",
        "changed_state_mount", "added_network", "published_port",
        "replaced_network", "missing_inspect",
    ),
)
def test_forged_or_insufficient_process_restart_rejected(tamper):
    before, after = synthetic_inspects()
    if tamper == "same_pid":
        after["State"]["Pid"] = before["State"]["Pid"]
    elif tamper == "same_start":
        after["State"]["StartedAt"] = before["State"]["StartedAt"]
    elif tamper == "different_container":
        after["Id"] = "d" * 64
    elif tamper == "target_stopped":
        after["State"]["Running"] = False
    elif tamper == "unhealthy_target":
        after["State"]["Health"]["Status"] = "starting"
    elif tamper == "lost_state_mount":
        after["Mounts"] = []
    elif tamper == "readonly_state_mount":
        after["Mounts"][0]["RW"] = False
    elif tamper == "changed_state_mount":
        after["Mounts"][0]["Source"] = "/tmp/substituted"
    elif tamper == "added_network":
        after["NetworkSettings"]["Networks"]["attacker_net"] = {"IPAddress": "1.2.3.4"}
    elif tamper == "published_port":
        after["HostConfig"]["PortBindings"] = {"8443/tcp": [{"HostPort": "8443"}]}
    elif tamper == "replaced_network":
        after["NetworkSettings"]["Networks"] = {"project_agent_net": {"IPAddress": "172.27.0.5"}}
    elif tamper == "missing_inspect":
        after["State"] = {}
    with pytest.raises(ValueError, match="IAM2378_"):
        validate_inspect(before, after)


def test_checkpoint_is_fsynced_created_once_and_cannot_be_overwritten(tmp_path):
    checkpoint = tmp_path / "checkpoint.json"
    payload = {
        "schema": CHECKPOINT_SCHEMA,
        "effect_state": "EFFECT_UNKNOWN",
        "revision": 2,
        "target_ledger_read_before_sigkill": False,
        "production_claim": False,
    }
    _write_once_synced(checkpoint, payload)
    assert _read_json(checkpoint) == payload
    with pytest.raises(ValueError, match="IAM2378_CHECKPOINT_PATH_INVALID"):
        _write_once_synced(checkpoint, {"effect_state": "CONFIRMED_EFFECT"})
    assert _read_json(checkpoint) == payload


def test_symlinked_checkpoint_cannot_be_loaded(tmp_path):
    real = tmp_path / "real.json"
    real.write_text('{"effect_state": "CONFIRMED_EFFECT"}\n', encoding="utf-8")
    fake = tmp_path / "checkpoint.json"
    fake.symlink_to(real)
    with pytest.raises(ValueError, match="IAM2378_EVIDENCE_MISSING"):
        _read_json(fake)


def test_checkpoint_not_auto_generated_without_real_observation(tmp_path):
    with pytest.raises(ValueError, match="IAM2378_EVIDENCE_MISSING"):
        _read_json(tmp_path / "no-observation.json")


def test_new_restart_mode_requires_durable_lost_ack_and_no_automatic_enablement():
    source = Path("scripts/enterprise_iam_lab/run_native_docker.sh").read_text("utf-8")
    assert 'LAB_NATIVE_PROCESS_RESTART:-0' in source
    assert "RESTART_REQUIRES_DURABLE_LOST_ACK" in source
    assert "--process-restart-recovery" in source
    assert "docker kill" in source and "docker start" in source
    assert 'TARGET_CONTAINER_ID_CHANGED_ON_RESTART' in source
    assert 'IAM_WORKER_EXIT' in source and '"137"' in source
    assert '--phase sigkill-before-lookup' in source
    assert '--phase verify-restart' in source


def test_worker_must_kill_itself_only_after_durable_checkpoint():
    source = Path("scripts/enterprise_iam_lab/native_process_restart_probe.py").read_text("utf-8")
    assert "os.kill(os.getpid(), signal.SIGKILL)" in source
    assert 'asyncio.run(_capture_pre_kill(' in source
    assert "target_ledger_read_before_sigkill" in source
    assert "lookup_exact_target_effect" in source
    assert "PostgresAtomicEffectStateStore()" in source
    assert "CONFIRMED_NO_EFFECT" not in source


def test_source_does_not_change_authorization_or_iam_target_effect_code():
    src = Path("scripts/enterprise_iam_lab/native_process_restart_probe.py").read_text("utf-8")
    assert "POST " not in src
    assert "issue_iam_permit_after_native_consumption" not in src
    assert "consume_once(" not in src
    assert "LAB_ALLOW_MUTATIONS" not in src
