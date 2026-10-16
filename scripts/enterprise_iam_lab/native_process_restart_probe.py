#!/usr/bin/env python3
"""#2378: prove a REAL local SIGKILL and Docker target process restart.

This does not mutate IAM, consume authorization or issue permits. It reuses
#2377's exact local synthetic-only issuer, signed permit, PostgreSQL and
target-owned SQLite observation. Only a target-owned committed row can justify
CONFIRMED_EFFECT; the caller must run #2377's existing CAS reconciler later.

This is NOT a host-power-off/network-partition or independent-operator proof.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import sys

from scripts.enterprise_iam_lab.reconcile_native_lost_ack import (
    lookup_exact_target_effect, read_native_issuer, require, require_discarded_response,
)
from scripts.enterprise_iam_lab.verify_native_docker import (
    _verified_native_postgres_join,
)
from veritas_os.policy.bind_effect_reconciliation import (
    EffectExecutionState, PostgresAtomicEffectStateStore, _record_hash_valid,
)
from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
    PostgresAtomicAuthorizationConsumptionStore,
)
from veritas_os.storage.db import close_pool


CHECKPOINT_SCHEMA = "iam-native-local-process-sigkill-checkpoint/v1"
RECOVERY_STATUS = "SYNTHETIC_SAME_HOST_SIGKILL_AND_DOCKER_RESTART_NOT_PRODUCTION_PROVEN"


def _read_json(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), "IAM2378_EVIDENCE_MISSING")
    value = json.loads(path.read_text(encoding="utf-8"))
    require(type(value) is dict, "IAM2378_INVALID_EVIDENCE")
    return value


def _write_once_synced(path: Path, record: dict) -> None:
    """Durably materialize nonsecret checkpoint before the worker is SIGKILLed."""
    require(path.parent.is_dir() and not path.exists() and not path.is_symlink(),
            "IAM2378_CHECKPOINT_PATH_INVALID")
    content = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


async def _unknown_state(*, receipt: dict, permit: dict):
    """Read original durable stores, without changing them."""
    native = PostgresAtomicAuthorizationConsumptionStore()
    effects = PostgresAtomicEffectStateStore()
    consumption = await native.get(permit["authorization_id"])
    require(consumption is not None, "IAM2378_CONSUMPTION_MISSING_AFTER_PROCESS_RESTART")
    require(
        consumption.consumption_id == receipt["consumption_id"]
        and consumption.consumption_hash == receipt["consumption_hash"]
        and consumption.live_adapter_bind_authorization_id == permit["authorization_id"]
        and consumption.live_adapter_bind_authorization_hash == receipt["authorization_hash"]
        and consumption.execution_intent_id == permit["execution_intent_id"]
        and consumption.idempotency_key == permit["request_id"],
        "IAM2378_CONSUMPTION_LINEAGE_CHANGED",
    )
    state = await effects.get(consumption.consumption_id)
    require(state is not None and _record_hash_valid(state),
            "IAM2378_DURABLE_EFFECT_STATE_MISSING_OR_TAMPERED")
    require(
        state.state == EffectExecutionState.EFFECT_UNKNOWN
        and state.revision == 2
        and state.operation_id == receipt["consumption_id"]
        and state.authorization_id == permit["authorization_id"]
        and state.consumption_id == consumption.consumption_id
        and state.consumption_hash == consumption.consumption_hash
        and state.execution_intent_id == permit["execution_intent_id"],
        "IAM2378_EFFECT_UNKNOWN_LINEAGE_REQUIRED",
    )
    return state


async def _capture_pre_kill(*, folder: Path, trust: Path,
                            permits: Path, checkpoint: Path) -> None:
    require_discarded_response(folder)
    receipt, permit = read_native_issuer(folder, trust, permits)
    try:
        state = await _unknown_state(receipt=receipt, permit=permit)
        # Deliberately do NOT touch the target's SQLite ledger here. The
        # effect outcome is still UNKNOWN at the point of process death.
        record = {
            "schema": CHECKPOINT_SCHEMA,
            "operation_id": state.operation_id,
            "authorization_id": state.authorization_id,
            "consumption_hash": state.consumption_hash,
            "effect_state_record_hash": state.record_hash,
            "effect_state": state.state.value,
            "revision": state.revision,
            "target_ledger_read_before_sigkill": False,
            "mutation_sent_from_worker": False,
            "new_permit_issued": False,
            "production_claim": False,
        }
        _write_once_synced(checkpoint, record)
    finally:
        await close_pool()


def validate_inspect(before: dict, after: dict) -> dict:
    """Check Docker's observations, not user-supplied 'restarted=true' text."""
    require(type(before) is dict and type(after) is dict, "IAM2378_INSPECT_INVALID")
    a, b = before.get("State"), after.get("State")
    require(type(a) is dict and type(b) is dict, "IAM2378_INSPECT_STATE_MISSING")
    require(
        before.get("Id") and before["Id"] == after.get("Id")
        and a.get("Running") is True and b.get("Running") is True
        and isinstance(a.get("Pid"), int) and isinstance(b.get("Pid"), int)
        and a["Pid"] > 0 and b["Pid"] > 0 and a["Pid"] != b["Pid"]
        and isinstance(a.get("StartedAt"), str)
        and isinstance(b.get("StartedAt"), str)
        and a["StartedAt"] != b["StartedAt"]
        and b.get("Health", {}).get("Status") == "healthy",
        "IAM2378_DOCKER_TARGET_PROCESS_NOT_RESTARTED",
    )
    mounted_before = before.get("Mounts")
    mounted_after = after.get("Mounts")
    require(type(mounted_before) is list and type(mounted_after) is list,
            "IAM2378_DOCKER_MOUNTS_MISSING")
    def state_mount(items):
        mounted = [m for m in items if m.get("Destination") == "/run/lab/state"]
        require(len(mounted) == 1, "IAM2378_TARGET_STATE_MOUNT_MISSING")
        item = mounted[0]
        require(item.get("RW") is True and item.get("Source"),
                "IAM2378_TARGET_STATE_MOUNT_NOT_PERSISTENT")
        return item["Source"]
    require(state_mount(mounted_before) == state_mount(mounted_after),
            "IAM2378_TARGET_STATE_MOUNT_CHANGED")
    nets_before = before.get("NetworkSettings", {}).get("Networks", {})
    nets_after = after.get("NetworkSettings", {}).get("Networks", {})
    require(
        len(nets_before) == len(nets_after) == 1
        and next(iter(nets_before)).endswith("_effect_net")
        and set(nets_before) == set(nets_after)
        and not before.get("HostConfig", {}).get("PortBindings")
        and not after.get("HostConfig", {}).get("PortBindings"),
        "IAM2378_TARGET_ISOLATION_CHANGED",
    )
    return {
        "same_docker_container_restarted": True,
        "target_process_pid_changed": True,
        "target_process_start_time_changed": True,
        "target_healthy_after_restart": True,
        "same_target_owned_sqlite_mount": True,
        "target_still_on_internal_effect_network": True,
        "target_has_no_published_port": True,
    }


async def _verify_after_restart(*, folder: Path, trust: Path, permits: Path,
                                target_db: Path, checkpoint: Path, kill_observation: Path,
                                before_inspect: Path, after_inspect: Path) -> dict:
    require_discarded_response(folder)
    receipt, permit = read_native_issuer(folder, trust, permits)
    checkpoint_data = _read_json(checkpoint)
    terminated = _read_json(kill_observation)
    require(
        checkpoint_data.get("schema") == CHECKPOINT_SCHEMA
        and checkpoint_data.get("effect_state") == "EFFECT_UNKNOWN"
        and checkpoint_data.get("revision") == 2
        and checkpoint_data.get("target_ledger_read_before_sigkill") is False
        and checkpoint_data.get("mutation_sent_from_worker") is False
        and checkpoint_data.get("new_permit_issued") is False
        and checkpoint_data.get("production_claim") is False
        and terminated.get("observed_exit_code") == 128 + signal.SIGKILL
        and terminated.get("expected_termination_signal") == "SIGKILL"
        and terminated.get("production_claim") is False,
        "IAM2378_ABORTED_WORKER_NOT_PROVEN",
    )
    before = _read_json(before_inspect)
    after = _read_json(after_inspect)
    topology = validate_inspect(before, after)
    try:
        state = await _unknown_state(receipt=receipt, permit=permit)
        require(
            checkpoint_data["operation_id"] == receipt["consumption_id"] == state.operation_id
            and checkpoint_data["authorization_id"] == permit["authorization_id"]
            and checkpoint_data["consumption_hash"] == state.consumption_hash
            and checkpoint_data["effect_state_record_hash"] == state.record_hash,
            "IAM2378_POST_SIGKILL_STATE_CHANGED",
        )
        # This is the FIRST target-ledger lookup in this worker. An absent or
        # mismatched row is UNKNOWN / test failure. NEVER infer NO_EFFECT.
        ack = lookup_exact_target_effect(target_db, permit)
        require(ack["permit_id"] == permit["permit_id"],
                "IAM2378_POST_RESTART_TARGET_EFFECT_NOT_CONFIRMED")
        joined = _verified_native_postgres_join(receipt, permit, target_db)
        require(
            joined["native_postgres_consumption_rows"] == 1
            and joined["native_postgres_idempotency_rows"] == 1
            and joined["target_effects_linked_to_postgres"] == 1
            and joined["native_record_digest_verified"] is True,
            "IAM2378_CROSS_DB_RESTART_JOIN_FAILED",
        )
        return {
            "result": "PASS",
            "status": RECOVERY_STATUS,
            "process_killed_by_real_sigkill": True,
            "actual_python_worker_restarted_as_new_interpreter": True,
            "native_postgres_effect_state_survived_kill": True,
            "native_postgres_effect_state_still_unknown": True,
            "target_owned_sqlite_effect_survived_target_restart": True,
            "target_grants": 1,
            "native_postgres_consumptions": 1,
            "no_second_mutation": True,
            "no_permit_reissuance": True,
            "new_effect_authority_granted": False,
            **topology,
            "remote_independent_verifier": False,
            "whole_host_crash_simulated": False,
            "production_claim": False,
        }
    finally:
        await close_pool()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True,
                        choices=("sigkill-before-lookup", "verify-restart"))
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--trust-dir", required=True, type=Path)
    parser.add_argument("--permit-dir", required=True, type=Path)
    parser.add_argument("--target-database", required=True, type=Path)
    parser.add_argument("--checkpoint", required=True, type=Path)
    parser.add_argument("--kill-observation", type=Path)
    parser.add_argument("--before-inspect", type=Path)
    parser.add_argument("--after-inspect", type=Path)
    args = parser.parse_args()
    if args.phase == "sigkill-before-lookup":
        asyncio.run(_capture_pre_kill(
            folder=args.report_dir, trust=args.trust_dir, permits=args.permit_dir,
            checkpoint=args.checkpoint,
        ))
        # A normal process return here would invalidate the entire test.
        os.kill(os.getpid(), signal.SIGKILL)
        raise SystemExit("SIGKILL_DID_NOT_STOP_PROCESS")
    require(
        args.kill_observation is not None
        and args.before_inspect is not None
        and args.after_inspect is not None,
        "IAM2378_RESTART_EVIDENCE_ARGS_MISSING",
    )
    evidence = asyncio.run(_verify_after_restart(
        folder=args.report_dir, trust=args.trust_dir, permits=args.permit_dir,
        target_db=args.target_database, checkpoint=args.checkpoint,
        kill_observation=args.kill_observation,
        before_inspect=args.before_inspect, after_inspect=args.after_inspect,
    ))
    out = args.report_dir / "iam_process_restart_observation.json"
    _write_once_synced(out, evidence)
    print(json.dumps({
        "result": evidence["result"],
        "status": evidence["status"],
        "process_killed_by_real_sigkill": evidence["process_killed_by_real_sigkill"],
        "target_process_pid_changed": evidence["target_process_pid_changed"],
        "production_claim": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
