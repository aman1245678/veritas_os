"""Strict startup re-arms the local stop without claiming durable history."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from veritas_os.api.startup_health import initialize_system_halt_on_startup
from veritas_os.core.eu_ai_act_oversight import SystemHaltController as Controller


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch):
    for key in ("VERITAS_ENV", "VERITAS_POSTURE", "VERITAS_REQUIRE_PRODUCTION_TRUSTLOG_POSTURE"):
        monkeypatch.delenv(key, raising=False)
    for name, value in {
        "_halted": False, "_halted_by": None, "_halted_at": None,
        "_halt_reason": None, "_history": [],
    }.items():
        monkeypatch.setattr(Controller, name, value)


@pytest.mark.parametrize("key,value", [
    ("VERITAS_ENV", "production"), ("VERITAS_ENV", "secure"),
    ("VERITAS_POSTURE", "prod"), ("VERITAS_POSTURE", "secure"),
    ("VERITAS_REQUIRE_PRODUCTION_TRUSTLOG_POSTURE", "1"),
])
def test_strict_start_requires_resume(monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    initialize_system_halt_on_startup()
    assert Controller.status()["halted"] is True
    assert Controller.status()["halted_by"] == "system:startup"


def test_existing_halt_reason_is_preserved(monkeypatch):
    monkeypatch.setenv("VERITAS_ENV", "production")
    Controller.halt(reason="retain operator stop", operator="synthetic-operator")
    before = Controller.status()
    initialize_system_halt_on_startup()
    assert Controller.status() == before
    assert len(Controller._history) == 1


def test_non_strict_start_does_not_clear_existing_stop(monkeypatch):
    monkeypatch.setenv("VERITAS_ENV", "local")
    initialize_system_halt_on_startup()
    assert Controller.is_halted() is False
    Controller.halt(reason="local operator stop", operator="synthetic-operator")
    initialize_system_halt_on_startup()
    assert Controller.is_halted() is True


@pytest.mark.parametrize("last_action", ["halt", "resume"])
def test_fresh_process_rearms_stop_after_previous_process_exit(last_action):
    env = dict(os.environ, VERITAS_ENV="production")
    source = (
        "import json; "
        "from veritas_os.api.startup_health import initialize_system_halt_on_startup as boot; "
        "from veritas_os.core.eu_ai_act_oversight import SystemHaltController as C; "
    )
    previous = subprocess.run(
        [sys.executable, "-c", source + "boot(); " + (
            "C.halt(reason='previous operator stop', operator='synthetic-operator'); "
            if last_action == "halt" else "C.resume(operator='synthetic-operator'); "
        ) + "print(json.dumps(C.status()))"],
        env=env, check=True, capture_output=True, text=True, timeout=15,
    )
    assert json.loads(previous.stdout)["halted"] is (last_action == "halt")
    replacement = subprocess.run(
        [sys.executable, "-c", source + "boot(); print(json.dumps(C.status()))"],
        env=env, check=True, capture_output=True, text=True, timeout=15,
    )
    status = json.loads(replacement.stdout)
    assert status["halted"] is True
    assert status["halted_by"] == "system:startup"
