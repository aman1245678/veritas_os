"""Uvicorn CLI declarations must not bypass the local halt deployment guard."""

from __future__ import annotations

import logging
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

import pytest

from veritas_os.api import startup_health


@pytest.fixture(autouse=True)
def isolated_deployment(monkeypatch):
    for key in (
        "VERITAS_POSTURE", "VERITAS_REQUIRE_PRODUCTION_TRUSTLOG_POSTURE", "NODE_ENV",
        "VERITAS_AUTH_ALLOW_FAIL_OPEN", "VERITAS_AUTH_STORE_FAILURE_MODE",
        "NEXT_PUBLIC_VERITAS_API_BASE_URL", "VERITAS_ENABLE_DIRECT_FUJI_API",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VERITAS_ENV", "production")
    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    monkeypatch.setenv("UVICORN_WORKERS", "1")
    monkeypatch.setattr(
        startup_health, "validate_trustlog_production_posture_on_startup",
        lambda **kwargs: None,
    )


@pytest.mark.parametrize("launcher", ["/venv/bin/uvicorn", "/venv/uvicorn/__main__.py"])
@pytest.mark.parametrize("args", [["--workers", "2"], ["--workers=2"]])
def test_cli_multiple_workers_override_single_worker_env(monkeypatch, launcher, args):
    monkeypatch.setattr(sys, "argv", [launcher, "example:app", *args])
    with pytest.raises(RuntimeError, match="process-local emergency halt"):
        startup_health.run_startup_config_validation(
            logger=logging.getLogger(__name__), validator=lambda: None,
        )


@pytest.mark.parametrize("argv", [
    ["/venv/bin/uvicorn", "example:app", "--workers=1"],
    ["/venv/bin/pytest", "--workers", "2"],
    ["/other/__main__.py", "--workers", "2"],
    ["/venv/bin/uvicorn", "example:app", "--", "--workers", "2"],
])
def test_single_worker_and_unrelated_launchers_remain_allowed(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", argv)
    startup_health.run_startup_config_validation(
        logger=logging.getLogger(__name__), validator=lambda: None,
    )


def test_local_cli_multiple_workers_warn(monkeypatch, caplog):
    monkeypatch.setenv("VERITAS_ENV", "local")
    monkeypatch.setattr(sys, "argv", ["uvicorn", "example:app", "--workers=2"])
    startup_health.run_startup_config_validation(
        logger=logging.getLogger(__name__), validator=lambda: None,
    )
    assert "process-local emergency halt" in caplog.text


@pytest.mark.skipif(os.name != "posix", reason="process-group cleanup requires POSIX")
@pytest.mark.parametrize("module_cli", [True, False])
def test_real_uvicorn_workers_refuse_startup(tmp_path, module_cli):
    """Exercise argv inherited by real spawned Uvicorn workers on loopback."""
    (tmp_path / "worker_probe.py").write_text(
        "from contextlib import asynccontextmanager\n"
        "import logging\n"
        "from fastapi import FastAPI\n"
        "from veritas_os.api import startup_health as h\n"
        "@asynccontextmanager\n"
        "async def lifespan(app):\n"
        "    h.validate_trustlog_production_posture_on_startup = lambda **kw: None\n"
        "    h.run_startup_config_validation(logger=logging.getLogger('probe'), "
        "validator=lambda: None)\n"
        "    print('WORKER_ADMITTED', flush=True)\n"
        "    yield\n"
        "app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )
    launcher = ([sys.executable, "-m", "uvicorn"] if module_cli else
                [str(Path(sys.executable).with_name("uvicorn"))])
    worker_args = ["--workers", "2"] if module_cli else ["--workers=2"]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2])
    lines = []
    with subprocess.Popen(
        [*launcher, "worker_probe:app", "--host", "127.0.0.1", "--port", "0", *worker_args],
        cwd=tmp_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True,
    ) as process:
        try:
            deadline = time.monotonic() + 20
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while time.monotonic() < deadline:
                    if not selector.select(timeout=0.2):
                        continue
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    lines.append(chunk.decode("utf-8", errors="replace"))
                    output = "".join(lines)
                    if "WORKER_ADMITTED" in output or output.count("Application startup failed") >= 2:
                        break
            output = "".join(lines)
            assert "WORKER_ADMITTED" not in output, output
            assert output.count("Application startup failed") >= 2, output
            assert "process-local emergency halt" in output, output
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            process.communicate(timeout=10)
