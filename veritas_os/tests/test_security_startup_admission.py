"""Strict authenticated HTTP admission requires completed API startup."""

from __future__ import annotations

import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from veritas_os.api import auth
from veritas_os.api.rbac import Permission


@pytest.mark.parametrize("dependency", [
    auth.require_api_key, auth.require_api_key_header_or_query,
    auth.require_permission(Permission.config_write),
])
@pytest.mark.parametrize("marker", [None, False, "true"])
def test_strict_authentication_cannot_bypass_missing_startup(monkeypatch, dependency, marker):
    monkeypatch.setenv("VERITAS_ENV", "production")
    monkeypatch.setenv("VERITAS_API_KEY", "startup-admission-test")
    monkeypatch.delenv("VERITAS_API_KEYS", raising=False)
    app = FastAPI()
    app.state.security_startup_complete = marker
    app.state.security_startup_pid = os.getpid()
    effects = []

    @app.post("/effect", dependencies=[Depends(dependency)])
    def effect():
        effects.append("executed")
        return {"ok": True}

    with TestClient(app) as client:
        assert client.post("/effect").status_code == 401
        assert effects == []
        response = client.post("/effect", headers={"X-API-Key": "startup-admission-test"})
        assert response.status_code == 503
        assert effects == []
        app.state.security_startup_complete = True
        assert client.post("/effect", headers={"X-API-Key": "startup-admission-test"}).status_code == 200
        assert effects == ["executed"]
        app.state.security_startup_pid = 0
        assert client.post("/effect", headers={"X-API-Key": "startup-admission-test"}).status_code == 503
        assert effects == ["executed"]
        app.state.security_startup_pid = os.getpid()
        app.state.security_startup_complete = False
        assert client.post("/effect", headers={"X-API-Key": "startup-admission-test"}).status_code == 503
        assert effects == ["executed"]


@pytest.mark.skipif(os.name != "posix", reason="process-group cleanup requires POSIX")
def test_real_uvicorn_lifespan_off_refuses_protected_api(monkeypatch):
    """A real API process with startup disabled must not admit authenticated requests."""
    monkeypatch.setenv("VERITAS_ENV", "production")
    monkeypatch.setenv("VERITAS_API_KEY", "startup-admission-test")
    monkeypatch.delenv("VERITAS_API_KEYS", raising=False)
    for key in ("VERITAS_POSTURE", "WEB_CONCURRENCY", "UVICORN_WORKERS", "SERVER_SOFTWARE"):
        monkeypatch.delenv(key, raising=False)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(auth.__file__).resolve().parents[2])
    with subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "veritas_os.api.server:app",
         "--lifespan", "off", "--host", "127.0.0.1", "--port", "0", "--no-use-colors"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
    ) as process:
        try:
            output = ""
            address = None
            deadline = time.monotonic() + 30
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while time.monotonic() < deadline:
                    if not selector.select(timeout=0.2):
                        continue
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    output += chunk.decode("utf-8", errors="replace")
                    address = re.search(r"Uvicorn running on (http://127\.0\.0\.1:\d+)", output)
                    if address:
                        break
            assert address is not None, output
            request = Request(
                address.group(1) + "/v1/system/halt-status",
                headers={"X-API-Key": "startup-admission-test"},
            )
            try:
                response = urlopen(request, timeout=10)
            except HTTPError as error:
                response = error
            with response:
                assert response.status == 503
                assert b"API security startup incomplete" in response.read()
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            process.communicate(timeout=10)
