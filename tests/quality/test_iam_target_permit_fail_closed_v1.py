"""Fail-closed target: LAB_ALLOW_MUTATIONS is not authorization."""
import importlib.util
import sqlite3
from pathlib import Path

import pytest

TARGET = Path(__file__).resolve().parents[2] / "scripts/enterprise_iam_lab/target_service.py"


@pytest.mark.parametrize("flag", ["0", "1"])
def test_scoped_identity_cannot_mutate_without_governed_permit(monkeypatch, tmp_path, flag):
    monkeypatch.setenv("LAB_ALLOW_MUTATIONS", flag)
    monkeypatch.setenv("LAB_DB_PATH", str(tmp_path / "iam.sqlite3"))
    spec = importlib.util.spec_from_file_location("iam_target_under_test", TARGET)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.init_db()

    class Connection:
        def getpeercert(self):
            return {"subject": ((("commonName", "scoped-executor"),),)}

    class Request:
        connection = Connection()
        headers = {"Content-Length": "17"}
        path = module.TARGET_PATH
        def __init__(self):
            self.responses = []
        def respond(self, status, reason):
            self.responses.append((status, reason))

    req = Request()
    module.Handler.do_POST(req)
    expected_reason = ("governed_executor_not_integrated" if flag == "0" else "veritas_target_permit_gate_not_integrated")
    assert req.responses == [(503, expected_reason)]
    with sqlite3.connect(module.DB_PATH) as db:
        assert db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 0
        assert db.execute("SELECT status, reason FROM audit").fetchall() == [
            (503, expected_reason)
        ]
