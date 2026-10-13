"""Fail-closed static compatibility gate for native-v2 and live-adapter bind APIs.

This is a source-contract regression test, NOT proof of runtime interoperability
or permission to enable IAM mutations.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "veritas_os/policy/native_bind_authorization.py"
CONSUME = ROOT / "veritas_os/policy/native_bind_authorization_consumption.py"
LIVE = ROOT / "veritas_os/policy/live_adapter_bind_authorization_consumption.py"
TARGET = ROOT / "scripts/enterprise_iam_lab/target_service.py"


def function(path: Path, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
    if len(found) != 1:
        raise AssertionError(f"missing/duplicate source API: {path.name}:{name}")
    return found[0]


def args(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}


class NativeLiveCompatibilityGate(unittest.TestCase):
    def test_native_issuance_and_verification_require_external_trust(self) -> None:
        for name in ("issue_native_bind_authorization", "verify_native_bind_authorization"):
            required = {"source_inputs", "governance_inputs", "trust_inputs"}
            self.assertTrue(required <= args(function(NATIVE, name)))

    def test_native_consume_rechecks_current_evidence_and_store(self) -> None:
        required = {"issuance_source_inputs", "current_source_inputs", "current_runtime_risk_packet", "governance_inputs", "trust_inputs", "now", "consumption_store"}
        node = function(CONSUME, "consume_native_bind_authorization")
        self.assertIsInstance(node, ast.AsyncFunctionDef)
        self.assertTrue(required <= args(node))

    def test_live_consume_has_distinct_adapter_dependencies(self) -> None:
        required = {"governance_inputs", "trust_inputs", "now", "consumption_store", "credential_resolver", "authorization_header_constructor", "adapter_factory"}
        node = function(LIVE, "consume_live_adapter_bind_authorization_and_invoke_bind")
        self.assertIsInstance(node, ast.AsyncFunctionDef)
        self.assertTrue(required <= args(node))

    def test_no_unverified_direct_artifact_interoperability_claim(self) -> None:
        # A distinct native artifact and live-adapter artifact exist. Shared
        # consumption record types do not establish artifact compatibility.
        self.assertIn("NativeBindAuthorizationArtifact", NATIVE.read_text(encoding="utf-8"))
        self.assertIn("CanonicalLiveAdapterBindAuthorizationArtifact", LIVE.read_text(encoding="utf-8"))
        self.assertNotEqual(
            args(function(CONSUME, "consume_native_bind_authorization")),
            args(function(LIVE, "consume_live_adapter_bind_authorization_and_invoke_bind")),
        )

    def test_iam_target_stays_disabled_by_default(self) -> None:
        tree = ast.parse(TARGET.read_text(encoding="utf-8"))
        # The source must continue to use a fail-closed explicit opt-in.
        source = TARGET.read_text(encoding="utf-8")
        self.assertIn('os.getenv("LAB_ALLOW_MUTATIONS", "0") != "1"', source)


if __name__ == "__main__":
    unittest.main()
