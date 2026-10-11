"""Fail-closed ownership guard for the Python 3.12 normal test file cutover."""

from pathlib import Path

import pytest

from scripts.ci.partition_heavy_pytest_cases import HEAVY_MODULES
from scripts.ci.select_pytest_shard import (
    partition_test_files,
    without_pinned_heavy_modules,
)


def _baseline():
    return [Path(module) for module in HEAVY_MODULES] + [
        Path(f"veritas_os/tests/test_normal_{index:03d}.py")
        for index in range(24)
    ]


def test_python312_handoff_retains_all_other_files_once():
    full = _baseline()
    normal = without_pinned_heavy_modules(full)
    assert len(full) - len(normal) == 2
    assert set(normal) == set(full) - {Path(module) for module in HEAVY_MODULES}
    assert all(module not in [item.as_posix() for item in normal] for module in HEAVY_MODULES)
    plan = partition_test_files(
        normal, shard_count=8, historical={}, avoid_duplicate_test_basenames=True
    )
    assigned = [p for shard in plan for p in shard]
    assert len(assigned) == len(set(assigned)) == len(normal)
    assert set(assigned) == set(normal)
    assert all(shard for shard in plan)


@pytest.mark.parametrize("remove", HEAVY_MODULES)
def test_missing_heavy_file_refuses_cutover(remove):
    files = [path for path in _baseline() if path.as_posix() != remove]
    with pytest.raises(ValueError, match="both pinned modules exactly once"):
        without_pinned_heavy_modules(files)


def test_duplicate_heavy_file_refuses_cutover():
    files = _baseline() + [Path(HEAVY_MODULES[0])]
    with pytest.raises(ValueError, match="both pinned modules exactly once"):
        without_pinned_heavy_modules(files)


def test_only_exact_pinned_modules_are_excluded():
    other = Path("veritas_os/tests/test_canonical_promotion_live_adapter_dry_run_other.py")
    result = without_pinned_heavy_modules(_baseline() + [other])
    assert other in result
    assert len(result) == len(_baseline()) - 2 + 1
