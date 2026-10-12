"""Fail-closed synthetic checks for read-only, complete CI job timing evidence."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from scripts.ci.measure_ci_wallclock import (
    DEFAULT_BASELINE_RUN,
    DEFAULT_BASELINE_SHA,
    DEFAULT_CANDIDATE_RUN,
    DEFAULT_CANDIDATE_SHA,
    _get_full_jobs,
    _instant,
    compare_runs,
    summarize_run,
    to_markdown,
)

BASE = datetime(2026, 10, 11, 6, tzinfo=timezone.utc)


def _instant_at(minutes):
    return (BASE + timedelta(minutes=minutes)).isoformat()


def _names(mode):
    names = [
        *[f"test (py3.11, shard {i}/4)" for i in range(1, 5)],
        *[f"test (py3.12, shard {i}/8)" for i in range(1, 9)],
        *[f"test-slow shard (py3.12, shard {i}/4)" for i in range(1, 5)],
        "coverage (py3.12 combined)",
        "test (py3.11)", "test (py3.12)",
        "lint", "dependency-audit",
    ]
    if mode == "after":
        names += [
            *[f"heavy-case test (py3.12, shard {i}/8)" for i in range(1, 9)],
            "heavy-case cutover preflight (py3.12)",
            "heavy-case JUnit complete-reconciliation (py3.12)",
        ]
    return names


def _build(mode):
    run_id, head = (
        (DEFAULT_BASELINE_RUN, DEFAULT_BASELINE_SHA)
        if mode == "before" else
        (DEFAULT_CANDIDATE_RUN, DEFAULT_CANDIDATE_SHA)
    )
    run = {
        "id": run_id,
        "name": "CI",
        "path": ".github/workflows/main.yml",
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "head_sha": head,
        "created_at": _instant_at(0),
        "run_started_at": _instant_at(1),
    }
    jobs = []
    for i, name in enumerate(_names(mode)):
        start = 2 + (i % 3)
        end = 12 + i / 3 if mode == "before" else 10 + i / 5
        jobs.append({
            "id": run_id * 100 + i,
            "name": name,
            "status": "completed",
            "conclusion": "success",
            "started_at": _instant_at(start),
            "completed_at": _instant_at(end),
        })
    return run, jobs


def _summary(mode, run=None, jobs=None):
    default_run, default_jobs = _build(mode)
    return summarize_run(
        default_run if run is None else run,
        default_jobs if jobs is None else jobs,
        expected_id=DEFAULT_BASELINE_RUN if mode == "before" else DEFAULT_CANDIDATE_RUN,
        expected_head=DEFAULT_BASELINE_SHA if mode == "before" else DEFAULT_CANDIDATE_SHA,
        mode=mode,
    )


def test_accepts_complete_pinned_runs_and_reports_observational_delta():
    before = _summary("before")
    after = _summary("after")
    result = compare_runs(before, after)
    assert result["kind"] == "CI_OBSERVATIONAL_WALLCLOCK_COMPARISON"
    assert before["job_count"] == len(_names("before"))
    assert after["job_count"] == len(_names("after"))
    assert result["wallclock_delta_seconds"] < 0
    assert "not a controlled A/B experiment" in " ".join(result["limitations"])
    rendered = to_markdown(result)
    assert "observational only" in rendered
    assert str(DEFAULT_BASELINE_RUN) in rendered
    assert str(DEFAULT_CANDIDATE_RUN) in rendered
    assert "not billing" in rendered


@pytest.mark.parametrize("field,wrong", [
    ("id", 900),
    ("name", "Unrelated Workflow"),
    ("path", ".github/workflows/unrelated.yml"),
    ("event", "push"),
    ("status", "in_progress"),
    ("conclusion", "failure"),
    ("head_sha", "0" * 40),
])
def test_wrong_run_provenance_never_passes(field, wrong):
    run, jobs = _build("before")
    run[field] = wrong
    with pytest.raises(ValueError, match="pinned successful run"):
        _summary("before", run, jobs)


@pytest.mark.parametrize("mode", ["before", "after"])
def test_missing_file_shard_is_rejected(mode):
    run, jobs = _build(mode)
    jobs = [j for j in jobs if j["name"] != "test (py3.12, shard 3/8)"]
    with pytest.raises(ValueError, match="incomplete/duplicated normal_py312"):
        _summary(mode, run, jobs)


def test_missing_heavy_shard_is_rejected():
    run, jobs = _build("after")
    jobs = [j for j in jobs if j["name"] != "heavy-case test (py3.12, shard 3/8)"]
    with pytest.raises(ValueError, match="incomplete/duplicated heavy_py312"):
        _summary("after", run, jobs)


def test_unexpected_heavy_shard_in_baseline_is_rejected():
    run, jobs = _build("before")
    extra = deepcopy(jobs[-1])
    extra["name"] = "heavy-case test (py3.12, shard 1/8)"
    extra["id"] += 100
    jobs.append(extra)
    with pytest.raises(ValueError, match="incomplete/duplicated heavy_py312"):
        _summary("before", run, jobs)


def test_duplicate_name_and_duplicate_job_id_are_rejected():
    run, jobs = _build("after")
    copy = deepcopy(jobs[0])
    copy["id"] += 99
    with pytest.raises(ValueError, match="duplicate job names"):
        _summary("after", run, jobs + [copy])
    copy["id"] = jobs[0]["id"]
    with pytest.raises(ValueError, match="duplicate job IDs"):
        _summary("after", run, jobs + [copy])


@pytest.mark.parametrize("field,wrong,reason", [
    ("conclusion", "skipped", "skipped or failed"),
    ("status", "queued", "skipped or failed"),
    ("started_at", "not-a-date", "malformed timestamp"),
    ("completed_at", "2026-10-11T05:00:00+00:00", "negative or implausible"),
])
def test_incomplete_failed_and_malformed_jobs_fail_closed(field, wrong, reason):
    run, jobs = _build("after")
    jobs[0][field] = wrong
    with pytest.raises(ValueError, match=reason):
        _summary("after", run, jobs)


def test_naive_timestamp_fails_closed():
    with pytest.raises(ValueError, match="timezone-free"):
        _instant("2026-10-11T10:00:00")


def test_missing_reconciliation_gate_is_rejected():
    run, jobs = _build("after")
    jobs = [
        x for x in jobs if x["name"] != "heavy-case JUnit complete-reconciliation (py3.12)"
    ]
    with pytest.raises(ValueError, match="incorrect new/legacy cutover"):
        _summary("after", run, jobs)


def test_pagination_reads_all_101_jobs_before_declaring_complete():
    jobs = [{"id": i} for i in range(1, 102)]
    calls = []
    def fetch(path):
        calls.append(path)
        if "page=1&" in path:
            return {"total_count": len(jobs), "jobs": jobs[:100]}
        if "page=2&" in path:
            return {"total_count": len(jobs), "jobs": jobs[100:]}
        raise AssertionError("unexpected GitHub pagination request")

    assert _get_full_jobs(123, fetch) == jobs
    assert len(calls) == 2


def test_incomplete_second_page_fails_closed():
    jobs = [{"id": i} for i in range(1, 102)]
    def fetch(path):
        if "page=1&" in path:
            return {"total_count": 101, "jobs": jobs[:100]}
        return {"total_count": 101, "jobs": []}
    with pytest.raises(ValueError, match="incomplete"):
        _get_full_jobs(123, fetch)


def test_overlapping_job_pages_are_rejected():
    jobs = [{"id": i} for i in range(1, 101)]
    def fetch(path):
        return {"total_count": 101, "jobs": jobs if "page=1&" in path else [jobs[-1]]}
    with pytest.raises(ValueError, match="duplicate GitHub job IDs"):
        _get_full_jobs(123, fetch)


def test_aggregate_rejects_zero_baseline_elapsed():
    a, b = _summary("before"), _summary("after")
    a["created_to_last_job_seconds"] = 0
    with pytest.raises(ValueError, match="baseline wall-clock"):
        compare_runs(a, b)
