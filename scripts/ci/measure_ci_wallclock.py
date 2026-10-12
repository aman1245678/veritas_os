#!/usr/bin/env python3
"""Compare two *completed* GitHub Actions CI runs using ALL paginated job timestamps.

Read-only measurement. Does not execute tests, change CI jobs, approve provider
usage, or claim causality. GitHub API timestamps reflect elapsed wall time,
not billed runner minutes. Only exact known CI heads are eligible.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

API_BASE = "https://api.github.com"
REPOSITORY = "veritasfuji-japan/veritas_os"
DEFAULT_BASELINE_RUN = 38112240623
DEFAULT_CANDIDATE_RUN = 38121325792
DEFAULT_BASELINE_SHA = "bc2d4251868cbce65c7712d6b6d2572a0044a071"
DEFAULT_CANDIDATE_SHA = "da7e4889c12f9e04ea6e33a48966aa51e995936a"

NORMAL_PY312 = re.compile(r"^test \(py3\.12, shard [1-8]/8\)$")
NORMAL_PY311 = re.compile(r"^test \(py3\.11, shard [1-4]/4\)$")
HEAVY_PY312 = re.compile(r"^heavy-case test \(py3\.12, shard [1-8]/8\)$")
SLOW_PY312 = re.compile(r"^test-slow shard \(py3\.12, shard [1-4]/4\)$")
EXPECTED_COMMON_NAMES = (
    "coverage (py3.12 combined)", "test (py3.11)", "test (py3.12)"
)


def _instant(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("missing timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("malformed timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("timezone-free timestamp is not trustworthy")
    return parsed.astimezone(timezone.utc)


def _elapsed(start: datetime, finish: datetime) -> float:
    duration = (finish - start).total_seconds()
    if duration < 0 or duration > 172800:
        raise ValueError("negative or implausible job/run timing")
    return round(duration, 3)


def _read_api(path: str, token: str) -> dict:
    if not path.startswith("/repos/" + REPOSITORY + "/"):
        raise ValueError("GitHub API request outside pinned repository")
    req = urllib.request.Request(
        API_BASE + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "User-Agent": "veritas-ci-wallclock-measurement",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as stream:
            value = json.load(stream)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ValueError("read-only GitHub API measurement failed") from exc
    if not isinstance(value, dict):
        raise ValueError("GitHub API payload is not an object")
    return value


def _get_full_jobs(
    run_id: int, fetch: Callable[[str], dict]
) -> list[dict]:
    """Read EVERY page; no misleading first-page-only 30-job comparison."""
    jobs: list[dict] = []
    expected_total: int | None = None
    for page in range(1, 11):
        payload = fetch(
            f"/repos/{REPOSITORY}/actions/runs/{run_id}/jobs"
            f"?per_page=100&page={page}&filter=latest"
        )
        total = payload.get("total_count")
        page_jobs = payload.get("jobs")
        if type(total) is not int or total < 1 or not isinstance(page_jobs, list):
            raise ValueError("missing GitHub job pagination metadata")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise ValueError("changing total_count across GitHub jobs pages")
        if any(not isinstance(job, dict) for job in page_jobs):
            raise ValueError("malformed job in GitHub API data")
        jobs.extend(page_jobs)
        if len(jobs) == expected_total:
            ids = [job.get("id") for job in jobs]
            if any(type(job_id) is not int for job_id in ids) or len(set(ids)) != len(ids):
                raise ValueError("missing/duplicate GitHub job IDs")
            return jobs
        if not page_jobs or len(jobs) > expected_total:
            raise ValueError("incomplete or overlapping GitHub job pages")
    raise ValueError("too many job pages for bounded measurement")


def _validate_job_set(names: list[str], *, mode: str) -> None:
    patterns = {
        "normal_py312": (NORMAL_PY312, 8),
        "normal_py311": (NORMAL_PY311, 4),
        "slow_py312": (SLOW_PY312, 4),
        "heavy_py312": (HEAVY_PY312, 0 if mode == "before" else 8),
    }
    for group, (pattern, expected_count) in patterns.items():
        found = [name for name in names if pattern.fullmatch(name)]
        if len(found) != expected_count or len(set(found)) != expected_count:
            raise ValueError(f"incomplete/duplicated {group} jobs in {mode} CI")
    for name in EXPECTED_COMMON_NAMES:
        if names.count(name) != 1:
            raise ValueError(f"missing/duplicated CI gate: {name}")
    preflight = names.count("heavy-case cutover preflight (py3.12)")
    reconciliation = names.count("heavy-case JUnit complete-reconciliation (py3.12)")
    if preflight != int(mode == "after") or reconciliation != int(mode == "after"):
        raise ValueError("incorrect new/legacy cutover gates")


def summarize_run(
    run: dict, jobs: list[dict], *,
    expected_id: int, expected_head: str, mode: str
) -> dict:
    if (
        run.get("id") != expected_id
        or run.get("name") != "CI"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("event") != "pull_request"
        or run.get("head_sha") != expected_head
        or run.get("path") != ".github/workflows/main.yml"
    ):
        raise ValueError("CI run metadata/status/head is not the pinned successful run")
    if not isinstance(jobs, list) or not jobs:
        raise ValueError("no complete CI jobs supplied")
    job_ids: list[int] = []
    rows: list[dict] = []
    for job in jobs:
        if not isinstance(job, dict) or type(job.get("id")) is not int:
            raise ValueError("missing CI job identity")
        job_ids.append(job["id"])
        if job.get("conclusion") != "success" or job.get("status") != "completed":
            raise ValueError("incomplete, skipped or failed CI job")
        start, stop = _instant(job.get("started_at")), _instant(job.get("completed_at"))
        duration = _elapsed(start, stop)
        name = job.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("unnamed CI job")
        rows.append({
            "job_id": job["id"],
            "name": name,
            "started_at": start.isoformat(),
            "completed_at": stop.isoformat(),
            "duration_seconds": duration,
        })
    if len(set(job_ids)) != len(job_ids):
        raise ValueError("duplicate job IDs")
    names = [row["name"] for row in rows]
    if len(set(names)) != len(names):
        raise ValueError("duplicate job names")
    _validate_job_set(names, mode=mode)

    created_at = _instant(run.get("created_at"))
    run_started = _instant(run.get("run_started_at"))
    first = min(_instant(row["started_at"]) for row in rows)
    last = max(_instant(row["completed_at"]) for row in rows)
    if created_at > run_started or run_started > last or created_at > first:
        raise ValueError("GitHub run creation/start chronology invalid")
    # All jobs across the complete run, including actions setup and waiting.
    runner_seconds = round(sum(row["duration_seconds"] for row in rows), 3)
    return {
        "run_id": expected_id,
        "run_url": f"https://github.com/{REPOSITORY}/actions/runs/{expected_id}",
        "head_sha": expected_head,
        "mode": mode,
        "job_count": len(rows),
        "created_at": created_at.isoformat(),
        "run_started_at": run_started.isoformat(),
        "first_job_started_at": first.isoformat(),
        "last_job_finished_at": last.isoformat(),
        "queued_until_first_job_seconds": _elapsed(created_at, first),
        "run_to_last_job_seconds": _elapsed(run_started, last),
        "created_to_last_job_seconds": _elapsed(created_at, last),
        "observed_runner_seconds_sum": runner_seconds,
        "longest_job": max(rows, key=lambda row: row["duration_seconds"]),
        "slowest_py312_file_shard": max(
            (row for row in rows if NORMAL_PY312.fullmatch(row["name"])),
            key=lambda row: row["duration_seconds"],
        ),
        "slowest_py312_heavy_shard": (
            max(
                (row for row in rows if HEAVY_PY312.fullmatch(row["name"])),
                key=lambda row: row["duration_seconds"],
            ) if mode == "after" else None
        ),
        "jobs": sorted(rows, key=lambda row: row["name"]),
    }


def compare_runs(before: dict, after: dict) -> dict:
    before_seconds = before["created_to_last_job_seconds"]
    after_seconds = after["created_to_last_job_seconds"]
    if before_seconds <= 0:
        raise ValueError("baseline wall-clock duration invalid")
    return {
        "schema_version": 1,
        "kind": "CI_OBSERVATIONAL_WALLCLOCK_COMPARISON",
        "baseline": before,
        "candidate": after,
        "wallclock_delta_seconds": round(after_seconds - before_seconds, 3),
        "wallclock_delta_pct": round(
            100 * (after_seconds - before_seconds) / before_seconds, 2
        ),
        "runner_time_delta_seconds": round(
            after["observed_runner_seconds_sum"]
            - before["observed_runner_seconds_sum"], 3
        ),
        "limitations": [
            "Two different commits and runs; not a controlled A/B experiment.",
            "Run duration reflects queueing, concurrency, runner speed and test-tree drift.",
            "Runner seconds are summed job wall durations, NOT GitHub billed minutes.",
            "Only one baseline run and one candidate run; do not infer repeatable speedup.",
            "Provider/effect execution and production latency are not measured.",
        ],
    }


def to_markdown(report: dict) -> str:
    b, a = report["baseline"], report["candidate"]
    delta = report["wallclock_delta_seconds"]
    sign = "increase" if delta >= 0 else "decrease"
    lines = [
        "# CI wall-clock comparison (observational only)",
        "",
        f"- Baseline: [Run {b['run_id']}]({b['run_url']}), head \`{b['head_sha']}\`",
        f"- Candidate: [Run {a['run_id']}]({a['run_url']}), head \`{a['head_sha']}\`",
        "",
        "| Metric | File-only baseline | New case-shard cutover |",
        "|---|---:|---:|",
    ]
    for label, key, divisor in [
        ("Created → last CI job (minutes)", "created_to_last_job_seconds", 60),
        ("Run start → last CI job (minutes)", "run_to_last_job_seconds", 60),
        ("Queue until first job (minutes)", "queued_until_first_job_seconds", 60),
        ("Sum of runner job wall durations (minutes; **not billing**)",
         "observed_runner_seconds_sum", 60),
        ("Job count", "job_count", 1),
    ]:
        fmt = ".2f" if divisor == 60 else ".0f"
        lines.append(
            f"| {label} | {format(b[key]/divisor, fmt)} | {format(a[key]/divisor, fmt)} |"
        )
    lines += [
        "",
        f"Observed wall-clock {sign}: **{abs(delta)/60:.2f} minutes** "
        f"({report['wallclock_delta_pct']:+.2f}%).",
        "",
        "## Bottlenecks",
        f"- Baseline slowest job: \`{b['longest_job']['name']}\` "
        f"({b['longest_job']['duration_seconds']/60:.2f} min)",
        f"- Candidate slowest job: \`{a['longest_job']['name']}\` "
        f"({a['longest_job']['duration_seconds']/60:.2f} min)",
        f"- Baseline slowest Python 3.12 file shard: "
        f"\`{b['slowest_py312_file_shard']['name']}\`",
        f"- Candidate slowest Python 3.12 file shard: "
        f"\`{a['slowest_py312_file_shard']['name']}\`",
        "",
        "## Limitations",
        *["- " + note for note in report["limitations"]],
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-run-id", type=int, default=DEFAULT_BASELINE_RUN)
    parser.add_argument("--candidate-run-id", type=int, default=DEFAULT_CANDIDATE_RUN)
    parser.add_argument("--baseline-head-sha", default=DEFAULT_BASELINE_SHA)
    parser.add_argument("--candidate-head-sha", default=DEFAULT_CANDIDATE_SHA)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args()
    token = os.environ.get("GH_ACTIONS_READ_TOKEN", "")
    if not token:
        parser.exit(1, "FAIL CI timing measurement: missing read-only Actions token\n")
    try:
        runs = []
        for run_id, head, mode in [
            (args.baseline_run_id, args.baseline_head_sha, "before"),
            (args.candidate_run_id, args.candidate_head_sha, "after"),
        ]:
            record = _read_api(
                f"/repos/{REPOSITORY}/actions/runs/{run_id}", token
            )
            jobs = _get_full_jobs(
                run_id, lambda path: _read_api(path, token)
            )
            runs.append(summarize_run(
                record, jobs, expected_id=run_id, expected_head=head, mode=mode
            ))
        report = compare_runs(*runs)
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        markdown = to_markdown(report)
        args.markdown_output.write_text(markdown, encoding="utf-8")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with Path(os.environ["GITHUB_STEP_SUMMARY"]).open(
                "a", encoding="utf-8"
            ) as stream:
                stream.write(markdown + "\n")
        print(
            "PASS read-only observational CI timing comparison: "
            f"{runs[0]['job_count']} baseline jobs and "
            f"{runs[1]['job_count']} candidate jobs; "
            f"delta={report['wallclock_delta_pct']:+.2f}%"
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"FAIL CI timing measurement: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
