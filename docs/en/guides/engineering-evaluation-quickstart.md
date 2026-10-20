# VERITAS OS — Engineering Evaluation Quickstart

**Audience:** AI-agent developers, security researchers, platform engineers, and enterprise evaluation teams.

**Goal:** In 10–15 minutes, inspect a reproducible local/offline execution-governance example; then decide whether a deeper, *scoped* PoC is worth discussing.

VERITAS treats an AI-proposed action as a **decision candidate**, not execution authority. Applicable authority, policy, approvals, and evidence must be evaluated before an effect crosses the Bind Boundary. See the [current implementation matrix](../validation/current-implementation-matrix.md) for implemented versus partial and future capabilities.

## Step 1 — Inspect the offline reviewer demo (10–15 minutes)

From a local checkout of this repository with a supported Python environment and any required local dependencies:

```bash
python3 scripts/demo/validate_reviewer_evidence_packet.py
```

Use the [External Reviewer Quickstart](../demo/external-reviewer-quickstart.md) for the expected fields and file locations. The documented fixture covers **five cases**: missing authority, missing approval, expired approval, and scope mismatch are blocked; valid authority and approval produce a commit-eligible fixture outcome. Inspect the actual validation report, not merely the process exit code.

Optionally generate the reviewer evidence bundle:

```bash
python3 scripts/demo/build_reviewer_evidence_bundle.py
```

The validation command uses local fixtures: **no live SaaS/IAM, customer credentials, external LLM call, or production effect is required**. A fixture result labeled `commit` or `commit_eligible` does **not** mean a real permission change was performed.

## Step 2 — Inspect a bounded external-effect reference path (optional)

```bash
python3 scripts/demo/run_external_bind_poc.py
```

The [External Bind Boundary PoC guide](external-bind-poc-evidence.md) documents three **synthetic** scenarios: a verified committed action, a blocked action with no action POST, and a compensation/rollback outcome with verification. It uses a local loopback fixture and test-only transport mapping; it is **not** a production SaaS integration. The scenario begins from a synthetic decision candidate rather than running the complete `/v1/decide` pipeline.

For an independently reviewable controlled Decision-to-Effect chain that includes real TLS and PostgreSQL with **synthetic business effects**, inspect the [reproducible E2E proof guide](../../../artifacts/real-decision-to-effect-e2e/README.md). Evaluate proof results against their **exact tested commit and assumptions**.

## Step 3 — Decide whether a one-day or customer-scoped PoC is relevant

For a **local/configured** one-day walkthrough, use the [One-Day PoC Walkthrough](../poc/one-day-poc-walkthrough.md) and [PoC Reviewer Pack](../poc/one-day-poc-reviewer-pack.md). That path requires an appropriately configured VERITAS API server and access controls. It is not a ready-made recipe for production installation into an arbitrary enterprise environment.

For a proposed customer-specific pilot, first agree on:

1. **One exact effect boundary:** a named API mutation, IAM privilege change, or approval-gated action, including the target and environment.
2. **Trust and credential ownership:** who issues authority, holds execution credentials, and prevents direct bypass around VERITAS (including IAM/network controls).
3. **Adversarial acceptance criteria:** fail-closed refusal when authority/approval is missing, stale, revoked, or mismatched; replay resistance and no unauthorized effect.
4. **Outcome and failure evidence:** receipts, unknown-effect handling, read-only reconciliation, and what is observable to an independent reviewer.
5. **Utility, environment, and safety constraints:** legitimate-task success alongside security; synthetic-first testing; no live customer data, production operations, paid provider use, or external effects without separate explicit agreement.

Record the repository commit SHA, environment, commands, pass/fail outputs, sanitized evidence, and open limitations. A green CI status or a local fixture PASS is not by itself proof of production bypass resistance, independent third-party certification, or customer readiness.

## Request a technical evaluation

Use the repository's [Technical collaboration / evaluation issue template](../../../.github/ISSUE_TEMPLATE/technical_collaboration.yml) to describe a **non-sensitive, bounded** evaluation proposal. Include the exact use case, expected effect boundary, and success criteria. An issue is only a proposal: it does not grant access, approve deployment, authorize spending, or permit external effects. Report vulnerabilities privately via [SECURITY.md](../../../SECURITY.md), not in a public issue.

**Scope boundary:** These materials enable local/offline review and a structured PoC discussion. They do **not** establish live bank/customer integration, universal Bind coverage, production availability or latency, commercial deployment, completed independent security audit, or regulatory certification.
