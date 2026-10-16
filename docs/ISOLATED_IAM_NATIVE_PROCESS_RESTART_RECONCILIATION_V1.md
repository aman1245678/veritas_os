# #2378 — Controlled SIGKILL and Docker target process restart V1

**Claim scope:** One disposable synthetic IAM workflow under one GitHub Actions
host, source-pinned to the exact PR test revision. This is a bounded
crash-*process* recovery experiment, **NOT** `RECON_01 PROVEN`, `ALLOW_01
PROVEN`, a host-power-off test, or an independently operated reconciliation
service.

## Reuse, not replacement

- #2375: actual local `/v1/decide` and signed Human Approval/native issued
  authorization -> one effect-bound Ed25519 Permit -> real isolated Docker
  mTLS synthetic target with target-owned SQLite role-grant ledger.
- #2376: PostgreSQL atomic single-use authorization consumption and cross-DB
  lineage verification; no "allow" from a fabricated self-reported receipt.
- #2377: durable `IN_FLIGHT` -> `EFFECT_UNKNOWN` and existing
  `reconcile_effect_unknown` -> `CONFIRMED_EFFECT` through read-only
  target-owned committed evidence; no second POST or reissued Permit.

**The original three test workflows and all actual policy enforcement code
remain unchanged.** Only `LAB_NATIVE_PROCESS_RESTART=1` selects this experiment;
it additionally requires both `LAB_NATIVE_DURABLE_PG=1` and
`LAB_NATIVE_LOST_ACK=1`. The default execution path is unchanged.

## What stops and what really restarts

1. A single real mTLS POST is transmitted without observing its HTTP response.
   No "201" is taken as authority. The original Permit replay is denied.
2. Existing code records durable PostgreSQL `EFFECT_UNKNOWN`; six standard
   negative conditions are tested without granting any further effect.
3. A **new, separate Python reconciliation worker** reads signed Permit and
   original PostgreSQL consumption/effect state, checks genuine UNKNOWN and
   writes a filesystem-fsynced nonsecret checkpoint. It **does not read** the
   target-owned ledger. It then calls `os.kill(os.getpid(), SIGKILL)`.
   Shell must observe exit status **137**, not an ordinary return or simulated
   exception; an exit code other than 137 fails the workflow.
4. The actual Docker **IAM target process** is killed with `docker kill`,
   verified stopped and started again with `docker start` in the SAME
   container. Docker inspect must show an unchanged container identity,
   distinct positive host process PID and StartedAt, healthy listener, and
   identical RW bind-mounted SQLite state. No published ports or agent
   access may appear.
5. A freshly launched, separate Python process checks that original PostgreSQL
   consumption and exactly the same `EFFECT_UNKNOWN` record/hash survived
   the SIGKILL. It reads target-owned SQLite read-only **after** the target
   process restart, verifies one committed permit/grant/audit, and reuses the
   existing cross-DB digest and lineage comparison. Missing or inconsistent
   target evidence is failure / UNKNOWN, **never CONFIRMED_NO_EFFECT**.
6. The existing #2377 fresh-process reconciliation converts the same
   PostgreSQL record through a compare-and-set to `CONFIRMED_EFFECT`.
   A second confirmation attempt is rejected as terminal. A separate
   final verifier reads PostgreSQL and target SQLite and verifies the
   process-kill/restart evidence too.

The only persisted uploaded evidence is bounded synthetic JSON observations
and SHA-256 checksums. Raw Docker inspect snapshots stay under an ephemeral
host temp directory; signing keys, bearer permits, TLS secrets, full DB files
and live DSNs are NEVER uploaded.

## Security limits that must remain visible

- This is a **controlled SIGKILL** of a local verifier worker and restart of
  a local synthetic target process. It does NOT kill PostgreSQL, simulate
  host power loss, network partition, WAL corruption or credentials withdrawal.
- The disposable host owns both trust and target filesystem. It can read the
  target's SQLite directly. This is **not** independently operated target-signed
  remote read-only reconciliation.
- Positive `CONFIRMED_EFFECT` is justified by target-owned evidence in this
  bounded case. Absence cannot prove `CONFIRMED_NO_EFFECT`, and no fresh
  execution authority is minted or reused after failure.
- No external cloud IAM account, customer privilege, paid model/API, official
  AgentDojo Utility scorer, or production key-management service is involved.
- The status is still `SYNTHETIC_SAME_HOST_SIGKILL_AND_DOCKER_RESTART_NOT_PRODUCTION_PROVEN`;
  source/CI green does not substitute for independent system-boundary testing.

## Dedicated gate

Run `.github/workflows/isolated-iam-native-process-restart-v1.yml`.
Check its exact-HEAD CI, SIGKILL exit witness, Docker inspect-derived
restart proof, SHA256 artifact, native consumption 1 / target mutation 1 /
additional effects 0, terminal-state immutability and all inherited tests.

**Next proof** after this controlled scope: independent target-owned
signed read-only API across an operator boundary with actual network
partitions, verifier credential withdrawal, and PostgreSQL host/service
restart/retained state.
