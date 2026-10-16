# PR #2377 — Native PostgreSQL effect-unknown and lost-ACK reconciliation V1

**Status:** Synthetic, same-host, isolated CI candidate. **NOT RECON_01 / ALLOW_01 PROVEN.**

## Existing components reused

- #2376: genuine synthetic `/v1/decide` → signed native Human Approval →
  atomic PostgreSQL authorization consumption → signed 10-second Ed25519
  permit → real segregated Docker/mTLS scoped executor → target-owned SQLite.
- `recover_in_flight_after_consumption`: reconstitute a durable **IN_FLIGHT**
  attempt from exactly the PostgreSQL-consumed authorization; no new capability.
- `classify_bind_exception`: transition conservatively to **EFFECT_UNKNOWN**.
- `reconcile_effect_unknown`: existing verifier-backed PostgreSQL CAS
  to **CONFIRMED_EFFECT** only when a separate verifier confirms an exact
  target-owned committed operation. Terminal state must be immutable.

The original `#2375` memory-only and `#2376` durable known-response
workflows are preserved, with their existing baseline assertions.

## What the new mode actually does

With explicit `LAB_NATIVE_LOST_ACK=1` and `LAB_NATIVE_DURABLE_PG=1`:

1. Before issuing the bearer permit, record IN_FLIGHT in PostgreSQL from the
   actual native consumed record. An inability to persist it fails the test.
2. The scoped Docker mTLS executor writes the **same** signed Permit with one
   real HTTPS POST and closes its socket **without calling getresponse or
   reading any HTTP status/body**. Completion of a socket send is not
   completion of a target effect. This models an acknowledgement lost
   *from the client's perspective*, not a network-injected packet loss.
3. A new, separate Python process reads existing PostgreSQL effect state and
   marks it EFFECT_UNKNOWN after the unobserved acknowledgement. **No
   authorization is re-consumed and no mutation is resent.**
4. Existing negative mTLS cases, wrong actor, wrong signer, permit mutation and
   replay tests continue to execute.
5. A second fresh process reopens **target-owned SQLite read-only**, validates
   the original signed permit from the isolated trusted host's pinned public
   key at its historical issue time, and checks the one committed grant,
   permit consumption, audit ID, actor, intent, request ID and validity
   window against **native PostgreSQL** using the #2376 verifier.
6. An exact, digest-bound verified local synthetic observation feeds the
   existing `reconcile_effect_unknown`. Its durable effect record must change
   EFFECT_UNKNOWN → CONFIRMED_EFFECT with a verification proof hash.
   A second reconciliation attempt fails because terminal state is immutable.
7. The final independent source verifier reopens PostgreSQL and checks the
   target SQLite against the same committed IDs and effect state; upload
   sanitized result-only JSON plus SHA-256 file manifest.

## Strict safety and nonclaims

- The trusted disposable **host** can read both databases and owns the
  ephemeral Ed25519 key; this is **not** independently operated cross-host
  authoritative target reconciliation.
- A missing effect record, absent/invalid target row, mismatched receipt,
  bad signature or missing PostgreSQL record is **UNKNOWN or failure**;
  it is NEVER promoted to CONFIRMED_NO_EFFECT. No retries.
- Only the client acknowledgement is deliberately unobserved. The experiment
  does not prove recovery across an actual host crash, power loss, network
  partition, compromised host or authenticated remote read-only service.
- Native consumption and target effect still form separate transactions.
  The protocol makes **no** claim of a distributed atomic commit.
- No production credentials, external IAM provider, paid model, official
  AgentDojo scorer, real customer effect or Utility measurement is used.
- Never mark `RECON_01 PROVEN`, `ALLOW_01 PROVEN`, production non-bypassability
  or third-party validation as achieved from this bounded result.

## Run independently in an ephemeral development runner

Use the dedicated
`.github/workflows/isolated-iam-native-lost-ack-reconciliation-v1.yml` with
Docker/Compose, PostgreSQL 16, Python 3.12, installed project dependencies and
`alembic upgrade head`.

The opt-in environment is:

```bash
export LAB_NATIVE_DURABLE_PG=1
export LAB_NATIVE_LOST_ACK=1
export LAB_REPORT_DIR=artifacts/isolated-enterprise-iam-native-lost-ack/latest
bash scripts/enterprise_iam_lab/run_native_docker.sh
```

The same-host verifier is restricted to this synthetic IAM fixture, exact
source SHA and local target ledger. Next required step is an independently
operated read-only mTLS reconciliation service with target-owned signed
observations and crash/restart/partition adversarial cases.
