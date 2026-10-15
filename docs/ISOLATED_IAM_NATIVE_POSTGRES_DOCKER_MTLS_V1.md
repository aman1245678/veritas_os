# PR #2376 — Native PostgreSQL consumption → isolated Docker mTLS IAM sink

**Status:** Implementation candidate. **Not proven until dedicated CI, target-ledger
validation and artifact review succeed at the final HEAD.** No actual enterprise
account, credentials, LLM provider, payment or customer effect is used.

## Exact scope

This deliberately reuses the existing implementation:

1. #2375's synthetic real `/v1/decide`, signed Human Approval, CDA and Native
   Bind Authorization issuance; existing `native_permit_bridge.py` performs
   fresh verification and authorizes **one** native consumption.
2. Existing `PostgresAtomicAuthorizationConsumptionStore` replaces the test-only
   process-local store when `LAB_NATIVE_DURABLE_PG=1` is explicit.
3. Existing native consume-before-sign rule creates the exact short-lived
   Ed25519 effect permit; no signer receives a caller-supplied `consumed=True`.
4. The **same** #2375 isolated Docker setup transfers only the permit to a
   scoped client, calls the IAM target using real mTLS, and commits exactly
   one synthetic role-grant in a **separate** target-owned SQLite database.
5. Trusted host-side verification reopens PostgreSQL **independently** and
   checks the one-row unique authorization/idempotency record, canonical
   record digest, consent linkage and ordering before the target's own recorded
   effect timestamp. Both DBs must match the Ed25519-verified permit's
   authorization ID, execution intent ID and request ID.
6. Six negative transport checks and replay are carried over from #2375.
   Original memory-only Docker mode and its archived evidence remain unchanged.

## How to run

In a dedicated ephemeral runner with Docker/Compose, PostgreSQL 16, Alembic,
OpenSSL and Python 3.12:

```bash
export VERITAS_DATABASE_URL="postgresql+psycopg://veritas:veritas_test@localhost:5432/veritas_test"
export LAB_NATIVE_DURABLE_PG=1
export LAB_REPORT_DIR=artifacts/isolated-enterprise-iam-native-postgres-docker/latest
alembic upgrade head
bash scripts/enterprise_iam_lab/run_native_docker.sh
```

The runner never mounts the native database connection or its credentials in
the agent, scoped executor or IAM target containers. It uploads **only**
sanitized bounded result JSON, never PostgreSQL state, SQLite DB bytes, signed
bearer permits, private signing keys or TLS certificates.

## Explicit remaining gaps

This is still **one disposable test host** controlling signer, DB and test
containers; PostgreSQL's single-use record is durable, but key custody,
network trust, and signer-to-scoped-executor delivery are not externally
authenticated production services. Native authorization consumption precedes
a separate effect and is **not** an atomic distributed transaction.
Crash-after-consume-before-effect and lost-acknowledgement require an
authoritative target-side reconciliation path; do not blindly mint a
replacement permit or retry the effect.

**Do not claim:** `ALLOW_01 PROVEN`, `RECON_01 PROVEN`, real customer IAM,
independent third-party validation, full infrastructure bypass resistance, or
new AgentDojo Utility improvement. No paid Provider or external effect is run.

## Next gates

- Introduce an independently operated issuer/key custody boundary.
- Prove lost-acknowledgement/restart and effect-state reconciliation against
  both durable native PostgreSQL ledger and target-owned receipt.
- Continue separate RCC/REVAS optimization without reducing authorization
  or Bind enforcement.
