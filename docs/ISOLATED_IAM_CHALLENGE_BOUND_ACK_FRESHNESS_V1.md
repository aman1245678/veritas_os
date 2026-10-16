# #2381 — Challenge-bound target-signed IAM acknowledgement freshness V1

**DRAFT / synthetic disposable host only. Not production PROVEN.**

## Objective

Prevent a **previously signed, perfectly valid target COMMITTED receipt**
from being accepted for a **different, newly registered reconciliation
challenge**. Preserve #2380 signed mTLS → durable PostgreSQL
`EFFECT_UNKNOWN → CONFIRMED_EFFECT` CAS without additional target effects,
native authorization consumption, or execution Permit issuance.

## Opt-in envelope and run conditions

- Only with `LAB_TARGET_ACK_FRESHNESS=1` AND `LAB_NATIVE_DURABLE_PG=1`,
  `LAB_NATIVE_LOST_ACK=1`, `LAB_TARGET_READONLY_ACK=1`,
  `LAB_NATIVE_SIGNED_ACK_RECONCILE=1`, no process-restart profile.
- The host-side verifier workflow generates a cryptographically random
  256-bit lowercase hexadecimal challenge **after durable UNKNOWN exists**
  and before the read-only mTLS GET. It writes a non-authorizing challenge
  record containing the exact target Permit ID, issue timestamp and UNKNOWN
  status to a private test report and the isolated read-only reader mount.
- The separate, restricted `CN=reconciliation-reader` Docker client queries
  `GET /v1/iam/reconciliation/{canonical-percent-encoded-permit-id}?challenge={64-lowercase-hex}`.
  Invalid, missing, duplicated or noncanonical challenge parameters are
  refused before consulting or signing a target observation. The existing
  mTLS identity requirement remains.
- Only the target container accesses its SQLite ledger to read the
  committed effect. If it cannot confirm that effect, it returns 404,
  **never signed CONFIRMED_NO_EFFECT**.
- New opt-in, versioned target Ed25519 acknowledgement
  `isolated-iam-target-committed-ack/v2-challenge` binds the original v1
  effect and audit fields, the exact submitted verifier challenge,
  `target_observed_at`, and `target_expires_at` to a **single signature**.
  The signed observation validity bound is at most **120 seconds**.
- The independent reconciliation Python process checks the exact previously
  registered challenge, signed target key, v2 schema, bounded target
  timestamps, original Permit and native PostgreSQL lineage, actual
  `EFFECT_UNKNOWN`, dedicated reader topology, refusal probes, and current
  PostgreSQL consumption before calling unchanged CAS. An old signed
  acknowledgement with a different challenge, a v1 receipt, changed
  signature, expired/future timestamp, missing receipt or altered
  authorization/intent/request cannot confirm the effect.
- The new proof identity and policy hash distinguish the challenge-bound
  verifier from #2380. Original #2379/#2380 profiles remain strict,
  default-off and unchanged at rest.

## Important limits and nonclaims

- The host **controls the two signing keys**, test CA, target, mTLS reader,
  PostgreSQL and network; they all run on one disposable CI host.
  This is not third-party custody, independent operations or remote
  production attestation.
- The target signs client-supplied challenges without a durable server-side
  nonce-consumption ledger. This proves rejection of old signed receipts
  under a **different challenge**, but **not** strict single-use of the
  same challenge/receipt, whole-system anti-replay, or protection from a
  fully compromised host/signing key. Do not claim global replay immunity.
- Target/host timestamps assume approximately synchronized clocks within
  the disposable CI environment. The target signs a bounded 120-second
  validity interval. This is NOT independently witnessed trusted time.
- No key revocation, independent pinned certificate roll-over, truly
  remote operator, network partition, host power loss, production IAM
  change, billable Provider, real customer or official AgentDojo Final128
  scorer. `RECON_01` and `ALLOW_01` remain NOT PROVEN in production.
- The final independent fixture audit may still inspect target SQLite to
  cross-check the test effect, but **the new #2381 reconciliation authority
  code has no SQLite credential/mount/DB path**.
- No signed absent-effect reply, no unsafe permission to retry or redispatch.
  If no fresh, matching, signed and verified effect exists: UNKNOWN.

## Merge gate

Require the final PR head to pass the new dedicated
`isolated-iam-challenge-bound-reconciliation-v1.yml` with real
Docker+mTLS+PostgreSQL, fresh challenge/target signature, 3 negative access
probes, adversarial old-ack replay rejection, bounded expiry, exact original
consumption and hash, 1 target effect, durable CAS to `CONFIRMED_EFFECT`,
immutable terminal state, 0 retries/reissuances, and a verified SHA-256
manifest. Also require all legacy #2375–#2380 workflows and full CI green.

Next genuinely independent gate: separately operated signer/reader and
approved CA, challenge registry with atomic one-time consumption, trusted
timestamps/key revocation and real cross-host fault injection.
