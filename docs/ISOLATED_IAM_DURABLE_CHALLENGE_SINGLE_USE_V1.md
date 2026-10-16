# #2382 — Durable challenge single-use bound to PostgreSQL effect CAS (candidate)

**DRAFT / opt-in synthetic, same-host engineering scope. Not production PROVEN.**

## Purpose
Extend merged #2381: an old signed acknowledgement must not be accepted under a
*different* challenge, and now the *same* challenge must not be consumed twice,
including after verifier restart. No new authorization is created. The original
synthetic IAM POST and signed Permit remain exactly once.

## Design and boundaries
- New Alembic 0011 `iam_reconciliation_challenges` stores SHA-256 of the
  256-bit challenge (not raw challenge), operation/authorization/consumption,
  original Permit ID, issue/expiry UTC, state and a signed evidence hash.
- Register only after the existing PostgreSQL `EFFECT_UNKNOWN` revision 2
  is observed; duplicate or expired registration fails closed. Challenge is
  not an effect authorization.
- The existing `reconcile_effect_unknown` algorithm and the signed
  Ed25519 target ACK/native consumption verifier remain in place.
- Only the opt-in `ChallengeBoundPostgresEffectStore.transition` coordinates
  the existing PostgreSQL `bind_effect_states` transition with `ISSUED`
  challenge consumption in **one database transaction**. Row lock + identical
  lineage + terminal CAS + conditional nonce update must all succeed.
  A crash rolls back both changes, or commits both. A unique partial index
  forbids more than one consumed nonce for an operation.
- Real dedicated Docker / mTLS / PostgreSQL workflow executes one allowed
  synthetic grant, records `UNKNOWN`, obtains a challenge-bound signed
  observation via the separate read-only reader, confirms
  `CONFIRMED_EFFECT`, then checks durable nonce consumption in a **new
  verifier process**. Re-registering the old nonce and eight simultaneous
  consumed-nonce CAS attempts must all fail.
- Legacy #2375–#2381 modes remain unchanged unless
  `LAB_DURABLE_CHALLENGE=1` and all prerequisite safety flags are present.

## Merge requirements
1. Final PR HEAD fixed and matched across all required CI runs.
2. Alembic upgrade 0010 -> 0011 succeeds on genuine PostgreSQL; baseline
   migrations and tests remain green.
3. Real Docker+PostgreSQL signed target receipt; registration precedes mTLS
   GET; signed target facts and original authorization lineage are verified.
4. Exactly one native PostgreSQL consumption, one synthetic IAM grant,
   `EFFECT_UNKNOWN -> CONFIRMED_EFFECT`, nonce `ISSUED -> CONSUMED`,
   and **zero** extra mutation or reissued Permit.
5. Duplicate nonce registration and concurrent replay on a fresh process
   refuse; evidence and nonce state survive restart.
6. Negative tests for malformed nonce/time, altered lineage, expired nonce,
   changed signed reply, absent PostgreSQL, and unsafe mode flags; previous
   #2381 verifier restrictions remain in force.
7. Redacted, SHA-256-verifiable artifact; no private keys, raw target SQLite,
   secrets, production credentials or billable Provider calls.

## Strict nonclaims / next work
The target, signing keys, registry and PostgreSQL still live on one disposable
CI host with host-controlled CA. This is NOT independent key custody, verified
external timestamps, separate remote operators, production replay immunity,
customer IAM, global network partition resilience, AgentDojo Utility recovery,
or `ALLOW_01 / RECON_01 PROVEN`. Clock uncertainty, certificate rotation,
signer revocation and independent operator supervision remain open.
Do not merge or report PROVEN from unit tests or green CI alone. Inspect the
actual redacted evidence, exact last HEAD and all inherited workflows.
Next: independent signer/operator and cross-host fault injection; then connect
RCC canonical candidate continuity from benchmark #416 into the native IAM
execution and receipt lineage.
