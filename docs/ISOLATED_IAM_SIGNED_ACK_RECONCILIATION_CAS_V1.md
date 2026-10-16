# #2380 — Target-signed Docker mTLS acknowledgement → native PostgreSQL reconciliation CAS

**Candidate status: DRAFT until final-source full CI + dedicated Docker+PostgreSQL job succeed.**

**Bounded claim:** Existing native signed approval / PostgreSQL consumption
and the #2377 lost-ACK unknown state are reconciled to CONFIRMED_EFFECT by
the existing `reconcile_effect_unknown` CAS, using the **#2379 target-signed
receipt obtained by a separate mTLS reader**. The new Reconciliation path
has **no target SQLite path, mount or SQL connection**. It does not mint
or reissue the original authority.

## Inherited trusted boundaries

- **#2375:** `/v1/decide`, synthetic signed Human Approval/native
  authorization, short-lived signed Permit, real Docker/mTLS effect, target
  local SQLite atomic permit consumption.
- **#2376:** real PostgreSQL atomic native one-time consumption and exact
  original authorization/intent/request linkage to one target effect.
- **#2377:** after one scoped mTLS POST whose HTTP response is deliberately
  **not read**, record `EFFECT_UNKNOWN` durably from `IN_FLIGHT`. No
  duplicate POST or additional Permit.
- **#2379:** a separate `CN=reconciliation-reader` Docker container
  obtains the original target-owned COMMITTED audit/permit/grant receipt
  over an authenticated mTLS GET. That receipt is Ed25519-signed with
  a DIFFERENT target key, carried to a host-side verifier. The reader has
  no SQLite, effect Permit or signing private-key mount.

## What's new in #2380

- Explicit `LAB_NATIVE_SIGNED_ACK_RECONCILE=1` requires
  `LAB_NATIVE_DURABLE_PG=1`, `LAB_NATIVE_LOST_ACK=1`,
  `LAB_TARGET_READONLY_ACK=1`, no process-restart profile. Any invalid
  combination fails closed; all older profiles retain their exact defaults.
- Fresh Python process `reconcile_signed_target_ack.py` takes ONLY bounded
  report JSON, original signing public key, original signed Permit, target
  public receipt signer key and Docker topology config. **No target DB path.**
- Independently recheck the original Native issuer's Permit signature,
  exact authorized action, the signed target's COMMITTED receipt signature,
  separate signer identity, subject/actor/action, authorization/intent/request,
  target commit time within the Permit time window, and actual native
  PostgreSQL consumed-row digest and unique key/authorization linkage.
  The new evidence digest covers both receipt fields **and signature**.
- Independently enforce #2379 reader service topology and all three denial
  cases (wrong mTLS reader scope, no client certificate, unknown effect).
  Unknown target evidence is NEVER transformed into confirmed no-effect.
- Pass `CONFIRMED_EFFECT` to the existing
  `reconcile_effect_unknown` verifier protocol and PostgreSQL CAS.
  Reconciliation verification repeats signature and PostgreSQL lineage
  checks at the moment of CAS. Confirm terminal state revision 3 with
  cryptographically bound evidence hash, and reject a second terminal update.
- The **legacy independent final fixture audit** still directly checks
  target-owned SQLite and PostgreSQL outside the new reconciliation
  authority path. This is deliberate test cross-checking; do not confuse
  it with how the new signed-only verifier reaches its decision.

## Fail-closed negative tests

Altered target signature, substituted receipt fields, wrong authorization,
wrong execution intent/request, wrong native consumption, invalid/native
time ordering, fake no-effect, missing PostgreSQL consumed-row, absent
target receipt, revoked/absent read-only client identity, missing target
record and forged proof claims must not result in terminal confirmation.
No retry or Permit renewal is attempted.

## Nonclaims and limits

- **Single disposable CI host:** it generates both test keys and controls
  Docker/SQLite/PostgreSQL. This is **not independently operated remote
  attestation** or secure production key custody; mTLS is real but on
  one host's isolated Docker networks.
- #2379's signed response binds immutable target effect details but has
  **no nonce or trusted remote freshness challenge**. This PR cannot
  prove replay resistance of target acknowledgement across hosts/sessions,
  stronger external time provenance, or key revocation.
- The lost ACK is an **intentionally unread HTTP response**, not genuine
  packet loss, crash/power failure, network partition or PostgreSQL outage.
  #2378 tested a different same-host SIGKILL path, not this combined path.
- **No real cloud IAM/customer effect, paid LLM, third-party validation,
  official AgentDojo Final128 scoring, cross-system atomicity or
  production credential storage** is demonstrated. Nothing here upgrades
  `RECON_01` / `ALLOW_01` to `PROVEN`.
- Absence of a signed COMMITTED receipt means **UNKNOWN**, never
  `CONFIRMED_NO_EFFECT` or implicit authority to re-dispatch.
- All source/CI/result claims must be verified at the exact final PR HEAD;
  CI green alone is not an independently operated proof.

## After this bounded gate

Introduce independently operated target key custody and an approved verifier,
add a challenge-bound target response with freshness and revocation checks,
then execute real cross-operator mTLS tests with network partitions and
state-loss fault injections. Keep every step's source/receipt pinned and
require external reviewer validation before any production claim.
