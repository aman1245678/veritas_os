# #2383 — Signed IAM source admission before Native Human Approval (synthetic)

**DRAFT, opt-in, same-host controlled-origin engineering proof. NOT RCC #416 execution, production IAM or an independent RCC signer.**

## Reason

Merged RCC #417 correctly refused to equate two different successful runs:
#416's local-counter candidate/ExecutionIntent and OS #2382's separately
created IAM role grant do **not** share authority or execution lineage.
Copying IDs or source receipts into a Permit would be an authority bypass.

#2383 introduces a NEW IAM-specific, signed **input-data admission** stage.
It cannot reuse #416's existing counter permission and it does not treat
original-request, candidate, scorer or RCC test success as execution authority.

## Opt-in path

The legacy #2375–#2382 Docker and native paths remain unchanged with
`LAB_SOURCE_BOUND_IAM_ADMISSION=0` (default).

With explicit `LAB_SOURCE_BOUND_IAM_ADMISSION=1`:
1. Fail closed unless all native PostgreSQL consume, lost ACK, target-signed
   read-only mTLS, challenge freshness and durable single-use CAS flags enabled.
2. A separate same-host **synthetic source fixture process** creates a
   **fresh Ed25519 key** and signs exact canonical origin JSON. The private
   origin key is host-private and never passed to native issuer / target.
   The signed origin includes: original request contents and SHA-256,
   candidate projection and SHA-256, IAM-specific action/subject/scope,
   actor, expiry up to 120s and a random source nonce.
3. Native issuer receives only a signed origin envelope and its selected
   verifier key. Ed25519, exact original request/candidate digests, nonce,
   clock, expected synthetic IAM effect/scope/actor are verified **BEFORE**
   constructing the Human Approval and native authorization. Independently
   captured real `/v1/decide` candidate projection must exactly match.
   A local-counter candidate, wrong actor/target, scorer-defined permissions,
   unsigned source input or expired data are refused.
4. The existing native signature/Human Approval/runtime scope check and
   PostgreSQL **single-use atomic consumption** remain unchanged. The
   new source-data signature does not satisfy the Human Approval requirement.
5. After native consume the service signs an additional evidence-only
   source->native ID map with its Ed25519 issuer key. That map binds the
   source request/candidate digests and source nonce hash to the actual
   native request ID, ExecutionIntent ID, authorization, consumption ID
   and signed IAM Permit ID. A separate verification process checks
   both the signed origin and the native issuer evidence map.
6. Exactly one isolated Docker/mTLS IAM effect is reconciled from real
   PostgreSQL EFFECT_UNKNOWN -> CONFIRMED_EFFECT against the read-only
   target-signed challenge reply and a single-use challenge ledger.

## Limitations that MUST remain visible

- The source signer is created in the same disposable CI host, not a remote
  RCC service. This is a new **IAM-specific controlled fixture**, not
  the original #416 local counter case and not fresh AgentDojo model data.
- The native Ed25519 source->authorization mapping is **signed evidence**
  recorded after durable consume. The existing target-facing Permit v1
  does not contain or cryptographically enforce the RCC source digest.
- No durable single-use source-attestation nonce ledger across distinct
  native authorization IDs, no independent operator key custody, no
  external trusted time, no real customer IAM, no paid Provider calls.
  Replay of a source attestation across fresh executions is NOT PROVEN
  impossible by this PR; only the underlying native authorization and
  target Permit/receipt have separately tested one-time semantics.
- #2383 does **not** demonstrate full original RCC #416 candidate -> native
  IAM execution, real matched Final128 Utility recovery, 0/128 fresh
  injection result, or production ALLOW_01 / RECON_01 PROVEN.

## Merge prerequisites

- Final exact PR HEAD all inherited + dedicated GitHub workflows green.
- Dedicated real Docker/mTLS+PostgreSQL run proves one permitted synthetic
  IAM grant, one native consumption, signed origin admission, fresh
  independently verified native ID bridge, one challenge consumption,
  one confirmed effect, zero duplicate mutations and zero Permit reissues.
- Negative source signature, scope, action, candidate, approval, time,
  trust/key and false production claims rejected before authorization.
- Sanitized redacted artifact, SHA-256 ZIP & manifest checked; no private
  signing keys or live customer credentials included.
- No modification to original #416 fixture, historical frozen corpus or
  RCC/REVAS scorer/gold authority. CI green is never production PROVEN.

## Next implementation

A separately operated, explicitly trusted RCC bridge must supply a real
IAM-scope original request/candidate attestation with independent key
custody and source replay prevention. The native issuer must commit its
digest into the authorization/Permit identity, and the target must check it
against an independently trusted policy before executing. Then validate
one genuinely shared request -> IAM operation -> signed receipt trace.
Only after that revisit paired Final128 Utility vs 92/128 and injection 0.
