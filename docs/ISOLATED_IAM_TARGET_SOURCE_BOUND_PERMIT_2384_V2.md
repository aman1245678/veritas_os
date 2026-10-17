# #2384 — Target-enforced synthetic source-bound IAM Permit v2

**Status: DRAFT. Opt-in, disposable same-host Docker + real local PostgreSQL.
Not a real independently operated RCC attestor, production IAM, or Final128 re-score.**

## Why this matters

#2383 verified a freshly signed **synthetic IAM-specific** original request and
selected candidate *before native authorization issuance*, but its post-consume
signed mapping was **evidence-only**. The v1 executable Permit did not commit
to that source or require the target to check the original request signer.

#2384 adds an explicit new Permit **v2** at the native-consumed-to-target seam:
- Existing native Ed25519 Human Approval, verified runtime authorization and
  durable PostgreSQL **single-use consumption happen first**; source signatures
  are INPUT PROVENANCE only, never native execution authority.
- The **issuer's signed v2 Permit** contains exact original request SHA-256,
  candidate SHA-256, source envelope/payload SHA-256, source nonce SHA-256 and
  the separately **source-signed original request and candidate envelope**.
- The **Docker IAM target** requires **both** pinned Ed25519 signatures
  (trusted Permit issuer and a separately pinned source public key). It checks
  source validity, exact IAM actor/target/scope/role, the original request,
  candidate, signed commitments, permit payload and freshness **before mutation**.
- Target SQLite atomically enforces one effect per native authorization/Permit
  **and per source nonce digest**, even if a different native authorization or
  Permit ID is used. Its source nonce column is UNIQUE.
- A truly issuer-signed legacy v1 Permit is denied over real mTLS **before**
  the allowed v2 effect in the dedicated workflow; bad/foreign signer/modified
  permit, unscoped client, no client cert and replay are also denied.
- Lost ACK remains unobserved (never assume success, never retry); the
  separately signed target read-only challenge receipt and original native
  PostgreSQL effect state are reconciled with an atomic CAS.
- Opt-in flags: `LAB_TARGET_SOURCE_BOUND_PERMIT=1` and the entire #2383 +
  #2382 native PG, signed ACK, durable challenge, mTLS mode. Existing v1 flows
  remain the default.

## Explicit limitations

1. **The source remains a same-host ephemeral synthetic signer**, not Ben's
   independent RCC service or AgentDojo candidate. It is an IAM-specific
   controlled fixture; the old #416 local-counter authority is not reused.
2. The origin public key is host-pinned before startup and the private key stays
   outside Docker. This proves separate cryptographic keys within the *same
   host operator trust boundary*, NOT independently managed key custody or
   real remote-source provenance.
3. Target source-nonce uniqueness persists **only within its single disposable
   SQLite target ledger**. No demonstrated distributed ledger, cluster-wide
   nonce consensus, whole-host crash durability, source revocation propagation
   or independent remote multi-host replay resistance.
4. The existing #2383 source-to-native receipt remains a separate historical
   evidence schema; the v2 executable Permit now carries independently
   target-verified commitments but doesn't retroactively turn that older
   receipt into a target attestation.
5. CI green is bounded synthetic authority-to-consequence proof, **NOT**
   production / customer IAM security, independent validation, certification,
   new real Final128 matched-corpus Utility, or an approved paid Provider call.

## Evidence acceptance

Dedicated workflow: `.github/workflows/isolated-iam-source-bound-target-2384.yml`.
Expected evidence must show:
- Exact PR HEAD and all workflows green, independent offline negative tests.
- Target v2 only and the valid signed v1 downgrade denied *before* effect.
- One native PostgreSQL authorization consume, one target IAM grant, one unique
  source nonce consumed, no duplicate POST or Permit reissue.
- Signed mTLS target challenge, durable PG
  `EFFECT_UNKNOWN -> CONFIRMED_EFFECT`, no target SQLite read by remote
  reconciliation operator and no cross-host proof claim.
- Sanitized evidence ZIP plus `manifest.sha256`; no private signing key,
  real employee/customer identity or confidential production receipt.

## Next boundary after merge

The remaining highest-risk work is **actual independently operated RCC
IAM-specific original request/candidate capture**, verifiably pinned source
trust/key rotation/revocation, external origin evidence, multiple-host nonce
custody, and then one real joint source→native→target trace. This PR must not
be cited as having closed those gates.

Source chain: benchmark [#416](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/416)
(local counter), [#417](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/417)
(false join denial), OS [#2382](https://github.com/veritasfuji-japan/veritas_os/pull/2382)
(native PG/signed mTLS/target effect), OS [#2383](https://github.com/veritasfuji-japan/veritas_os/pull/2383)
(signed synthetic source admission).
