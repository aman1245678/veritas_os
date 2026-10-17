# #2385 — External RCC-shaped IAM source import with out-of-band trust pin

**Draft, import-side contract only; independent Ben/RCC operator execution NOT YET PROVEN.**

## Why

Merged #2384 showed synthetic target-side enforcement of a source-signed
IAM-only request/candidate in Permit v2 with durable target source nonce
uniqueness. Its Ed25519 source private key was still minted on the same CI
host that ran VERITAS. The next trust boundary is a *signed upstream IAM*
request/candidate supplied by an operator other than VERITAS.

This PR implements a **fail-closed external input entrypoint**, not an
external operational achievement. It intentionally does not call Ben,
acquire his private key, use the old #416 local-counter candidate, promote
RCC scorer outputs to IAM authority, or mint an external signing key.

### Safe opt-in interface (isolated disposable test system only)

Provide operator-approved files and **independently distributed** trusted
SPKI SHA-256 through process environment, **not** by reading the fingerprint
from the attacker-controlled attestation:

- `LAB_RCC_EXTERNAL_SOURCE_MODE=1`
- `LAB_RCC_SIGNED_SOURCE_FILE=/absolute/path/to/external-iam-signed.json`
- `LAB_RCC_PUBLIC_KEY_FILE=/absolute/path/to/preapproved-ed25519-public.pem`
- `LAB_RCC_TRUST_SPKI_SHA256=<64 lower-case hex SHA256 of DER SubjectPublicKeyInfo>`

This opt-in requires the full existing #2384 source-bound target v2 mode:
`LAB_SOURCE_BOUND_IAM_ADMISSION=1`,
`LAB_TARGET_SOURCE_BOUND_PERMIT=1`, real native PostgreSQL,
loss-of-ACK, signed mTLS read-only challenge and one-use CAS.

In external mode, the launch script **must not** call
`prepare-synthetic-origin`. Before Docker starts, it separately
checks the supplied public Ed25519 key against the pinned digest,
then verifies exact signed IAM request/candidate schema, action/scope,
origin payload hash, freshness, nonce and targeted resource.

The external signed payload is temporarily stored in the private host
scratch directory, **not** uploaded as a GitHub Actions Artifact.
Only hash-based redacted preflight report and actual native/target
verified evidence may be retained. No external private key is read or
copied. Its public key is mounted read-only to the Docker target.

Native authorization issuer independently **rechecks the pin** before
Human Approval/one-use consumption. The target validates that pinned
SPKI independently of the issuer's own valid Permit v2 signature and
before the synthetic IAM mutation. The target continues to enforce
source nonce uniqueness in its SQLite ledger and source digests in its
signed Permit v2. Existing #2383/#2384 same-host synthetic paths are
unchanged by default.

## Why this is NOT an independent RCC proof

- The current compatible schema is
  `rcc-controlled-synthetic-iam-origin/v1`. It is a synthetic-only
  IAM-specific shape with no Ben-controlled upstream evidence.
- The external file and key can be supplied by a single local test
  process; we have no evidence here that keys were generated/custodied
  by Ben, on independent RCC infrastructure, or in a separate trust
  domain. A configured fingerprint alone cannot prove operator
  independence or that RCC's actual candidate generator chose the action.
- No real independently hosted RCC endpoint, key rotation/revocation
  evidence, approval provenance from a buyer, customer IAM, distributed
  replay ledger, third-party auditing, or scored Final128 held-out
  measurement was executed.
- The Ed25519 signed source is *data provenance*; it never substitutes
  for fresh native Human Approval, action-specific authority or native
  PostgreSQL one-use consumption. Old #416 local-counter authorization
  MUST NOT be promoted to `saas:grant_admin`.
- No new paid Provider/API calls or production-level claim is authorized.

## Evidence gates

PR dedicated workflow runs **offline/negative preflight tests only**.
It generates adversarial test signer fixtures locally, deliberately
labels them **NOT independent RCC**, and performs **zero Docker IAM
effects**. Existing #2384 CI remains the authority for the separate
same-host source-bound target v2 execution.

For a real independent-source claim, require an actual independently
controlled signing key, agreed key fingerprint transferred out of band,
a *new IAM-specific actual RCC candidate* with source-hash/decision
lineage and operator receipts, distinct execution process/host and
exact same-run native Human Approval → Permit v2 → signed target ACK →
durable reconciliation. Reconfirm no source nonce reuse or altered
scoring authority. Only then promote a source-bound cross-repo PROVEN.

## Contract for Ben / peer operator (future, needs their agreement)

1. Independently generate and own an Ed25519 source signing key, share
   the public SPKI and SHA-256 through a trusted agreed channel.
2. Align on a new genuine RCC IAM-request schema/fixture, including
   actor, target, requested action/scope, canonical candidate digest,
   expiry and unique source nonce. The present `synthetic-iam-origin/v1`
   shape is only a compatibility test input and cannot claim authentic
   RCC model output or #416 authorization.
3. Generate one source-signed, fresh IAM-specific request/candidate,
   with original upstream request/candidate lineage and a signed
   peer receipt. Transfer the signed artifact without private keys.
4. Agree on explicit local user/owner approval before import, immutable
   exact commit pins, replay policy, scope and test-only credentials.
5. Both parties independently reproduce the source→native→target chain
   and retain exact signed evidence under distinct custodians.

This PR does not send that request to Ben. A message or agreement is a
separate explicit user action. Merge requires verified CI and human
approval; do not claim independent operator validation from CI alone.
