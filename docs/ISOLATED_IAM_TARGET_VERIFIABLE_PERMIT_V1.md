# Isolated IAM target-verifiable permit boundary V1

Status: DESIGN CONTRACT — NOT IMPLEMENTED, NOT PROVEN.

## Security invariant

A target mutation MUST require more than an mTLS certificate, a locally
configured scope, an environment toggle, or a client-supplied success flag.
The target must validate an authorization permit that is cryptographically
bound to the exact intended effect and is non-replayable.

## Required permit and verification

- A VERITAS-controlled signing identity, with the verification key pinned
  by the target, not the agent or effect caller.
- Canonical binding: method POST, exact target path, role=admin, subject,
  scope=saas:grant_admin, authorization_id, execution_intent_id, request_id,
  validity interval, issuer key ID, and audience=isolated-iam-target.
- A permit MUST be issued only after verified human approval, current
  policy/authority checks, and successful atomic single-use authorization
  consumption. Native consume-only success is NOT itself a dispatch permit.
- Target validates signature, audience, clock, target, action, actor scope,
  and a durable unique permit ID before committing any effect.
- Target records permit consumption, effect and audit outcome atomically in
  its own SQLite transaction. Concurrent requests cannot both commit.
- Invalid, missing, expired, mismatched, or replayed permits MUST fail
  before the target grant changes.
- If the caller loses its response after commit, reconciliation MUST read
  target-owned state and avoid issuing a second effect.

## Isolation

The agent has no effect network route, target signing key, scoped mTLS
credential, Docker socket, or access to the target DB. Only the governed
executor may access the target effect network and its scoped mTLS identity.
The signing key is not held by the executor. A permit cannot be generated
from possession of the scoped credential alone.

## Evidence gates

ALLOW_01: exactly one verified permit causes exactly one target grant.
DENY_01: absent/invalid approval creates no permit or effect.
DENY_02: agent network cannot reach target.
DENY_03: untrusted client TLS denied.
DENY_04: authenticated unscoped client denied.
DENY_05: replay of consumed permit has no effect.
DENY_06: changed target, scope or body has no effect.
RECON_01: independent read-only observer confirms one grant and one
committed permit ID, with correlated receipts.

All results must include exact checkout SHA, target snapshot hashes,
audit entries, permit ID, outcome, and artifact manifest. No secrets in
artifacts. Keep mutations OFF until implementation and negative tests
pass. External provider calls and customer IAM changes remain forbidden.

## Implementation sequence

1. Specify versioned canonical permit envelope and issuer/target trust
   roots; never equate native authorization artifact with a target permit.
2. Implement governed issuer bridge from native atomic consumption to
   effect-bound permit issuance, with crash/recovery semantics.
3. Implement target-side signature, replay and transaction enforcement.
4. Implement isolated Docker executor with restricted key/credential mounts.
5. Run and independently verify the complete eight-case matrix.

No passing CI on this document can be interpreted as ALLOW_01 proof.
