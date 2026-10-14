# Isolated IAM target permit consumption (test-gated component)

**Status:** target-handler plus SQLite integration tested offline; **NOT**
native VERITAS authorization integration, governed executor, Docker e2e,
or production claim. This work cannot establish ALLOW_01 / RECON_01.

## Activation and trust boundary

The IAM target still defaults to rejecting every mutation. Successful
synthetic commits require all of these target-owned settings:

- `LAB_ALLOW_MUTATIONS=1`
- `LAB_TEST_PERMIT_GATE=1` (explicit **test-only** activation)
- `LAB_PERMIT_VERIFIER_PEM=/path/to/pinned-ed25519-public-key.pem`
- `LAB_PERMIT_ISSUER=isolated-iam-test-issuer` (default test issuer)

The public verification key must be provisioned outside any agent/caller
writable mount. No signing private key is read or accepted by the target.

The request has JSON content-type and body
`{"role":"admin","permit":{"payload":{...},"signature":"..."}}`.
Only the exact synthetic target, role, method, scope, subject, and
audience in `signed_permit.EXPECTED` are admissible. The TLS client
must independently carry the pinned `scoped-executor` role scope.
Malformation, untrusted signature/issuer, wrong operation, and expired
permit are denied before target changes.

## Atomicity

SQLite `BEGIN IMMEDIATE` serializes the grant, success audit row, and
durable permit consumption. Unique `permit_id`, unique
`authorization_id`, and unique target grant prevent repeat effects.
An internal ledger/audit write error rolls back the whole transaction.
A lost response after COMMIT should be reconciled against target-owned
`grants`, `permit_consumptions`, and `audit`.

Offline tests exercise the real handler and SQLite transaction using a
synthetic TLS-peer fixture, temporary Ed25519 keys, and a disposable DB.
They cover replay concurrency, wrong keys, tampering, mismatched effect
bindings, expiry, missing verifier, malformed requests and rollback.

## Non-claims / remaining gates

- The test signer can mint synthetic permits without VERITAS approval.
  There is no trusted bridge from native consume to permit issuance.
- The existing isolated Docker infra image remains in default-deny
  mode; it does not yet provision the cryptography runtime, trusted key
  mount or governed executor for this enabled test path.
- No real mTLS session, Docker network, provider API, external IAM or
  human approval has been exercised by this target-handler test.
- Neither ALLOW_01 nor any external bypass-resistance case is PROVEN.
- Follow-up: trusted issuer bridge, key isolation, disposable Docker
  executor, eight-case runtime matrix, exact-SHA retained evidence,
  independent observer reconciliation.
