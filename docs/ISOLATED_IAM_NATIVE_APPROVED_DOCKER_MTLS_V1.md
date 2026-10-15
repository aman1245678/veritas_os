# PR #2375 — Synthetic native authorization → real Docker mTLS IAM effect (V1)

**Status: bounded synthetic integration candidate. NOT ALLOW_01 PROVEN.**
No real customer IAM, production credentials, paid model/provider calls, or
production-capable executor are enabled.

## What is newly connected

Earlier PRs proved separate halves:

- **#2373** generated signed synthetic Human Approval, actual native
  authorization and atomic consumption, then a valid short-lived signed
  effect permit, but called the IAM target handler with a *mock TLS peer*.
- **#2374** exercised *real Docker internal networks and mTLS sockets*,
  exact target side permit verification, one grant and replay/negative
  denials, but obtained a pre-signed **transport-only** permit with no
  native authorization or approval consumption.

**#2375 does not substitute either proof.** The host-side disposable
`native_docker_issuer.py` builds a synthetic decision through real
`/v1/decide` and signed CDA, then invokes existing native policy,
authority signature and Human Approval signature verifiers. It calls
the actual `issue_iam_permit_after_native_consumption` function,
which calls the native single-use consumption store before it may sign
an effect-bound permit. The exact resulting Ed25519 permit is handed
as a bearer artifact to the physically separate scoped Docker
executor, which sends a real mTLS POST to the isolated IAM target
running `target_service.py`. The target independently verifies the
public key and target-specific claims and atomically commits SQLite
admin grant, permit ledger entry and success audit.

The target's pre-allow database must have zero grants and zero permit
consumptions. The trusted host verifier reads the target-owned DB
after the operation, checks the exact native permit ID, native
authorization ID, intent ID, request ID, TLS-executor actor, audit ID
and real `consumed_at` timestamp against the **Ed25519-verified permit
bytes** and the issuer's bounded receipt.

## Independent negative observations (same Docker target)

- scoped mTLS + **missing native permit** → 400 (before issuance,
  and no grants/permit-consumptions in target DB)
- untrusted agent attempting target private container IP → network
  unreachable/blocked (not an artificial service-stopped refusal)
- scoped mTLS + valid native permit → 201 with exactly one DB grant
- same permit replay → 409, no additional grant
- scoped mTLS + changed signed scope → 403
- scoped mTLS + permit signed by another key → 403
- certificate-less HTTPS client → TLS handshake denial
- mTLS client with valid permit but `unscoped-probe` identity → 403
- native permit TTL always at most 10 seconds; the real target clock
  must accept the permit during its actual validity interval
- issuer receipt self-assertions alone never count as proof; tampered
  receipts/signatures or mismatched target SQLite ledger are rejected
  by the independent verifier

## Isolation / key custody in this disposable test

- The ephemeral Ed25519 issuer PRIVATE key and synthetic native
  approval authority source are kept in a permission-restricted
  host-only temporary directory. That private key **is written to
  host disk for the duration of this lab**, protected only by host
  file permissions, and is explicitly deleted at teardown. It is NOT
  a production key service or KMS. This is a trust assumption, not
  verified resistance to host compromise.
- IAM target receives pinned public Ed25519 verifier key, its own TLS
  server key and a writable SQLite directory; no signing private key.
- Only the `scoped-executor` receives synthetic mTLS client
  credentials and signed permits. No issuer private key, target DB
  or verifier trust mount.
- Agent has neither client certificates nor permit mount nor the
  target's network. No published host ports; both networks internal.
- Only test-only explicit `LAB_ALLOW_MUTATIONS=1` and
  `LAB_TEST_PERMIT_GATE=1` are enabled in the **separate dedicated
  Docker compose**. The baseline default-deny compose and existing
  #2374 transport-only workflow are unchanged.
- The public Docker build may download pinned `cryptography` into
  an image; runtime containers sit on internal Docker networks
  without direct internet access. No billable provider services run.

## How to reproduce

On a disposable CI runner with Docker, OpenSSL, Python 3.12 and
`pip install -e ".[dev,signing]"`:

```bash
python -m pytest -q tests/quality/test_iam_native_docker_verifier_v1.py
bash scripts/enterprise_iam_lab/run_native_docker.sh
```

Dedicated CI:
`.github/workflows/isolated-iam-native-approved-docker-v1.yml`.

Only sanitized result JSON and source SHA are uploaded; **do not**
archive signing keys, certs, private native fixture capture, permit
bearer files, secrets or the target SQLite database.

## Explicit non-proofs

The native consumption store remains
`InMemoryAtomicAuthorizationConsumptionStore` with
`allow_in_memory_for_testing=True`. This is not independent
durable cross-process single-use enforcement. The host runner still
controls the signer, issuer and test environment. An attacker with
host privileges or signing key access could bypass the test issuer,
and independently submitted forged issuer-claim JSON is not a
trusted third-party audit.

Therefore this run can establish only:

**Synthetic native approval / atomic in-memory consume → issuer's
signed permit → segregated real Docker/mTLS executor → target-owned
single committed effect**, plus scoped local denials.

It does **NOT** establish production IAM security, a durable native
PostgreSQL consume-and-sign service, issuer-to-executor authenticated
delivery, complete credential/network bypass closure, independent
third-party validation, RECON_01, or `ALLOW_01 PROVEN`.

Next: replace test-only in-memory store with durable native PostgreSQL
consumption, create a service-isolated signer under real trusted key
custody, and add loss-of-response/reconciliation and adversarial
cross-container bypass proofs anchored to exact source and retained
independent evidence.
