# Synthetic native-approved IAM operation → target SQLite V1

**Status:** offline integration test candidate only. Do not promote this
report to PROVEN until exact-SHA CI artifacts and verification are inspected.

## What is exercised

- A local test subprocess invokes the existing real `/v1/decide` HTTP
  pipeline with a controlled synthetic IAM grant candidate and synthetic
  policy/KMS/Object Lock backends. The chosen action is explicitly
  `grant_admin_role` with `required_human_approval=True`.
- Its resulting genuine signed CDA is promoted via the native authority
  chain with exact synthetic IAM endpoint and scoped credential reference
  metadata (NOT actual credential material).
- The native issuer builds an authorization with signed synthetic
  authority evidence, verified synthetic human approval, a signed
  authorization decision and reviewed runtime-risk packet using existing
  real verifier code.
- The #2372 bridge calls the native atomic consume-only API and signs a
  separate target-bound short-lived Ed25519 permit only on success.
- The #2371 target handler, under explicit isolated test-only mutation
  flags, verifies the permit and commits exactly one synthetic grant,
  consumption ledger entry and success audit row in SQLite.
- A read-only test observer queries target-owned tables independently of
  issuer/handler return values.

## Negative cases

- Replaying an issued permit cannot create another grant.
- Re-consuming an existing native authorization is refused.
- Missing Human Approval is blocked before signing/consuming.
- Changed target endpoint is blocked before native consumption.
- Lost consumption store acknowledgement is treated as consumed/unknown:
  no effect permit is signed and the authorization is not reusable.

## Strict non-claims

This is **NOT ALLOW_01 PROVEN**. The end-to-end path runs locally
with a synthetic mTLS peer object and ephemeral test signing keys.
Its native authorization store is intentionally process-local and
activated only via `allow_in_memory_for_testing=True`.
No real mTLS handshake, inter-process network separation, trusted
production issuer key custody, durable PostgreSQL bridge deployment,
real provider IAM, or independent third-party replay has been proven.
The runtime Docker target stays default-off and no cloud service calls
or real IAM changes occur. All permissions apply exclusively to the
synthetic `contractor-001` target. The application bridge currently
accepts a signer and deployment pins as injected service inputs; this
does not establish secure runtime custody or independent provenance
of either input.

Next evidence gates: durable native consumption + isolated issuer,
credential-inaccessible agent and segregated scoped executor, actual
mTLS transport, target-owned snapshots, exact-SHA retained artifacts,
independent review, then full eight-case ALLOW/DENY/RECON matrix.
