# IAM-native consumption-to-permit bridge V1 (isolated, test-only)

## Exact boundary

`scripts/enterprise_iam_lab/native_permit_bridge.py` adds
`issue_iam_permit_after_native_consumption`. It does not accept an externally
constructed consumption result, a boolean such as `approved=True`, or a
request-supplied permit. It invokes the existing real
`consume_native_bind_authorization` API within the issuer boundary before
signing a narrowly scoped effect permit.

The issuer requires **deployment-owned** native lineage pins for execution
intent ID/hash, bind context hash and action contract digest. Before any
consume attempt, it verifies that native intent and policy explicitly match
`grant_admin_role`, policy allows `saas:grant_admin` and does not prohibit
admin, human approval is VERIFIED and has a signed artifact and proof digest,
and current endpoint is the isolated HTTPS IAM target at port 8443 and exact
synthetic role path. The real native consumption API then reconstructs signed
authority/approval evidence, checks current risk and revocation, and performs
an atomic single-use claim. Only the returned success from this specific
API invocation can reach the separate Ed25519 permit signer.

The permit is bound to the single synthetic IAM grant, carries the native
authorization ID, execution-intent ID and idempotency request ID, and uses a
deterministic permit ID derived from the returned consumption record ID plus
authorization hash. Permit expiry is the earlier of 10 seconds or the native
authorization expiry. The target in #2371 already verifies and atomically
consumes permits for the test-only IAM flow.

## Failure / recovery

A native consumption failure, stale risk, missing Human Approval or mismatch
must never call the permit signer. If consumption commits but acknowledgement
is lost, or signing fails after successful consumption, DO NOT silently retry
the authorization. Treat it as consumed/unknown and require independent
reconciliation. A resulting permit is **not** evidence that the target grant
was applied; only target-owned state can establish that.

## Key custody and production exclusion

The issuer's signer must be independently provisioned by a trusted service
outside agent access. Giving the signing key to an untrusted agent/executor
would invalidate the authority boundary regardless of these code checks.
The pinned deployment lineage MUST be reviewed independently, never chosen
or mutated by a candidate agent. The in-memory consumption store requires
an explicit test override and is not durable.

## Proof status

- Negative tests use **real native authorization and consumption verifier
  fixtures** for another synthetic action to establish that an unrelated
  signed authorization cannot mint an IAM permit. They also reject missing
  approval, altered deployment lineage and changed native claims.
- A **genuinely native-approved IAM grant artifact has not yet been generated**
  and exercised end to end. There is deliberately no false positive success
  claim from a mocked or transplanted approval.
- No Docker mTLS governed executor, external IAM provider, real credential
  access, effect dispatch, or independent completed ALLOW_01/RECON_01 proof
  is added in this PR.
- Target wiring and complete eight-case proof remain separate work.
