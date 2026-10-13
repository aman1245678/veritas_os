# Isolated IAM V1 — native VERITAS authorization integration preflight

**Status:** CONTRACT / NOT EXECUTED. Follow-up to merged PR #2363.

## Confirmed baseline at merge `6ffd6def9f20a45db537d992df7be0449ded7c04`
- `scripts/enterprise_iam_lab/target_service.py` independently enforces TLS client identity and a local `saas:grant_admin` scope. Mutations default to **OFF** (`LAB_ALLOW_MUTATIONS=0`); enabling them without governed execution is forbidden.
- `scripts/enterprise_iam_lab/run_infra.sh` and `verify_infra.py` demonstrate DENY_02 network isolation, DENY_03 missing client certificate and DENY_04 insufficient target scope, with target-owned database evidence.
- `veritas_os/core/continuation_runtime/bind_admissibility.py` exports `evaluate_bind_admissibility`. Its own docstring says it is a pure fail-closed recheck and **does not generate decisions or execute effects**. Its eligible recommendation is not itself authorization.
- The guessed path `veritas_os/core/continuation_runtime/bind_authorization_consumption.py` is **not present** at this merge. This is not evidence that no native consumption implementation exists elsewhere.

## Interface discovery gate — must be completed before executable integration
For each boundary below, find the actual upstream implementation and a passing targeted test; record import path, callable, input/output contract, trust owner, durable store and commit/source hash. Mark missing interfaces **BLOCKED** rather than emulating them with test-only HMAC tokens.

| Boundary | Required property | State |
|---|---|---|
| Decision/authorization issuance | Actual VERITAS issuer; exact subject, target, operation, scope and expiry | UNMAPPED |
| Approval verification | Verify genuine trusted approval and freshness, not request-provided boolean | UNMAPPED |
| Authorization verification | Cryptographic identity/audience/subject/target/scope/expiry checks | UNMAPPED |
| Bind-time recheck | `evaluate_bind_admissibility` with trusted live inputs | IDENTIFIED, NOT WIRED |
| Atomic one-use consumption | Durable consume before dispatch; concurrency/crash/retry semantics | UNMAPPED |
| Governed executor | Sole holder of scoped mTLS credentials; separate agent/effect networks | SPECIFIED, NOT WIRED |
| Target-owned receipt and reconciliation | Independent target database snapshot, exact request and authorization lineage | PARTIAL INFRA ONLY |

## Next executable slice acceptance
1. Preserve #2363's three observed denials and existing fail-closed verifier.
2. Add a governed executor only after identifying the native issuer/verifier/consumer. Do **not** set `LAB_ALLOW_MUTATIONS=1` in the infrastructure-only runner.
3. Prove `ALLOW_01`: one valid native authorization, one durable consumption, exactly one target-owned synthetic grant, matched receipt.
4. Prove `DENY_01` missing approval, `DENY_05` consumed replay and `DENY_06` target/scope substitution each yield zero **additional** effects.
5. Prove `RECON_01` using a read-only target-owned database snapshot, not only an executor-reported response.
6. Include negative tests for tampering, concurrency, stale TTL and a crash window between consumption and effect. If the current runtime cannot safely reconcile that window, block promotion and state the gap.
7. Pin Git commit and exact embedded module hashes; retain a sanitized evidence manifest, per-case decisions, target audit and JUnit at the exact tested SHA.

## Nonclaims
This preflight does **not** implement or execute native authorization, live enterprise IAM, production cloud controls, external provider inference or real customer effects. It does not authorize paid APIs. Green CI for this document is not `PROVEN` for ALLOW_01 / DENY_01 / DENY_05 / DENY_06 / RECON_01.

## Release rule
Do not merge an executable authorization/effect PR without independently checking exact-SHA CI artifacts and confirming the target DB effect count. Maintain `AI intelligence != execution authority`.
