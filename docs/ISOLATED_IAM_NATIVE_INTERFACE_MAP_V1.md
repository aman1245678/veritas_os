# Native IAM integration — verified source interface map V1

**Status: interface discovery only; NO IAM effect execution.**
Baseline: `veritas_os` main merge `bc7967635562b805deabe25ad57dfca2b0f20c15`.

The prior preflight's UNMAPPED rows are **discovery gaps**, not evidence that native interfaces are absent. GitHub default-branch code search and file inspection located:

| Boundary | Actual source | Entry point / qualification |
|---|---|---|
| Native issuance | `veritas_os/policy/native_bind_authorization.py` | `issue_native_bind_authorization` |
| Native verification | same | `verify_native_bind_authorization` |
| Native consumption | `veritas_os/policy/native_bind_authorization_consumption.py` | `consume_native_bind_authorization`; module explicitly states it does not dispatch effects |
| Live-adapter governed invocation | `veritas_os/policy/live_adapter_bind_authorization_consumption.py` | `consume_live_adapter_bind_authorization_and_invoke_bind` |
| Atomic single-use store | `veritas_os/policy/live_adapter_bind_authorization_consumption_store.py` | `AtomicAuthorizationConsumptionStore`, `InMemoryAtomicAuthorizationConsumptionStore`, `PostgresAtomicAuthorizationConsumptionStore` |
| Effect state and recovery | `veritas_os/policy/bind_effect_runtime.py` | `consume_bind_record_lineage_and_effect_state`, `recover_in_flight_after_consumption` |
| Bind-time recheck | `veritas_os/core/continuation_runtime/bind_admissibility.py` | `evaluate_bind_admissibility` |
| Isolated IAM target | `scripts/enterprise_iam_lab/target_service.py` | mTLS + target scope, mutation disabled in #2363 infrastructure runner |

## Compatibility blockers before executable work
1. Establish whether native v2 issuance/verification/consumption and live-adapter invocation can share the same artifact, trust policy and consumption record **without converting or fabricating authority**. Their names alone do not prove interoperability.
2. Inspect function signatures, test fixtures and trust roots for every selected entrypoint; run dedicated unit tests with exact source SHA.
3. Determine correct governance/approval and reconciliation capability inputs, including revocation and expiry.
4. Map atomic consumption and crash recovery to the target's independent effect receipt; ensure retry never creates a second effect.
5. Implement the governed executor as the only holder of scoped client certificate and backend-network access; leave the existing infra-only `LAB_ALLOW_MUTATIONS=0` path unchanged.
6. Test ALLOW_01, DENY_01, DENY_05, DENY_06, RECON_01 against target-owned DB while preserving DENY_02/03/04.
7. Preserve evidence pinning, provenance and fail-closed behavior; do not report an end-to-end proof until observed.

## Nonclaims
This map confirms **source code entrypoints**, not their successful interoperability, correct trust configuration, production authorization or any synthetic IAM mutation. No paid provider or external API is authorized. A green documentation CI is not a proof of native authorization-to-effect.
