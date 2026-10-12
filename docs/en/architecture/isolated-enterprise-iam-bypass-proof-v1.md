# Isolated Enterprise-IAM Bypass Proof V1 — Experiment Contract

**Status: SPECIFICATION ONLY — NOT EXECUTED / NOT PROVEN.**  
**Rule-of-One:** `EXTERNAL_ENFORCEMENT_DENIES_UNGOVERNED_IAM_MUTATION`  
**Frozen machine-readable contract:** [`contracts/isolated-enterprise-iam-bypass-v1.json`](../../../contracts/isolated-enterprise-iam-bypass-v1.json)

## Why a new experiment

The [controlled Decision-to-Effect E2E](../../../artifacts/real-decision-to-effect-e2e/README.md) proves a bounded positive execution and reconciliation path with real TLS and PostgreSQL but synthetic credentials and effects. The [BCBR V1 closure record](bind-coverage-bypass-resistance-v1-closure-record.md) covers three frozen VERITAS-owned dispatch paths, process-locally, at its separately audited SHA. Neither demonstrates that **an independent enterprise-like IAM target** rejects a request which bypasses VERITAS.

This experiment adds one missing assertion: **the target and infrastructure must enforce the authority boundary independently of the agent and the VERITAS process**. Recording a VERITAS `DENY` without attempting direct effect is not sufficient.

## Frozen action (one only)

- Synthetic `POST /v1/iam/users/contractor-001/roles` with exact JSON body `{"role":"admin"}`.
- Required action scope: `saas:grant_admin`.
- Target: disposable, local enterprise-like IAM API with target-owned durable storage and append-only-ish test audit records (not a real cloud identity provider).
- Expected legitimate business effect: **exactly one** transition from a non-admin user to admin. There must be **no additional role mutation** from any negative probe.
- VERITAS candidate: reuse or adapt the repository's existing [SaaS permission-change governance evaluator](../demo/saas-permission-change-governed-demo.md). Its current fixed-date/fixture approval is **not** acceptable as production authority; any future runtime adapter must document verifier provenance and expiry.

## Required same-environment topology

```text
agent (untrusted) -- agent_net --> VERITAS + governed executor
        X                              |
        X no effect route              | ephemeral scoped executor identity
        X no target credential         | + authorization consume
                                       v
                                  effect_net (private)
                                       |
                              independently enforced
                              mTLS + target-side RBAC
                                       |
                           synthetic IAM mutation API
                                       |
                          target-owned durable state
                                       |
                          read-only independent observer
```

- **Agent:** connected only to `agent_net`; no Docker socket, host networking, target database credentials, executor bearer material, client private key or CA signing key.
- **Executor:** separate trusted process on both networks; its secrets are injected per run and not distributed to the agent. It must rely on a valid, single-use VERITAS authorization bound to method, body, target, audience and scope *at execution time*, not merely on a claim in the HTTP body.
- **Target:** only `effect_net`; no published host port. Independently rejects untrusted client identities and identities without permission to grant the exact role. A self-declared `authorization_id` supplied by the caller is not target authority.
- **Observer:** independent read-only snapshot of target state before and after each scenario, plus separate network/runtime observations. It cannot mint a valid execution credential or write an effect.
- **Runner:** disposable Docker Compose project + unique networks, ephemeral CA and secrets, all started and destroyed within one run. A reachable negative probe may be deliberately attached to `effect_net` to test target policy **after** network isolation is tested; this is a distinct attacker capability and must be labeled as such.
- A container network topology alone is **not IAM**; local mTLS identity and target-side scoped RBAC are stand-ins for a possible later real IAM/IdP deployment.

**Fail-closed prerequisites:** no external API or paid provider, no live tokens, no host network, no shared mounted Docker socket inside workloads, no ambient cloud credentials, no unrestricted `docker compose` service ports. Missing isolation or missing evidence fails the proof.

## Paired comparison: one operation, one environment

| Case | Route / adversary capability | Mandatory observation | Effect delta |
| --- | --- | --- | ---: |
| `ALLOW_01` | Valid authority, verified human approval, bound single-use authorization, executor dispatch | Target commits and independently records the operation | **+1** |
| `DENY_01` | Same executor path but missing/invalid approval | VERITAS refuses pre-dispatch; target shows no new effect | **0** |
| `DENY_02` | Agent calls target directly with agent-only network reachability | DNS/routing/connect probe fails outside target; absence of target audit event is corroborative, not sole proof | **0** |
| `DENY_03` | Deliberately reachable probe, no trusted client certificate | Target TLS layer refuses the connection; snapshot unchanged | **0** |
| `DENY_04` | Deliberately reachable, authenticated but insufficiently scoped identity | Target policy returns explicit 403 and audit denial | **0** |
| `DENY_05` | Replay already-consumed valid authorization | VERITAS consumption store refuses; no new target POST/effect | **0** |
| `DENY_06` | Valid approval but method/body/target/scope substitution | VERITAS bind-time recheck refuses; no effect | **0** |
| `RECON_01` | Independent read-only target inspection | Exactly one original target operation and correlated evidence | **0** |

The negative cases must be **real probes**, not a list of expected error strings fabricated by a test double. A refused connection is **not** an HTTP 403; distinguish network error, TLS handshake rejection, target-policy 403 and VERITAS pre-dispatch rejection. Do not aggregate them as if they prove the same layer.

## Evidence contract and independent verification

When a runtime harness is implemented, retain at minimum:

1. `report.json`: proven predicates, per-case result and observed effect delta; `tested_sha` from actual Git checkout, `source_sha` and `base_sha`, deployment image digests and explicit `production_claim=false`.
2. `evidence.json`: one request ID per attempt, decision/intent/authorization/consumption IDs where applicable, exact method/target/body digest, target operation ID where present, BindReceipt/Outcome and reconciliation lineage.
3. `topology.json`: Docker network inspect / resolved service attachment and **target non-publication** evidence, with secret-bearing fields removed.
4. `target_audit.jsonl` and `independent_target_snapshot.json`: target-side accept/deny observations and read-only before/after states. A network denial must have independent probe stderr/exit-status evidence because it never reached the target.
5. `manifest.sha256`: deterministic checksums for reviewer reproduction and integrity comparison, never a claim that the original data source or verifier is inherently trusted.

The independent verifier must fail unless **all** predicates in the JSON contract are observed at the same `tested_sha`, one grant exists after `ALLOW_01`, every negative attempt adds zero grants, replay does not redeliver, the network path is genuinely absent for the agent, and the target itself rejects reachable unauthorized probes. It must reject absent/malformed identity fields, mismatched target operation or idempotency keys, missing audit records, or leaked keys/tokens in artifacts.

Record `EFFECT_UNKNOWN` as unknown if an HTTP result is lost; do not confuse transport failure with `NO_EFFECT`. Use existing read-only reconciliation for uncertain outcomes rather than blind redispatch.

## Implementation sequence and acceptance gates

**Phase 1 (this PR):** freeze the one-operation experiment contract, threat boundary and claim limits. **No runtime proof claimed.**

**Phase 2:** build an entirely isolated runner for the synthetic target, scoped credential authority, mTLS, Docker network partitions, real probes and independent target-state snapshots. Integrate the existing VERITAS governance decision and single-use consumption path; do not substitute a hand-coded boolean for its authorization. Connect CI only after the local runner is demonstrably reproducible. If the runtime cannot enforce independent target authorization, report **NOT PROVEN**, even if happy-path tests pass.

**Phase 3:** capture exact-source-SHA CI artifacts, rerun on merged `main`, independently verify the saved bundles, then ask an outside reviewer to reproduce using the documented runbook. `CI SUCCESS` is not `PROVEN`; the audited scope and assumptions must appear with any claim.

## Threat model and explicit non-claims

In scope: untrusted agent tool output and direct calls; no target credentials on the agent; network-bypass attempts; missing approvals; stale/replayed or scope-mismatched authorizations; unauthenticated / unauthorized but network-reachable requests.

Out of scope: host/root or Docker-daemon compromise, arbitrary code execution in the trusted executor, theft of executor keys, compromised target-side RBAC administrator, kernel escape, public-cloud IAM enforcement, real customer IdP and credentials, enterprise HA/DR/SLA, universal bind coverage, and regulatory certification.

In particular, these tests would prove **synthetic enterprise-like isolation under an explicitly stated Docker trust model**, not a complete customer production deployment.

## Review and exit criteria

- Contract cases remain fixed until a deliberately versioned replacement.
- A reviewer can reproduce the topology without obtaining a paid API key.
- Agent-to-target denial is caused by the infrastructure, while reachable credential/scope denial is caused by the independent target.
- Positive/negative traces share one operation shape and environment; differences are attributable to authorization and access boundaries.
- The evidence proves outcomes through a target-owned observation channel, rather than trusting the caller's own log.
- Only once the runnable evidence and outside replay exist may this track be advanced from `SPECIFICATION_ONLY_NOT_EXECUTED`.
