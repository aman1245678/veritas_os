# Isolated IAM: real mTLS signed-permit transport V1 (#2374)

**Status:** disposable transport-only Docker test. **NOT ALLOW_01 PROVEN.**
This profile is NOT a production configuration or a native VERITAS issuer.

## Precise purpose

This PR separates two claims:

1. #2373 proved a synthetic signed Human Approval / native authorization /
   atomic consumption / target permit / SQLite grant pipeline **inside a
   process-local test harness** with a synthetic mTLS peer.
2. #2374 exercises the **real HTTPS/mTLS socket** across two Docker internal
   networks, target-owned Ed25519 permit verification and SQLite commit
   while recording negative bypass observations. The permit signer in
   THIS profile is explicitly host-side synthetic and does **not** call
   VERITAS native authorization.

Together these are useful bounded evidence, but they do NOT prove their
joint enforcement as one deployed native execution path.

## Isolated execution

`compose.enterprise-iam-permit-transport.yml` is separate from the
default-deny `compose.enterprise-iam-lab.yml` and does not modify its
`LAB_ALLOW_MUTATIONS=0` invariant. The permit transport compose uses
`LAB_ALLOW_MUTATIONS=1` AND `LAB_TEST_PERMIT_GATE=1` solely for a
synthetic `contractor-001` role grant. The target independently requires
both (1) CA-signed client identity with exact `scoped-executor` scope and
(2) a signed, time-bound permit that names the exact HTTP method, path,
role, subject, scope and intended audience. An ID is unique across the
target's SQLite consumption ledger.

A temporary on-host Ed25519 signer creates synthetic permits. It stays
only in the generator's process memory; no private permit-signing key is
exported, mounted or retained. Target reads **only public Ed25519 PEM**.
The target's own TLS key is in a server-only read-only certificate mount.
The scoped executor receives its own mTLS client certificate plus
pre-generated signed permits but no verifier mount, target SQLite mount,
server TLS key or permit signing key. The agent-direct container receives
none of those and sits only on `agent_net`; target and scoped executor
sit only on `effect_net`. Both Docker networks are internal, there
are no published host ports, containers drop capabilities and use
read-only root filesystems.

The observed transport cases are:

| Observation | Expected enforced result |
|---|---|
| scoped valid signed permit | 201 committed, one target grant |
| replay same permit | 409 permit_replayed |
| scoped missing permit | 400 invalid_mutation |
| scoped tampered payload | 403 permit_denied |
| scoped wrong signer | 403 permit_denied |
| valid permit + unscoped mTLS identity | 403 target_scope_denied |
| certificate-less client | real TLS client certificate refusal |
| agent-direct attempts target IP | blocked TCP / unreachable (not connection-refused) |

The target database is independently inspected **before** and **after**
successful issuance: before allow there must be zero grants and zero
permit consumptions; after allow exactly one admin grant, one consumption,
one success audit ID linked to the consumption, denied attempts and one
replay record. The verifier rejects forged JSON status and target-ledger
inconsistencies and pins evidence to the checked-out Git SHA.

## How to run

In a disposable Docker-capable environment with Python 3.12,
`cryptography==46.0.4`, and OpenSSL installed:

```bash
bash scripts/enterprise_iam_lab/run_permit_transport.sh
```

The dedicated GitHub Actions workflow runs this with
`tests/quality/test_iam_permit_transport_verifier_v1.py`. Output:
`artifacts/isolated-enterprise-iam-permit-transport/latest/`.
Only sanitized JSON summaries are archived. All CA/private TLS
certificates, signed permits and SQLite state are deleted on exit; the
CI workflow does **not** archive these.

## Scope limits / next steps

- Signed permits in this runner have IDs prefixed
  `transport-only:`; native issuance / approval / consumption is
  **NOT** exercised by this runner. This is not authorization evidence.
- No separated, durable native signer + PostgreSQL consumption service
  has been integrated with the target over Docker.
- The driver/host is trusted to provide synthetic permits. No hostile
  host compromise, kernel escape, privilege escalation, OS lockdown
  compliance, cross-host firewall test or key exfiltration resistance
  is proven. Running Docker requires powerful host privileges.
- This does not test real IAM provider credentials, third-party IdP
  APIs, or durable reconciliation after a lost target response.
- A future PR must integrate the actual signed native-approved permit
  from an issuer with strong key custody, isolate agent ↔ issuer ↔
  executor, and validate ALLOW_01, DENY_01..06 and RECON_01 with
  independent, retained exact-SHA evidence.

**No external provider API or billable AI model calls are used here.**
