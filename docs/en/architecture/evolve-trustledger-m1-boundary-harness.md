# Evolve TrustLedger M1 — independent synthetic boundary harness (draft)

## Status and proof scope

Research-only, **non-executing** synthetic boundary harness. The Oct19b
partner package was independently checked using the local VERITAS evaluator,
but this does not constitute production integration, a frozen evidence baseline,
or joint Milestone 1 sign-off.

- Evolve's ADOPT is governance input, **not** VERITAS execution authority.
- The fixture issuer allowlist is a test profile, **not** cryptographic
  issuer authentication, a deployed trust policy, or Ed25519 verification.
- Local SHA-256 consistency is **not** authenticity or trusted timestamp proof.
- No partner scripts are executed, no network calls, no API keys, no
  BindAuthorization, no credentials, no external effects.
- An independently configured ActionClassContract, verified AuthorityEvidence,
  Human Approval and Policy are **not** supplied by the Evolve Receipt.
- Layer 3 uses the real `CommitBoundaryEvaluator` with those inputs missing;
  the expected result is a fail-closed block/refusal, **not** a positive
  authorization demonstration.

## Input and operation

Use the locally received six-case ZIP as a read-only input. The package is
not checked into this public repository. Its partner-generated
`evolve_output.json` is comparison data, never trusted as authority.

```sh
python -m veritas_os.governance.evolve_trustledger_m1 /path/to/partner-six-cases.zip > m1_local_report.json
python -m pytest -q veritas_os/tests/test_evolve_trustledger_m1.py
```

The ZIP's `build_cases.py`, `build_cases_fixed.py`, and
`evolve_runner_v2.py` are **never** executed.

The manifest uses a **list** of `{path, sha256}` entries with POSIX-style paths, while ZIP member names use literal backslashes. The harness independently checks every listed raw-byte SHA-256 and rejects missing, unlisted or duplicate ZIP members. The three bundled partner scripts are hash-checked as inert data, **never executed**. Synthetic regression tests generate a partner-shaped ZIP in memory; no partner evidence package is checked into this repository.

The output is a synthetic boundary report. `layer_1` only recognizes the
fixed test schema/issuer; `layer_2` recomputes canonical claims from the
received receipt, checks the embedded hash, evaluates the local test window,
and binds organization/assessment against `live_state.json`. `layer_3`
is reached only when the synthetic L1/L2 checks pass.

The receipt claims hash excludes **exactly** these five keys:

- `receipt_issuer_authentication`
- `timestamp_proof`
- `receipt_claims_hash`
- `canonical_claims_input`
- `_unknown_field_policy_note`

Any other fields, including unexpected note fields, remain in the claims hash.
Canonicalization is recursively sorted, compact UTF-8 JSON without Unicode
normalization; duplicate keys and non-finite numbers are rejected.

## Expected cases

| Case | First decisive synthetic boundary | VERITAS Layer 3 |
| --- | --- | --- |
| 1 Valid | L1/L2 synthetically consistent | Independent authority absent; block/refuse |
| 2 Tampered claims | L2 claims hash mismatch | NOT_REACHED |
| 3 Expired | L2 freshness expired | NOT_REACHED |
| 4 Wrong subject | L2 organization/assessment mismatch | NOT_REACHED |
| 5 Unrecognized issuer | L1 issuer not recognized | NOT_REACHED |
| 6 Unknown schema | L1 schema version not recognized | NOT_REACHED |

Case 5 also lacks provenance, but issuer recognition is the first tested
boundary; Layer 2 must not be described as independently executed.
Case 6 must not mark unevaluated freshness checks as PASS.

## Historical evidence gate — 2026-10-19 (superseded by Oct19b)

**Historical note only.** The Oct18b/Oct19 discrepancies below preceded the
corrected Oct19b evidence package. The Oct19b local strict verification and
Kiel's 2026-10-20 confirmation are described later in this document and in
the [draft joint Boundary Verification Report](evolve-trustledger-m1-joint-boundary-verification-report-draft.md).
Do not treat this historical section as the current evidence status.

The received `VERITAS_M1_Final_Oct18b.zip` has passed independent package
integrity checks in the review process, but **has not been frozen**.
The Oct19 revision still has outstanding evidence-record issues pending partner correction:

1. Case 3 still contains mixed evaluation dates in the gate explanation and
   case metadata. The local `live_state.json` and other evidence timestamps
   must be reconciled to the final frozen case definition.
2. Case 5 still reports positive freshness and context-binding booleans even though Layer 1 rejects the issuer.
3. Case 6 correctly marks Layer 2 as NOT_REACHED, but its context-binding check is still reported as failed despite not being reached.

The received Oct19 ZIP and its MANIFEST SHA-256 were independently matched against the sender's values; manifest-listed hashes and input fingerprints also match. That is **byte integrity**, not evidence-record consistency, issuer authenticity or freeze approval.

Do not claim this harness passes the frozen six-case run before the revised
ZIP is received, independently checked and explicitly frozen.

## Historical planned next gate (pre-Oct19b)

The following was the plan before receipt of Oct19b; the actual local
verification is recorded below. Formal evidence freeze and bilateral
acceptance remain pending.

After evidence freeze: pin the exact ZIP and MANIFEST SHA-256, verify all
per-file raw hashes, reconcile Evolve's three-state records, run the harness
against the frozen bytes, and publish an independent VERITAS result with
run logs and a reviewable evidence digest. A further separately approved
test would be required to exercise **positive** VERITAS Authority/Policy/
Approval admissibility; it must never derive those from ADOPT.

Do not merge on the strength of green CI alone: review the synthetic trust
limitations and runtime evaluator results first.


## Received Oct19b evidence — local verification (2026-10-20)

The actual partner-supplied `VERITAS_M1_Final_Oct19b.zip` was processed locally
on macOS using `tools/evolve_m1_oct19b_strict_proof.py` and this PR's
`evaluate_synthetic_zip` implementation. The ZIP was **not** committed or
executed as code. This is a user-reported local result; CI tests use generated
synthetic fixtures and do not execute the received partner ZIP.

- Partner ZIP SHA-256: `8781bfc6d1518713291e1e262bc818d7855504aaea4f0280c625a51027a91787`
- Manifest SHA-256: `319ca54e89d697ac7f5945333f7498f4e04c7fb8ee8ab6826c3ef7c3aba675f3`
- Verified harness HEAD: `7b1b6d02d4af9718d34a59711fd6de366f3c2f32`
- Local JSON report SHA-256: `53e95c0a75d714c8b4983c37ad5608a16d847c65ff0896b781ca9820a0e2f46d`
- Strict local result: `PASS`, `failures=[]`, `records_reconciled=true`, 6/6
  expected synthetic boundary outcomes, 0 record warnings.
- Case 1: L1 recognized, L2 synthetic consistency only (not authenticated),
  L3 `BLOCK` due to missing independent VERITAS authority.
- Cases 2–4: L2 `REJECTED` (claims-hash mismatch, expiry, context mismatch).
- Cases 5–6: L1 `REJECTED` (issuer, schema); L2/L3 `NOT_REACHED`.
- No network dispatch, external effect, real signature authentication, or
  VERITAS authorization was performed. `frozen_baseline_approved=false` and
  `milestone1_signed_off=false`.

Reproduction on a local checkout with the private ZIP available:

```sh
PYTHONPATH=. python tools/evolve_m1_oct19b_strict_proof.py \\
  /path/to/VERITAS_M1_Final_Oct19b.zip \\
  --report /path/to/evolve_m1_oct19b_proof.json
```

The JSON report remains on the verifier's local machine. Its hash is a
reference for subsequent independent evidence exchange, not a substitute for
sharing and reviewing the actual report. Final evidence freeze and the joint
Boundary Verification Report require explicit agreement by both parties.
