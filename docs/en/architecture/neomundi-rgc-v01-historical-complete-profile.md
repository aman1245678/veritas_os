# NeoMundi RGC v0.1.0 Historical COMPLETE-only Profile

## Scope and status

This is a deliberately **opt-in, historical compatibility** profile for
authentic, signed NeoMundi RGC JSON carrying
`identity.schema_version = "0.1.0"`.
It adds `NeoMundiRgcV01CompleteVerifier` without changing the
existing `NeoMundiRgcV02Verifier` or the frozen execution path.

It is **not** a silent reinterpretation of v0.1 as v0.2 and it is **not**
a general implementation of every v0.1 contract. In particular, the
historical v0.1 schema permitted ambiguity around unmeasured numeric
signals. This profile does **not** try to resolve that ambiguity through
defaults or optimistic inference.

It only accepts an explicit, signed COMPLETE subset:

- `schema_version = 0.1.0`, not 0.2.0 (never relabel signed data);
- the measurement version appears in a VERITAS-controlled exact allowlist;
- `runtime_scope = single_request`;
- `measurement_status = complete` and `measurement_coverage = 1.0`;
- all five known signals explicitly marked `measured`, each with a
  real numeric score in `[0, 1]`;
- `observation_class_scope = measured_domain`, and a bounded
  `within_bounds` or `flagged` classification;
- an explicit `temporal_boundary` establishing nothing and denying
  single-record drift, persistence, recurrence, or frequency conclusions;
- explicit non-empty limitations and measurement boundary;
- `authorization_status = not_applicable` and physically present
  `execution_permission_changed = false`;
- explicit SHA-256 and `sorted-json-utf8` canonicalization parameters.

A partial record, missing status, unknown signal state, null-valued
`measured` signal, unsupported version, or semantic overclaim **fails closed**.
`measurement_version` is distinct from the RGC schema version and
is preserved in evidence provenance. Only explicitly approved measurement
versions can be verified under a given policy hash. For the initial
historical test, an operator may choose `("3.3.0",)`; later versions
require a separate explicit policy decision.

## Cryptographic boundary

The payload is reconstructed from the **unmodified** `identity`,
`provenance`, `observation`, and `governance` objects (excluding
`integrity`), serialized as Python sorted compact JSON with
`ensure_ascii=True`, UTF-8 encoded, and SHA-256 hashed.
This is **not** RFC 8785 / JCS canonicalization.

The verifier reuses the existing, narrow Ed25519/EdDSA compact-JWS
verification logic and requires the five authenticated claims
(`payload_hash`, `hash_algorithm`, `schema_version`,
`request_id`, `timestamp`) to match the received JSON exactly.

The trusted public JWKS is supplied by an independently controlled
VERITAS configuration, **not** loaded from the RGC, its email, or its
`key_id`. The verifier policy hash binds the separately configured
keys, legacy profile, version allowlist, and cryptographic requirements.
A signature does not independently establish key-source authenticity.
`signer_identity` is unauthenticated integrity metadata outside the
canonical payload and is not treated as a trust root.

No production RGC, real provider key, or partner-controlled artifact is
included in this repository. Tests use synthetic keys and data only.

## Evidence vs execution authority

The verifier maps valid signed input to measurement-only
`ExternalMeasurementEvidence`; it never creates
`AuthorityEvidence`, `HumanApproval`, `BindAuthorization`, a
`GovernanceDecision`, or permission to perform an effect.

- `model = local` is preserved as a reported field, not proof of actual
  local model execution.
- `within_bounds` is not global safety or factual correctness.
- A single record is not evidence of absence of drift over time.
- `factual_hallucination_score = 0.0` is a signed measured signal,
  not independent certification of factual truth.
- Neither a valid signature nor full declared measurement coverage
  establishes that the current evaluator implementation is healthy.
- `measurement_version = 3.3.0` is not silently compared against
  other measurement algorithm versions.

## Generic trust / replay and historical freshness

Provider verification alone is **not** a sealed VERITAS acceptance.
The verifier must be explicitly approved via an
`ExternalMeasurementTrustPolicy`, and the generic
`verify_external_measurement_artifact_to_evidence(...)` boundary must
independently enforce freshness, expiry posture, semantic consistency,
and atomic replay consumption.

The observed timestamp is also mapped to issuance time for this
single-timestamp contract; it does not prove two separate events.
The provider contract lacks a reliable `expires_at` field, so any
exception to generic expiry requirements must be explicit and bounded.

A historical observation outside the configured maximum age remains
**stale** for current governance use. Do not forge a historical `now`,
increase the validity window merely to force a successful live proof,
or promote an offline signature check into a claim of operational
freshness.

## Official first-live PoC status

The existing hardened
`scripts/run_neomundi_real_observation_poc.py` and its manifest
contracts remain **v0.2-only**. This PR does not silently route
v0.1 data into that CLI or assert successful live interoperability.

Before any real v0.1 artifact is admitted through the official
partner-ingress runner, implement and review an **explicit v0.1
intake/manifest dispatch** with independently sourced key provenance,
exact-file hashes, operator approval, durable replay, and evidence
reporting. The actual received production artifact must remain outside
the public repository. A subsequent fresh observation may be required
to complete the real end-to-end PoC.

## Tests

Synthetic regressions cover valid signed complete records, v0.2
cross-version rejection, exact measurement-version policy identity,
complete/partial and signal-state failures, execution authority
fail-closed checks, signed-claim mismatches, post-sign tampering, and
generic freshness/replay/policy binding.
