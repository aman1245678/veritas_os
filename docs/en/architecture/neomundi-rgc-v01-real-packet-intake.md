# NeoMundi historical RGC v0.1.0 COMPLETE-only intake

## Status / boundary

This **opt-in** intake is distinct from the RGC v0.2 production-artifact
PoC runner. It consumes only original, *unmodified* RGC artifacts with
`identity.schema_version = "0.1.0"` and complete-only semantics.
Do not relabel signed data. The v0.2 CLI and v0.2 manifest schema remain
fixed to `0.2.0`; the generic external-measurement verification boundary
remains unchanged.

A valid JWS with an artifact-supplied or emailed key is not enough to
establish provider trust. An operator must independently approve the
correct public key via a genuine out-of-band process and retain a
Trusted Public Key Provenance Receipt. This code **correlates** the
receipt fingerprint to the supplied public key; it does **not**
independently prove the trust channel was authentic.

## Input contract

Supply four separate JSON files **outside the public repository**:

1. Original NeoMundi RGC v0.1.0 observation, byte-for-byte as received.
2. Public-only trusted JWKS independently approved by the operator.
3. Trusted Public Key Provenance Receipt per
   `schemas/trusted_public_key_provenance_receipt.schema.json`.
   `bundle_internal_key_used` must be `false`.
4. v0.1.0 intake manifest per
   `schemas/neomundi_rgc_v01_complete_intake_manifest.schema.json`.
   The manifest binds original artifact bytes, exact JWKS bytes,
   provenance-receipt bytes, request ID, selected key ID, reported
   signer identity, and handoff reference.

No private signing key or API credentials are required.

The manifest is **packet correlation**, not trust, issuance time,
evidence freshness, governance approval or permission.
The provenance receipt is a record of *someone's trust decision*;
its existence alone cannot authenticate that decision.

## Gate ordering

```text
RGC v0.1 + public JWKS + provenance receipt + v0.1 manifest
    ↓
exact raw-file hashes + manifest version / request / key / signer
    ↓
separate key provenance receipt + raw Ed25519 key fingerprint
    ↓
NeoMundiRgcV01CompleteVerifier (policy-pinned measurement version)
    ↓
SHA-256 payload reconstruction + Ed25519/JWS + signed claims
    ↓
strict COMPLETE / five measured signals / temporal boundary
    ↓
generic trust, real-time freshness, expiry posture, replay guard
    ↓
non-authoritative VerifiedExternalMeasurementEvidence + report/manifest
```

The existing v0.2 runbook is unchanged. For v0.1, the
`accepted_measurement_version` is an explicit operator-configured
exact match, bound into the provider verifier policy hash.

## Invocation

Run from a properly installed VERITAS checkout, in a secure local
environment, after independent public-key approval. Use a **new output-directory path that does not already exist**
for every attempt. The CLI does **not** accept an
artificial `--now` argument.

```bash
python scripts/run_neomundi_rgc_v01_complete_intake.py \
  --artifact /secure/inbox/rgc-v01-original.json \
  --jwks /secure/inbox/operator-approved-neomundi-public-jwks.json \
  --trusted-key-provenance /secure/inbox/key-provenance.json \
  --intake-manifest /secure/inbox/v01-intake-manifest.json \
  --accepted-measurement-version 3.3.0 \
  --replay-state-dir /secure/state/neomundi-v01-replay \
  --output-dir /secure/evidence/neomundi-v01-attempt-001 \
  --max-age-seconds 3600 \
  --allow-no-expiry
```

`--allow-no-expiry` is an **explicit** PoC exception to the generic
default. The runner never alters observation timestamps, fabricates
an issuance or expiration time, or expands freshness limits to force
a historical success.

The historical v0.1 intake enforces a non-expandable freshness window
of **1 to 3600 seconds** and a future-skew limit of **0 to 60 seconds**.
The actual 19 October 2026 v0.1 observation is historical and
**must fail** current-governance freshness checks after the one-hour limit. A successfully validated offline signature
is not proof of currently usable or fresh evidence.

## Results

On success, the CLI creates:

- `verification_report.json` — provider, intake, key-provenance,
  trust/freshness and no-authority result;
- `verified_external_measurement_evidence.json` — serialized,
  auditable non-authoritative evidence (not portable runtime trust);
- `evidence_manifest.json` — exact input bytes and output hashes,
  verifier policy and replay binding.

Results are staged in a private sibling directory and atomically
published under `--output-dir` only after **all** result files have
been written. On normal verification failure, only a failure-status
`verification_report.json` is published. On write or atomic-rename
failure, the output directory is not published at all and the CLI
returns a nonzero status. These guarantees cover ordinary operating
system errors during publication, not all power-loss scenarios.

**Important:** Generic replay consumption occurs before output
publication. If publication fails after successful verification,
the replay marker **remains consumed**; the operator must investigate
and reconcile that attempt rather than blindly redispatch the same
observation or reset the replay marker. No success result is
reported on publication failure.
Input and output files may contain controlled partner data.
Do not commit them or paste them into a public issue/PR.

The file-based replay marker is durable only for a *single local
filesystem namespace*, not a distributed single-use service.

## Non-claims and remaining work

```text
Measurement != Authority
Advisory != Authorization
Valid signature != Trusted key origin
Within bounds != VERITAS ALLOW
Verified measurement != Governance decision
```

This PR does not create AuthorityEvidence, HumanApproval,
BindAuthorization, a governance decision, an external effect, a
BindReceipt, or an end-to-end governance Evidence Packet.

It does **not** prove NeoMundi's current evaluator health,
that `model: local` means actual local execution, factual correctness,
or drift from one record. Measurement version `3.3.0` remains separate
from schema version `0.1.0` and should not be silently compared
against other measurement versions.

The final cross-system milestone remains: independently authenticated
key provenance + genuine current observation + accepted real packet
+ separately evaluated VERITAS governance + auditable receipt.
