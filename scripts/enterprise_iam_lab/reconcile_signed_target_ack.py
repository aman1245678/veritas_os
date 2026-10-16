#!/usr/bin/env python3
"""#2380: REAL native PG EFFECT_UNKNOWN -> CONFIRMED_EFFECT via target-signed mTLS.

No target SQLite access, no target grant POST, no new consumption or Permit
issuance. Reuses #2377's existing native lost-ACK, #2379's already-observed
dedicated reader mTLS GET, and the existing durable reconciliation CAS.

This is ONE disposable, same-host Docker demonstration, not cross-operator
or production reconciliation. In particular, the host initially generates
the target signing key; target mTLS metadata is bounded CI observation.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

from scripts.enterprise_iam_lab.durable_challenge_registry import (
    ChallengeBoundPostgresEffectStore, digest as challenge_digest, lookup as challenge_lookup,
)
from scripts.enterprise_iam_lab.reconcile_native_lost_ack import (
    read_native_issuer, require, require_discarded_response,
)
from scripts.enterprise_iam_lab.target_readonly_receipt import (
    CHALLENGE_PATTERN, MAX_OBSERVATION_VALIDITY, SCHEMA_CHALLENGE,
    SOURCE_IDENTITY, canonical as canonical_target_receipt,
)
from scripts.enterprise_iam_lab.verify_readonly_ack import (
    read_json, verify_probes, verify_readonly_topology,
    verify_target_signature,
)
from veritas_os.policy.bind_effect_reconciliation import (
    BindEffectStateError,
    EffectExecutionState,
    PostgresAtomicEffectStateStore,
    ReconciliationClaim,
    ReconciliationEvidence,
    VerifiedReconciliationEvidence,
    _record_hash_valid,
    reconcile_effect_unknown,
)
from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
    AuthorizationConsumptionRecord,
    PostgresAtomicAuthorizationConsumptionStore,
)
from veritas_os.policy.trusted_https_reconciliation import (
    reconciliation_observation_digest,
)
from veritas_os.security.hash import sha256_of_canonical_json
from veritas_os.storage.db import close_pool


SOURCE_TYPE = "synthetic-target-signed-mtls-readonly-ack-v1"
SOURCE_TYPE_CHALLENGE = "synthetic-target-signed-mtls-challenge-ack-v2"
VERIFIER_ID = "iam-2380-target-signed-docker-mtls-verifier-v1"
PROOF_STATUS = "SYNTHETIC_NATIVE_POSTGRES_SIGNED_MTLS_ACK_CAS_NOT_PRODUCTION_PROVEN"


def aware(value: str) -> datetime:
    require(type(value) is str and bool(value), "IAM2380_TIMESTAMP_ABSENT")
    try:
        clock = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        raise ValueError("IAM2380_TIMESTAMP_INVALID") from None
    require(clock.tzinfo is not None and clock.utcoffset() is not None,
            "IAM2380_TIMESTAMP_NO_TIMEZONE")
    return clock.astimezone(timezone.utc)


def signature_digest(envelope: dict) -> str:
    """Include signature AND payload in the reconciliation evidence digest."""
    require(type(envelope) is dict and set(envelope) == {"payload", "signature"},
            "IAM2380_SIGNED_ACK_ENVELOPE_INVALID")
    return sha256_of_canonical_json(envelope)


def validate_signed_lineage(
    *,
    envelope: dict,
    target_public_pem: bytes,
    receipt: dict,
    permit: dict,
    native: AuthorizationConsumptionRecord,
    observed_at: str,
    expected_challenge: str = "",
    challenge_issued_at: str = "",
) -> dict:
    """Recheck target signature + exact native consumption before promoting."""
    payload = verify_target_signature(
        envelope, target_public_pem,
        expected_schema=SCHEMA_CHALLENGE if expected_challenge else "isolated-iam-target-committed-ack/v1",
    )
    if expected_challenge:
        require(
            type(expected_challenge) is str
            and CHALLENGE_PATTERN.fullmatch(expected_challenge) is not None
            and payload["challenge"] == expected_challenge
            and bool(challenge_issued_at),
            "IAM2381_WRONG_OR_MISSING_CHALLENGE",
        )
        challenge_clock = aware(challenge_issued_at)
        target_clock = aware(payload["target_observed_at"])
        target_expiry = aware(payload["target_expires_at"])
        verifier_clock = aware(observed_at)
        require(
            challenge_clock - timedelta(seconds=2) <= target_clock <= verifier_clock + timedelta(seconds=2)
            and target_clock < target_expiry
            and target_expiry - target_clock <= MAX_OBSERVATION_VALIDITY
            and verifier_clock <= target_expiry
            and verifier_clock - challenge_clock <= MAX_OBSERVATION_VALIDITY,
            "IAM2381_STALE_FUTURE_OR_UNSOLICITED_SIGNED_OBSERVATION",
        )
    require(
        payload["permit_id"] == permit["permit_id"] == receipt["permit_id"]
        and payload["external_operation_reference"] == permit["permit_id"]
        and payload["authorization_id"] == permit["authorization_id"] == receipt["authorization_id"]
        and payload["execution_intent_id"] == permit["execution_intent_id"] == receipt["execution_intent_id"]
        and payload["request_id"] == permit["request_id"] == receipt["request_id"],
        "IAM2380_TARGET_PERMIT_LINEAGE_MISMATCH",
    )
    require(
        native.consumption_id == receipt["consumption_id"]
        and native.consumption_hash == receipt["consumption_hash"]
        and native.live_adapter_bind_authorization_id == permit["authorization_id"]
        and native.live_adapter_bind_authorization_hash == receipt["authorization_hash"]
        and native.execution_intent_id == permit["execution_intent_id"]
        and isinstance(native.execution_intent_hash, str)
        and len(native.execution_intent_hash) == 64
        and native.idempotency_key == permit["request_id"]
        and native.consumption_state == "CONSUMED"
        and native.single_use_enforced is True,
        "IAM2380_NATIVE_CONSUMPTION_LINEAGE_MISMATCH",
    )
    committed_at = aware(payload["consumed_at"])
    require(
        aware(native.consumed_at) <= committed_at
        and aware(permit["not_before"]) <= committed_at < aware(permit["expires_at"])
        and committed_at <= aware(observed_at),
        "IAM2380_ACK_COMMIT_CLOCK_OUTSIDE_NATIVE_PERMIT",
    )
    return payload


class SyntheticSignedMtlsAckVerifier:
    """Verify the signed, already-fetched target receipt. No target DB access."""

    def __init__(
        self, *,
        envelope: dict, pinned_target_public: bytes,
        receipt: dict, permit: dict, native: AuthorizationConsumptionRecord,
        expected_challenge: str = "", challenge_issued_at: str = "",
    ) -> None:
        self.envelope = envelope
        self.pinned_target_public = pinned_target_public
        self.receipt = receipt
        self.permit = permit
        self.native = native
        self.expected_challenge = expected_challenge
        self.challenge_issued_at = challenge_issued_at
        self.source_type = SOURCE_TYPE_CHALLENGE if expected_challenge else SOURCE_TYPE
        self.digest = signature_digest(envelope)
        self.target_public_fingerprint = hashlib.sha256(pinned_target_public).hexdigest()
        self.policy_hash = sha256_of_canonical_json({
            "verifier_id": VERIFIER_ID,
            "source_identity": SOURCE_IDENTITY,
            "source_type": self.source_type,
            "expected_challenge": expected_challenge if expected_challenge else "disabled",
            "target_public_fingerprint": self.target_public_fingerprint,
            "proof_scope": "synthetic-mtls-retrieved-target-ed25519-receipt-and-native-postgres",
            "operator_independent": False,
            "allow_no_effect_confirmation": False,
        })

    async def verify(self, evidence: ReconciliationEvidence) -> VerifiedReconciliationEvidence:
        require(
            evidence.claim == ReconciliationClaim.CONFIRMED_EFFECT
            and evidence.operation_id == self.native.consumption_id
            and evidence.authorization_id == self.permit["authorization_id"]
            and evidence.consumption_id == self.native.consumption_id
            and evidence.source_type == self.source_type
            and evidence.source_identity == SOURCE_IDENTITY
            and evidence.external_operation_reference == self.permit["permit_id"]
            and evidence.external_ack_digest == self.digest
            and evidence.observation_digest == reconciliation_observation_digest(evidence),
            "IAM2380_UNTRUSTED_RECONCILIATION_CLAIM",
        )
        payload = validate_signed_lineage(
            envelope=self.envelope, target_public_pem=self.pinned_target_public,
            receipt=self.receipt, permit=self.permit, native=self.native,
            observed_at=evidence.observed_at,
            expected_challenge=self.expected_challenge,
            challenge_issued_at=self.challenge_issued_at,
        )
        # The PostgreSQL record is loaded again from the actual native store
        # on every verification invocation, not trusted from the receipt alone.
        actual = await PostgresAtomicAuthorizationConsumptionStore().get(
            self.permit["authorization_id"],
        )
        require(actual is not None and actual == self.native,
                "IAM2380_NATIVE_POSTGRES_CHANGED_OR_MISSING")
        checked = datetime.now(timezone.utc).isoformat()
        proof_hash = sha256_of_canonical_json({
            "verifier_policy_hash": self.policy_hash,
            "verified_at": checked,
            "verified_reconciliation_claim": evidence.model_dump(mode="json"),
            "signed_ack_sha256": self.digest,
            "native_pg_consumption_hash": actual.consumption_hash,
            "target_payload_digest": hashlib.sha256(
                canonical_target_receipt(payload)
            ).hexdigest(),
        })
        return VerifiedReconciliationEvidence(
            evidence=evidence,
            verifier_id=VERIFIER_ID,
            verifier_policy_hash=self.policy_hash,
            verification_proof_hash=proof_hash,
            verified_at=checked,
        )


async def perform(*, folder: Path, trust: Path, permits: Path,
                  target_public: Path, compose_config: Path,
                  freshness_challenge: bool = False,
                  durable_challenge: bool = False) -> dict:
    require(not durable_challenge or freshness_challenge,
            "IAM2382_DURABLE_REQUIRES_FRESHNESS")
    # Neither this function nor the signer-backed verifier can open target
    # SQLite: NO --target-database path, sqlite3 connection, or target mount.
    require_discarded_response(folder)
    receipt, permit = read_native_issuer(folder, trust, permits)
    require(
        receipt.get("durable_in_flight_created") is True
        and receipt.get("native_store_durable") is True,
        "IAM2380_DURABLE_UNKNOWN_SCOPE_MISSING",
    )
    topology = verify_readonly_topology(read_json(compose_config))
    envelope = verify_probes(folder)
    challenge = ""
    challenge_time = ""
    if freshness_challenge:
        registered = read_json(folder / "iam_freshness_challenge.json")
        require(
            registered.get("schema") == "iam-2381-host-challenge/v1"
            and registered.get("permit_id") == permit["permit_id"]
            and registered.get("target_status_before_lookup") == "EFFECT_UNKNOWN",
            "IAM2381_EXPECTED_PRELOOKUP_STATE_MISSING",
        )
        challenge = registered.get("challenge")
        challenge_time = registered.get("issued_at")
        require(
            isinstance(challenge, str)
            and CHALLENGE_PATTERN.fullmatch(challenge) is not None,
            "IAM2381_CHALLENGE_INVALID",
        )
    pinned = target_public.read_bytes()
    require(pinned != (trust / "permit-public.pem").read_bytes(),
            "IAM2380_TARGET_SIGNER_MUST_DIFFER_FROM_ISSUER")

    native_store = PostgresAtomicAuthorizationConsumptionStore()
    effect_store = (
        ChallengeBoundPostgresEffectStore(
            nonce_sha256=challenge_digest(challenge),
            permit_id=permit["permit_id"],
            authorization_id=permit["authorization_id"],
            operation_id=receipt["consumption_id"],
        ) if durable_challenge else PostgresAtomicEffectStateStore()
    )
    try:
        native = await native_store.get(permit["authorization_id"])
        require(native is not None, "IAM2380_MISSING_NATIVE_PG_CONSUMPTION")
        before = await effect_store.get(native.consumption_id)
        require(before is not None and _record_hash_valid(before)
                and before.state == EffectExecutionState.EFFECT_UNKNOWN
                and before.revision == 2
                and before.operation_id == native.consumption_id
                and before.authorization_id == permit["authorization_id"]
                and before.consumption_id == native.consumption_id
                and before.consumption_hash == native.consumption_hash,
                "IAM2380_DURABLE_EFFECT_UNKNOWN_REQUIRED")
        now = datetime.now(timezone.utc).isoformat()
        verifier = SyntheticSignedMtlsAckVerifier(
            envelope=envelope, pinned_target_public=pinned,
            receipt=receipt, permit=permit, native=native,
            expected_challenge=challenge, challenge_issued_at=challenge_time,
        )
        # Fail closed BEFORE CAS if the saved signed target receipt or native
        # lineage is missing/tampered. No effect retry under any outcome.
        validate_signed_lineage(
            envelope=envelope, target_public_pem=pinned,
            receipt=receipt, permit=permit, native=native, observed_at=now,
            expected_challenge=challenge, challenge_issued_at=challenge_time,
        )
        evidence = ReconciliationEvidence(
            operation_id=native.consumption_id,
            authorization_id=permit["authorization_id"],
            consumption_id=native.consumption_id,
            claim=ReconciliationClaim.CONFIRMED_EFFECT,
            source_type=verifier.source_type, source_identity=SOURCE_IDENTITY,
            observed_at=now,
            external_operation_reference=permit["permit_id"],
            external_ack_digest=verifier.digest,
            observation_digest="0" * 64,
        )
        evidence = evidence.model_copy(update={
            "observation_digest": reconciliation_observation_digest(evidence)
        })
        confirmed = await reconcile_effect_unknown(
            operation_id=native.consumption_id, evidence=evidence,
            verifier=verifier, effect_store=effect_store, updated_at=now,
        )
        persisted = await effect_store.get(native.consumption_id)
        consumed_nonce = (await challenge_lookup(challenge_digest(challenge))
                          if durable_challenge else None)
        if durable_challenge:
            require(consumed_nonce is not None
                    and consumed_nonce["state"] == "CONSUMED"
                    and consumed_nonce["operation_id"] == native.consumption_id
                    and consumed_nonce["authorization_id"] == permit["authorization_id"]
                    and consumed_nonce["permit_id"] == permit["permit_id"]
                    and consumed_nonce["evidence_hash"] == persisted.reconciliation_evidence_hash,
                    "IAM2382_NONCE_AND_EFFECT_NOT_ATOMICALLY_COMMITTED")
        require(
            confirmed == persisted
            and confirmed.state == EffectExecutionState.CONFIRMED_EFFECT
            and confirmed.revision == before.revision + 1
            and confirmed.reconciliation_evidence_hash is not None
            and _record_hash_valid(confirmed),
            "IAM2380_SIGNED_MTLS_CAS_NOT_DURABLE",
        )
        terminal_immutable = False
        try:
            await reconcile_effect_unknown(
                operation_id=native.consumption_id, evidence=evidence,
                verifier=verifier, effect_store=effect_store, updated_at=now,
            )
        except BindEffectStateError as exc:
            terminal_immutable = str(exc) == "BES_TERMINAL_STATE_IMMUTABLE"
        require(terminal_immutable, "IAM2380_RECONCILIATION_TERMINAL_NOT_IMMUTABLE")
        return {
            "result": "PASS",
            "phase": "reconcile",
            "proof_status": PROOF_STATUS,
            "operation_id": native.consumption_id,
            "effect_state_before": before.state.value,
            "effect_state_after": persisted.state.value,
            "revision": persisted.revision,
            "reconciliation_evidence_digest": persisted.reconciliation_evidence_hash,
            "source_type": verifier.source_type,
            "source_identity": SOURCE_IDENTITY,
            "freshness_challenge_verified": freshness_challenge,
            "durable_challenge_consumed_with_effect": durable_challenge,
            "durable_challenge_replay_allow": False,
            "freshness_challenge_digest": hashlib.sha256(
                challenge.encode("ascii")
            ).hexdigest() if freshness_challenge else None,
            "target_ack_freshness_bounded_seconds": int(
                MAX_OBSERVATION_VALIDITY.total_seconds()
            ) if freshness_challenge else None,
            "cross_host_replay_proven": False,
            "target_ack_signature_verified": True,
            "target_ack_sha256": verifier.digest,
            "native_postgres_consumption_verified": True,
            "target_owned_sqlite_directly_read_for_reconciliation": False,
            "separate_mtls_reader_without_target_database": topology["reader_has_no_target_sqlite"],
            "target_reader_no_private_signer_mount": topology["reader_has_no_target_signer_private_key"],
            "terminal_state_immutable": True,
            "target_post_retried": False,
            "permit_reissued": False,
            "independent_operator_validation": False,
            "real_cloud_iam_effects": 0,
            "paid_provider_calls": 0,
            "production_claim": False,
        }
    finally:
        await close_pool()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--trust-dir", required=True, type=Path)
    parser.add_argument("--permit-dir", required=True, type=Path)
    parser.add_argument("--target-public-key", required=True, type=Path)
    parser.add_argument("--compose-config", required=True, type=Path)
    parser.add_argument("--freshness-challenge", action="store_true")
    parser.add_argument("--durable-challenge", action="store_true")
    args = parser.parse_args()
    result = asyncio.run(perform(
        folder=args.report_dir, trust=args.trust_dir,
        permits=args.permit_dir, target_public=args.target_public_key,
        compose_config=args.compose_config,
        freshness_challenge=args.freshness_challenge,
        durable_challenge=args.durable_challenge,
    ))
    (args.report_dir / "iam_reconciliation_reconcile.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "result": result["result"],
        "phase": result["phase"],
        "effect_state": result["effect_state_after"],
        "signed_remote_receipt_verified": True,
        "target_post_retried": False,
        "production_claim": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
