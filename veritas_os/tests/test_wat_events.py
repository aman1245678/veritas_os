"""Unit tests for WAT event-lane revocation state derivation."""

from __future__ import annotations

from pathlib import Path

import pytest

from veritas_os.audit import wat_events
from veritas_os.audit.wat_events import (
    derive_latest_revocation_state,
    persist_wat_validation_event,
    persist_wat_issuance_event,
    persist_wat_revocation_event,
    list_wat_events,
)


def test_derive_latest_revocation_state_defaults_active(tmp_path: Path) -> None:
    state = derive_latest_revocation_state("missing-wat", path=tmp_path / "wat_events.jsonl")
    assert state["status"] == "active"
    assert state["source"] == "wat_events"


def test_derive_latest_revocation_state_pending(tmp_path: Path) -> None:
    path = tmp_path / "wat_events.jsonl"
    persist_wat_issuance_event(wat_id="wat-1", actor="test", path=path)
    persist_wat_revocation_event(wat_id="wat-1", actor="test", confirmed=False, path=path)
    state = derive_latest_revocation_state("wat-1", path=path)
    assert state["status"] == "revoked_pending"
    assert state["source"] == "wat_events"


def test_derive_latest_revocation_state_confirmed(tmp_path: Path) -> None:
    path = tmp_path / "wat_events.jsonl"
    persist_wat_issuance_event(wat_id="wat-2", actor="test", path=path)
    persist_wat_revocation_event(wat_id="wat-2", actor="test", confirmed=False, path=path)
    persist_wat_revocation_event(wat_id="wat-2", actor="test", confirmed=True, path=path)
    state = derive_latest_revocation_state("wat-2", path=path)
    assert state["status"] == "revoked_confirmed"
    assert state["source"] == "wat_events"


@pytest.mark.parametrize("confirmed", [False, True])
def test_revocation_survives_browsing_window(
    tmp_path: Path, monkeypatch, confirmed: bool,
) -> None:
    """Validation telemetry cannot hide a retained revocation after 500 rows."""
    monkeypatch.setattr(wat_events, "_build_anchor_reference", lambda event: {})
    path = tmp_path / "wat_events.jsonl"
    revoked = persist_wat_revocation_event(
        wat_id="revoked", actor="test", confirmed=confirmed, path=path,
    )
    for _ in range(500):
        persist_wat_validation_event(wat_id="revoked", actor="test", path=path)
    # The browsing cap is intentional; it must not define revocation state.
    assert len(list_wat_events(wat_id="revoked", limit=1000, path=path)) == 500
    state = derive_latest_revocation_state("revoked", path=path)
    assert state["status"] == ("revoked_confirmed" if confirmed else "revoked_pending")
    assert state["event_id"] == revoked["event_id"]
    assert derive_latest_revocation_state("other-wat", path=path)["status"] == "active"


def test_confirmed_revocation_survives_later_pending(tmp_path: Path, monkeypatch) -> None:
    """A later pending request is not an explicit revocation reset."""
    monkeypatch.setattr(wat_events, "_build_anchor_reference", lambda event: {})
    path = tmp_path / "wat_events.jsonl"
    revoked = persist_wat_revocation_event(
        wat_id="revoked", actor="test", confirmed=True, path=path,
    )
    persist_wat_revocation_event(
        wat_id="revoked", actor="test", confirmed=False, path=path,
    )
    state = derive_latest_revocation_state("revoked", path=path)
    assert state["status"] == "revoked_confirmed"
    assert state["event_id"] == revoked["event_id"]


def test_primary_audit_path_stores_metadata_and_pointers_only(tmp_path: Path) -> None:
    path = tmp_path / "wat_events.jsonl"
    event = persist_wat_issuance_event(
        wat_id="wat-boundary-1",
        actor="test",
        details={
            "psid": "psid-1",
            "metadata": {"request_id": "rid-1"},
            "observable_digest_ref": "separate_store://digests/wat-boundary-1",
            "observable_digest_payload": {"raw": "must-not-persist"},
        },
        path=path,
    )

    details = event["details"]
    assert "metadata" in details
    assert "event_pointers" in details
    assert (
        details["event_pointers"]["observable_digest_ref"]
        == "separate_store://digests/wat-boundary-1"
    )
    assert "observable_digest_payload" not in details


def test_observable_digest_payload_not_accepted_as_ref(tmp_path: Path) -> None:
    path = tmp_path / "wat_events.jsonl"
    event = persist_wat_issuance_event(
        wat_id="wat-boundary-legacy-1",
        actor="test",
        details={
            "observable_digest": "sha256:deadbeef",
        },
        path=path,
    )

    assertion = event["details"]["retention_boundary_assertion"]
    assert assertion["outcome"] == "failed"
    assert "observable_digest_payload_not_accepted_as_ref" in assertion["failed_reasons"]


def test_observable_digest_ref_must_be_locator_not_payload(tmp_path: Path) -> None:
    path = tmp_path / "wat_events.jsonl"
    event = persist_wat_issuance_event(
        wat_id="wat-boundary-legacy-3",
        actor="test",
        details={
            "observable_digest_ref": "sha256:deadbeef",
        },
        path=path,
    )

    assertion = event["details"]["retention_boundary_assertion"]
    pointers = event["details"]["event_pointers"]
    assert "observable_digest_ref" not in pointers
    assert assertion["outcome"] == "failed"
    assert "observable_digest_ref_not_locator" in assertion["failed_reasons"]


def test_legacy_locator_fallback_is_transitional_and_flagged(tmp_path: Path) -> None:
    path = tmp_path / "wat_events.jsonl"
    event = persist_wat_issuance_event(
        wat_id="wat-boundary-legacy-2",
        actor="test",
        details={
            "observable_digest": "separate_store://digests/wat-boundary-legacy-2",
        },
        path=path,
    )

    assertion = event["details"]["retention_boundary_assertion"]
    assert event["details"]["event_pointers"]["observable_digest_ref"].startswith(
        "separate_store://digests/"
    )
    assert assertion["outcome"] == "failed"
    assert "legacy_observable_digest_ref_fallback_used" in assertion["failed_reasons"]


def test_retention_policy_version_immutable_after_enforcement(tmp_path: Path) -> None:
    path = tmp_path / "wat_events.jsonl"
    persist_wat_issuance_event(
        wat_id="wat-boundary-2",
        actor="test",
        details={
            "retention_policy_version": "wat_retention_v1",
            "retention_enforced_at_write": True,
        },
        path=path,
    )

    with pytest.raises(ValueError, match="immutable"):
        persist_wat_validation_event(
            wat_id="wat-boundary-2",
            actor="test",
            details={
                "retention_policy_version": "wat_retention_v2",
                "retention_enforced_at_write": True,
            },
            path=path,
        )


def test_warning_events_include_traceability_context_and_correlation(tmp_path: Path) -> None:
    path = tmp_path / "wat_events.jsonl"
    event = persist_wat_validation_event(
        wat_id="wat-warning-1",
        actor="test",
        event_type="wat_validation_failed",
        status="warning",
        details={"reason": "revocation_pending"},
        path=path,
    )
    metadata = event["details"]["metadata"]
    assert metadata["warning_context"] == "wat_shadow_warning"
    assert metadata["warning_correlation_id"]


@pytest.mark.parametrize(
    "transition_event",
    [
        "wat_issued",
        "wat_replay_suspected",
        "wat_revocation_pending",
        "wat_revoked_confirmed",
    ],
)
def test_validation_helper_rejects_non_validation_events(
    tmp_path: Path,
    transition_event: str,
) -> None:
    """Lifecycle transitions must use their dedicated persistence helpers."""
    path = tmp_path / "wat_events.jsonl"

    with pytest.raises(ValueError, match="unsupported_wat_validation_event_type"):
        persist_wat_validation_event(
            wat_id="wat-helper-isolation",
            actor="test",
            event_type=transition_event,
            path=path,
        )

    assert not path.exists()
