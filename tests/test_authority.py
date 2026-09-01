from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from threading import Barrier, Thread
from uuid import UUID, uuid4

import pytest

from src.doharights import (
    CurrentUseAuthorization,
    DohaRightsAuthority,
    HistoricalAcquisitionReceiptState,
    IssueRightsCommand,
    ReplaceRightsCommand,
    RevokeRightsCommand,
    RightsAuthorityError,
    RightsEvidenceReference,
    RightsEvidenceType,
    RightsLifecycleEventType,
    RightsPermissions,
    RightsRecord,
    RightsRetention,
    RightsRetentionMode,
    RightsReview,
    RightsSourceClassification,
    RightsSourceToken,
    RightsStatus,
    RightsSubject,
    RightsSubjectKind,
    SourceAuthority,
    canonical_fingerprint,
)
from src.doharights.authority import canonical_bytes
from src.doharights.postgres import rights_record_from_mapping

NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
SOURCE_ID = UUID("11111111-1111-4111-8111-111111111111")
PRODUCER_ID = UUID("22222222-2222-4222-8222-222222222222")
REVIEWER_ID = UUID("22222222-2222-4222-8222-333333333333")
SUBJECT_ID = UUID("33333333-3333-4333-8333-333333333333")
RECORD_ID = UUID("44444444-4444-4444-8444-444444444444")


def subject(kind: RightsSubjectKind = RightsSubjectKind.SOURCE_DATASET) -> RightsSubject:
    return RightsSubject(SUBJECT_ID, "AIHUB-71748", kind, "AIHUB-71748")


def record(
    record_id: UUID = RECORD_ID,
    *,
    previous: UUID | None = None,
    source: SourceAuthority | None = None,
    producer: UUID = PRODUCER_ID,
) -> RightsRecord:
    return RightsRecord(
        record_id,
        source or SourceAuthority(SOURCE_ID),
        subject(),
        RightsPermissions(True, False, False, False, True, True),
        RightsStatus.APPROVED_LIMITED,
        RightsSourceClassification("external", False, False, False, False, True),
        RightsRetention(True, RightsRetentionMode.INDEFINITE_WHILE_CURRENT, "training"),
        (),
        "KR",
        RightsReview(REVIEWER_ID, NOW),
        CurrentUseAuthorization(
            True,
            "internal_noncommercial_model_training_and_evaluation",
            False,
            True,
            HistoricalAcquisitionReceiptState.NOT_RECOVERED,
            False,
        ),
        (
            RightsEvidenceReference(
                "evidence:aihub-current-usage-policy",
                RightsEvidenceType.PROVIDER_USAGE_POLICY,
                "AI Hub",
                "https://aihub.or.kr/intrcn/guid/usagepolicy.do",
                NOW,
            ),
        ),
        NOW,
        ("evidence:candidate-a-eligibility",),
        producer,
        previous,
    )


def issue_command(
    value: RightsRecord | None = None, request_id: UUID | None = None
) -> IssueRightsCommand:
    return IssueRightsCommand(
        request_id or uuid4(), value or record(), uuid4(), PRODUCER_ID, NOW, "approved"
    )


def authority() -> DohaRightsAuthority:
    return DohaRightsAuthority(SourceAuthority(SOURCE_ID), PRODUCER_ID)


def assert_code(code: str, action) -> None:
    with pytest.raises(RightsAuthorityError) as captured:
        action()
    assert captured.value.code == code


def test_source_subject_and_record_are_frozen_and_versioned() -> None:
    current = record()
    assert current.source_authority.origin_domain == "DohaRights"
    assert current.schema_version == "rights-authority-v1"
    assert current.subject.dataset_source_identity == "AIHUB-71748"
    assert current.permissions == RightsPermissions(True, False, False, False, True, True)
    assert current.retention.mode is RightsRetentionMode.INDEFINITE_WHILE_CURRENT
    assert current.consent_evidence_references == ()
    with pytest.raises((AttributeError, TypeError)):
        current.permissions.internal_training = False  # type: ignore[misc]


@pytest.mark.parametrize(
    "kind,binding",
    [
        (RightsSubjectKind.SOURCE_DATASET, "AIHUB-71748"),
        (RightsSubjectKind.DATASET_VERSION, "AIHUB-71748/pilot-v2"),
        (RightsSubjectKind.DERIVED_ARTIFACT, "sha256:derived-artifact-identity"),
    ],
)
def test_explicit_subject_granularity(kind: RightsSubjectKind, binding: str) -> None:
    actual = RightsSubject(uuid4(), "AIHUB-71748", kind, binding)
    assert actual.kind is kind
    assert actual.bound_identity == binding


def test_path_is_not_a_dataset_source_logical_identity() -> None:
    assert_code(
        "RIGHTS_DATASET_SOURCE_INVALID",
        lambda: RightsSubject(
            uuid4(), "C:\\datasets\\candidate-a", RightsSubjectKind.SOURCE_DATASET, "x"
        ),
    )


def test_canonical_fingerprint_has_golden_parity() -> None:
    value = record()
    assert value.fingerprint == canonical_fingerprint(value)
    assert (
        value.fingerprint
        == "sha256:968367e585436c200b370b49347ae67967852314c82996b4adb0ffe898ab45a1"
    )


def test_issue_read_and_verify_source_token() -> None:
    service = authority()
    issued = service.issue(issue_command())
    assert issued.record.record_id == RECORD_ID
    assert issued.source_token.projection_revision == 1
    assert service.get_current_rights(subject()) == issued
    assert service.verify_currentness(issued.source_token) == issued
    assert service.history(subject())[0].event_type is RightsLifecycleEventType.ISSUED


def test_exact_issue_replay_and_conflicting_replay() -> None:
    service = authority()
    request_id = uuid4()
    command = issue_command(request_id=request_id)
    first = service.issue(command)
    assert service.issue(command) == first
    conflicting = replace(command, reason="different")
    assert_code("RIGHTS_REQUEST_CONFLICT", lambda: service.issue(conflicting))
    assert len(service.history(subject())) == 1


def test_reader_cannot_issue_with_wrong_authority() -> None:
    service = authority()
    command = replace(issue_command(), actor_authority_id=uuid4())
    assert_code("RIGHTS_PRODUCER_UNAUTHORIZED", lambda: service.issue(command))
    assert_code("RIGHTS_CURRENT_MISSING", lambda: service.get_current_rights(subject()))


def test_wrong_source_authority_is_rejected() -> None:
    service = authority()
    wrong = record(source=SourceAuthority(uuid4()))
    assert_code("RIGHTS_SOURCE_AUTHORITY_MISMATCH", lambda: service.issue(issue_command(wrong)))


def test_reviewer_and_producer_must_be_distinct() -> None:
    assert_code(
        "RIGHTS_REVIEWER_PRODUCER_COLLISION",
        lambda: replace(record(), review=RightsReview(PRODUCER_ID, NOW)),
    )


def test_current_use_facts_are_in_record_fingerprint_and_token() -> None:
    base = record()
    changed = replace(
        base,
        current_use_authorization=replace(
            base.current_use_authorization,
            historical_acquisition_receipt=HistoricalAcquisitionReceiptState.RECOVERED,
        ),
    )
    assert base.fingerprint != changed.fingerprint
    assert RightsSourceToken.issue(base, 1).token_fingerprint != (
        RightsSourceToken.issue(changed, 1).token_fingerprint
    )


def test_canonical_current_use_record_round_trips_from_postgres_payload() -> None:
    value = record()
    restored = rights_record_from_mapping(json.loads(canonical_bytes(value)))
    assert restored == value
    assert restored.fingerprint == value.fingerprint


def test_replace_is_append_only_and_old_token_becomes_stale() -> None:
    service = authority()
    first = service.issue(issue_command())
    replacement_id = UUID("55555555-5555-4555-8555-555555555555")
    new_record = record(replacement_id, previous=RECORD_ID)
    result = service.replace(
        ReplaceRightsCommand(
            uuid4(), RECORD_ID, new_record, uuid4(), uuid4(), PRODUCER_ID, NOW, "renewed"
        )
    )
    assert result.record.record_id == replacement_id
    assert result.source_token.projection_revision == 2
    assert [event.event_type for event in service.history(subject())] == [
        RightsLifecycleEventType.ISSUED,
        RightsLifecycleEventType.SUPERSEDED,
        RightsLifecycleEventType.ISSUED,
    ]
    assert_code("RIGHTS_SOURCE_TOKEN_STALE", lambda: service.verify_currentness(first.source_token))


def test_replace_requires_exact_current_and_chain() -> None:
    service = authority()
    service.issue(issue_command())
    bad = record(uuid4(), previous=uuid4())
    command = ReplaceRightsCommand(
        uuid4(), RECORD_ID, bad, uuid4(), uuid4(), PRODUCER_ID, NOW, "renewed"
    )
    assert_code("RIGHTS_REPLACEMENT_CHAIN_INVALID", lambda: service.replace(command))


def test_revoke_preserves_history_and_removes_current() -> None:
    service = authority()
    current = service.issue(issue_command())
    event = service.revoke(
        RevokeRightsCommand(
            uuid4(), subject(), RECORD_ID, uuid4(), PRODUCER_ID, NOW, "withdrawn", ("case:1",)
        )
    )
    assert event.event_type is RightsLifecycleEventType.REVOKED
    assert len(service.history(subject())) == 2
    assert_code("RIGHTS_CURRENT_MISSING", lambda: service.get_current_rights(subject()))
    assert_code("RIGHTS_CURRENT_MISSING", lambda: service.verify_currentness(current.source_token))


def test_token_tamper_is_rejected() -> None:
    token = RightsSourceToken.issue(record(), 1)
    assert_code(
        "RIGHTS_SOURCE_TOKEN_TAMPERED",
        lambda: RightsSourceToken(
            token.source_authority,
            token.subject,
            token.record_id,
            token.record_fingerprint,
            token.projection_revision,
            "sha256:" + "0" * 64,
        ),
    )


def test_concurrent_issue_allows_only_one_current() -> None:
    service = authority()
    gate = Barrier(3)
    results: list[str] = []

    def run(value: RightsRecord) -> None:
        gate.wait()
        try:
            service.issue(issue_command(value))
            results.append("issued")
        except RightsAuthorityError as exc:
            results.append(exc.code)

    workers = [Thread(target=run, args=(record(uuid4()),)) for _ in range(2)]
    for worker in workers:
        worker.start()
    gate.wait()
    for worker in workers:
        worker.join()
    assert sorted(results) == ["RIGHTS_CURRENT_ALREADY_EXISTS", "issued"]
    assert service.get_current_rights(subject()).record.record_id in service._records


def test_no_filesystem_or_cache_fallback_on_missing_current() -> None:
    service = authority()
    assert_code("RIGHTS_CURRENT_MISSING", lambda: service.get_current_rights(subject()))
