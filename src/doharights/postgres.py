"""Authenticated PostgreSQL port for current-use DohaRights records."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from datetime import datetime
from typing import Any, Protocol, cast
from uuid import UUID

from .authority import (
    CurrentRightsRead,
    CurrentUseAuthorization,
    HistoricalAcquisitionReceiptState,
    IssueRightsCommand,
    ReplaceRightsCommand,
    RightsAuthorityError,
    RightsEvidenceReference,
    RightsEvidenceType,
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
    canonical_bytes,
    canonical_fingerprint,
)


class Cursor(Protocol):
    def execute(self, query: str, params: tuple[object, ...]) -> None: ...
    def fetchone(self) -> Mapping[str, Any] | tuple[Any, ...] | None: ...
    def __enter__(self) -> Cursor: ...
    def __exit__(self, *args: object) -> None: ...


class Connection(Protocol):
    def cursor(self, *, row_factory: object | None = None) -> AbstractContextManager[Cursor]: ...
    def __enter__(self) -> Connection: ...
    def __exit__(self, *args: object) -> None: ...


class PostgresCurrentRightsAuthority:
    """Use only SECURITY DEFINER functions; callers never receive table DML."""

    def __init__(self, connect: Callable[[], AbstractContextManager[Connection]]) -> None:
        if not callable(connect):
            raise RightsAuthorityError("RIGHTS_POSTGRES_CONFIG_INVALID")
        self._connect = connect

    def issue(self, command: IssueRightsCommand) -> CurrentRightsRead:
        record = command.record
        token = RightsSourceToken.issue(record, 1)
        payload_bytes = canonical_bytes(record)
        payload = json.loads(payload_bytes)
        params: tuple[object, ...] = (
            command.request_id,
            canonical_fingerprint(command),
            record.record_id,
            record.source_authority.source_authority_id,
            record.subject.rights_subject_id,
            record.subject.dataset_source_identity,
            record.subject.kind.value,
            record.subject.bound_identity,
            record.fingerprint,
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            payload_bytes,
            record.permissions.internal_training,
            record.permissions.commercial_use,
            record.permissions.redistribution,
            record.permissions.external_model_publication,
            record.effective_at,
            json.dumps(record.provenance_references),
            record.producer_authority_id,
            command.event_id,
            command.occurred_at,
            command.reason,
            token.token_fingerprint,
            record.status.value,
            json.dumps(_json_value(record.source_classification)),
            record.permissions.analysis,
            record.permissions.derivative_generation,
            json.dumps(_json_value(record.retention)),
            json.dumps(record.consent_evidence_references),
            record.jurisdiction,
            record.review.reviewer_authority_id,
            record.review.reviewed_at,
            json.dumps(_json_value(record.current_use_authorization)),
            json.dumps(_json_value(record.evidence_references)),
        )
        row = self._one(
            "SELECT * FROM doharights_v1.issue_current_use_rights("
            + ",".join(["%s"] * len(params))
            + ")",
            params,
        )
        revision = int(_field(row, "projection_revision", 1))
        returned_token = str(_field(row, "source_token_fingerprint", 2)).strip()
        actual = RightsSourceToken.issue(record, revision)
        if returned_token != actual.token_fingerprint:
            raise RightsAuthorityError("RIGHTS_POSTGRES_RESPONSE_INVALID")
        return CurrentRightsRead(record, actual)

    def get_current_rights(self, subject: RightsSubject) -> CurrentRightsRead:
        row = self._one(
            "SELECT * FROM doharights_v1.get_current_use_rights(%s)",
            (subject.rights_subject_id,),
        )
        payload = _field(row, "canonical_payload", 0)
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, Mapping):
            raise RightsAuthorityError("RIGHTS_POSTGRES_RESPONSE_INVALID")
        record = rights_record_from_mapping(payload)
        if record.subject != subject:
            raise RightsAuthorityError("RIGHTS_SUBJECT_MISMATCH")
        revision = int(_field(row, "projection_revision", 3))
        token = RightsSourceToken.issue(record, revision)
        if str(_field(row, "source_token_fingerprint", 4)).strip() != token.token_fingerprint:
            raise RightsAuthorityError("RIGHTS_POSTGRES_RESPONSE_INVALID")
        return CurrentRightsRead(record, token)

    def replace(self, command: ReplaceRightsCommand) -> CurrentRightsRead:
        record = command.replacement
        current = self.get_current_rights(record.subject)
        if current.record.record_id != command.expected_current_record_id:
            raise RightsAuthorityError("RIGHTS_EXPECTED_CURRENT_MISMATCH")
        token = RightsSourceToken.issue(record, current.source_token.projection_revision + 1)
        payload_bytes = canonical_bytes(record)
        payload = json.loads(payload_bytes)
        params: tuple[object, ...] = (
            command.request_id,
            canonical_fingerprint(command),
            command.expected_current_record_id,
            record.record_id,
            record.source_authority.source_authority_id,
            record.subject.rights_subject_id,
            record.fingerprint,
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            payload_bytes,
            record.permissions.internal_training,
            record.permissions.commercial_use,
            record.permissions.redistribution,
            record.permissions.external_model_publication,
            record.effective_at,
            json.dumps(record.provenance_references),
            record.producer_authority_id,
            command.supersede_event_id,
            command.issue_event_id,
            command.occurred_at,
            command.reason,
            token.token_fingerprint,
            record.status.value,
            json.dumps(_json_value(record.source_classification)),
            record.permissions.analysis,
            record.permissions.derivative_generation,
            json.dumps(_json_value(record.retention)),
            json.dumps(record.consent_evidence_references),
            record.jurisdiction,
            record.review.reviewer_authority_id,
            record.review.reviewed_at,
            json.dumps(_json_value(record.current_use_authorization)),
            json.dumps(_json_value(record.evidence_references)),
        )
        row = self._one(
            "SELECT * FROM doharights_v1.replace_current_use_rights("
            + ",".join(["%s"] * len(params))
            + ")",
            params,
        )
        revision = int(_field(row, "projection_revision", 1))
        actual = RightsSourceToken.issue(record, revision)
        if str(_field(row, "source_token_fingerprint", 2)).strip() != actual.token_fingerprint:
            raise RightsAuthorityError("RIGHTS_POSTGRES_RESPONSE_INVALID")
        return CurrentRightsRead(record, actual)

    def verify_currentness(self, token: RightsSourceToken) -> CurrentRightsRead:
        current = self.get_current_rights(token.subject)
        if current.source_token != token:
            raise RightsAuthorityError("RIGHTS_SOURCE_TOKEN_STALE")
        return current

    def _one(self, query: str, params: tuple[object, ...]) -> Mapping[str, Any] | tuple[Any, ...]:
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()
        except RightsAuthorityError:
            raise
        except Exception:
            raise RightsAuthorityError("RIGHTS_POSTGRES_UNAVAILABLE") from None
        if row is None:
            raise RightsAuthorityError("RIGHTS_CURRENT_MISSING")
        return row


def rights_record_from_mapping(value: Mapping[str, Any]) -> RightsRecord:
    """Rebuild the exact typed immutable record returned by the owner authority."""

    try:
        source = cast(Mapping[str, Any], value["source_authority"])
        subject = cast(Mapping[str, Any], value["subject"])
        permissions = cast(Mapping[str, Any], value["permissions"])
        classification = cast(Mapping[str, Any], value["source_classification"])
        retention = cast(Mapping[str, Any], value["retention"])
        review = cast(Mapping[str, Any], value["review"])
        current_use = cast(Mapping[str, Any], value["current_use_authorization"])
        evidence = cast(list[Mapping[str, Any]], value["evidence_references"])
        return RightsRecord(
            record_id=UUID(str(value["record_id"])),
            source_authority=SourceAuthority(UUID(str(source["source_authority_id"]))),
            subject=RightsSubject(
                UUID(str(subject["rights_subject_id"])),
                str(subject["dataset_source_identity"]),
                RightsSubjectKind(str(subject["kind"])),
                str(subject["bound_identity"]),
            ),
            permissions=RightsPermissions(
                bool(permissions["internal_training"]),
                bool(permissions["commercial_use"]),
                bool(permissions["redistribution"]),
                bool(permissions["external_model_publication"]),
                bool(permissions["analysis"]),
                bool(permissions["derivative_generation"]),
            ),
            status=RightsStatus(str(value["status"])),
            source_classification=RightsSourceClassification(
                str(classification["source_type"]),
                bool(classification["user_created"]),
                bool(classification["generated"]),
                bool(classification["reference"]),
                bool(classification["uploaded"]),
                bool(classification["external"]),
            ),
            retention=RightsRetention(
                bool(retention["allowed"]),
                RightsRetentionMode(str(retention["mode"])),
                str(retention["scope"]),
                _time(retention.get("expires_at")),
            ),
            consent_evidence_references=tuple(value["consent_evidence_references"]),
            jurisdiction=str(value["jurisdiction"]),
            review=RightsReview(
                UUID(str(review["reviewer_authority_id"])),
                cast(datetime, _time(review["reviewed_at"])),
            ),
            current_use_authorization=CurrentUseAuthorization(
                bool(current_use["authorized"]),
                str(current_use["scope"]),
                bool(current_use["fresh_acquisition_required"]),
                bool(current_use["existing_material_reuse"]),
                HistoricalAcquisitionReceiptState(
                    str(current_use["historical_acquisition_receipt"])
                ),
                bool(current_use["provider_reacquisition_requirement_found"]),
            ),
            evidence_references=tuple(
                RightsEvidenceReference(
                    str(item["reference_id"]),
                    RightsEvidenceType(str(item["evidence_type"])),
                    str(item["authority"]),
                    str(item["locator"]),
                    cast(datetime, _time(item["observed_at"])),
                    cast(str | None, item.get("content_fingerprint")),
                )
                for item in evidence
            ),
            effective_at=cast(datetime, _time(value["effective_at"])),
            provenance_references=tuple(value["provenance_references"]),
            producer_authority_id=UUID(str(value["producer_authority_id"])),
            previous_record_id=(
                UUID(str(value["previous_record_id"]))
                if value.get("previous_record_id") is not None
                else None
            ),
        )
    except (KeyError, TypeError, ValueError, RightsAuthorityError):
        raise RightsAuthorityError("RIGHTS_POSTGRES_RESPONSE_INVALID") from None


def _json_value(value: object) -> Any:
    return json.loads(canonical_bytes(value))


def _time(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError
    return parsed


def _field(row: Mapping[str, Any] | tuple[Any, ...], name: str, index: int) -> Any:
    return row[name] if isinstance(row, Mapping) else row[index]


__all__ = ["PostgresCurrentRightsAuthority", "rights_record_from_mapping"]
