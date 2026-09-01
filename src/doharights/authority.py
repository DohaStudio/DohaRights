"""Append-only DohaRights domain authority and source-token contract."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, TypeVar, cast
from uuid import UUID

SCHEMA_VERSION = "rights-authority-v1"
TOKEN_SCHEMA_VERSION = "rights-source-token-v1"
ORIGIN_DOMAIN = "DohaRights"


class RightsAuthorityError(RuntimeError):
    """Fail-closed authority error with a stable public code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RightsSubjectKind(str, Enum):
    SOURCE_DATASET = "source_dataset"
    DATASET_VERSION = "dataset_version"
    DERIVED_ARTIFACT = "derived_artifact"


class RightsLifecycleEventType(str, Enum):
    ISSUED = "issued"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


def _require_text(value: str, code: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise RightsAuthorityError(code)


def _require_aware(value: datetime, code: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RightsAuthorityError(code)
    return value.astimezone(timezone.utc)


def _canonical(value: Any) -> Any:
    if is_dataclass(value):
        return {field.name: _canonical(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return _require_aware(value, "RIGHTS_TIMESTAMP_INVALID").isoformat().replace("+00:00", "Z")
    if isinstance(value, tuple):
        return [_canonical(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise RightsAuthorityError("RIGHTS_CANONICAL_VALUE_INVALID")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _canonical(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def canonical_fingerprint(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_bytes(value)).hexdigest()}"


@dataclass(frozen=True, slots=True)
class SourceAuthority:
    source_authority_id: UUID
    schema_version: str = SCHEMA_VERSION
    origin_domain: str = ORIGIN_DOMAIN

    def __post_init__(self) -> None:
        if (
            self.source_authority_id.int == 0
            or self.schema_version != SCHEMA_VERSION
            or self.origin_domain != ORIGIN_DOMAIN
        ):
            raise RightsAuthorityError("RIGHTS_SOURCE_AUTHORITY_INVALID")


@dataclass(frozen=True, slots=True)
class RightsSubject:
    rights_subject_id: UUID
    dataset_source_identity: str
    kind: RightsSubjectKind
    bound_identity: str

    def __post_init__(self) -> None:
        if self.rights_subject_id.int == 0:
            raise RightsAuthorityError("RIGHTS_SUBJECT_INVALID")
        _require_text(self.dataset_source_identity, "RIGHTS_DATASET_SOURCE_INVALID")
        _require_text(self.bound_identity, "RIGHTS_SUBJECT_BINDING_INVALID")
        if "/" in self.dataset_source_identity or "\\" in self.dataset_source_identity:
            raise RightsAuthorityError("RIGHTS_DATASET_SOURCE_INVALID")


@dataclass(frozen=True, slots=True)
class RightsPermissions:
    internal_training: bool
    commercial_use: bool
    redistribution: bool
    external_model_publication: bool


@dataclass(frozen=True, slots=True)
class RightsRecord:
    record_id: UUID
    source_authority: SourceAuthority
    subject: RightsSubject
    permissions: RightsPermissions
    effective_at: datetime
    provenance_references: tuple[str, ...]
    producer_authority_id: UUID
    previous_record_id: UUID | None = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.record_id.int == 0 or self.producer_authority_id.int == 0:
            raise RightsAuthorityError("RIGHTS_RECORD_IDENTITY_INVALID")
        _require_aware(self.effective_at, "RIGHTS_EFFECTIVE_AT_INVALID")
        if self.schema_version != SCHEMA_VERSION:
            raise RightsAuthorityError("RIGHTS_RECORD_SCHEMA_INVALID")
        if not self.provenance_references:
            raise RightsAuthorityError("RIGHTS_PROVENANCE_REQUIRED")
        for reference in self.provenance_references:
            _require_text(reference, "RIGHTS_PROVENANCE_INVALID")

    @property
    def fingerprint(self) -> str:
        return canonical_fingerprint(self)


@dataclass(frozen=True, slots=True)
class RightsLifecycleEvent:
    event_id: UUID
    event_type: RightsLifecycleEventType
    subject_id: UUID
    record_id: UUID
    actor_authority_id: UUID
    occurred_at: datetime
    previous_record_id: UUID | None
    reason: str
    provenance_references: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.event_id.int == 0 or self.actor_authority_id.int == 0:
            raise RightsAuthorityError("RIGHTS_EVENT_IDENTITY_INVALID")
        _require_aware(self.occurred_at, "RIGHTS_EVENT_TIME_INVALID")
        _require_text(self.reason, "RIGHTS_EVENT_REASON_REQUIRED")


@dataclass(frozen=True, slots=True)
class RightsSourceToken:
    source_authority: SourceAuthority
    subject: RightsSubject
    record_id: UUID
    record_fingerprint: str
    projection_revision: int
    token_fingerprint: str
    schema_version: str = TOKEN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.record_id.int == 0
            or self.projection_revision < 1
            or self.schema_version != TOKEN_SCHEMA_VERSION
            or not self.record_fingerprint.startswith("sha256:")
        ):
            raise RightsAuthorityError("RIGHTS_SOURCE_TOKEN_INVALID")
        if self.token_fingerprint != canonical_fingerprint(self.payload()):
            raise RightsAuthorityError("RIGHTS_SOURCE_TOKEN_TAMPERED")

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source_authority": asdict(self.source_authority),
            "subject": asdict(self.subject),
            "record_id": self.record_id,
            "record_fingerprint": self.record_fingerprint,
            "projection_revision": self.projection_revision,
        }

    @classmethod
    def issue(cls, record: RightsRecord, projection_revision: int) -> RightsSourceToken:
        payload = {
            "schema_version": TOKEN_SCHEMA_VERSION,
            "source_authority": asdict(record.source_authority),
            "subject": asdict(record.subject),
            "record_id": record.record_id,
            "record_fingerprint": record.fingerprint,
            "projection_revision": projection_revision,
        }
        return cls(
            record.source_authority,
            record.subject,
            record.record_id,
            record.fingerprint,
            projection_revision,
            canonical_fingerprint(payload),
        )


@dataclass(frozen=True, slots=True)
class CurrentRightsRead:
    record: RightsRecord
    source_token: RightsSourceToken


@dataclass(frozen=True, slots=True)
class IssueRightsCommand:
    request_id: UUID
    record: RightsRecord
    event_id: UUID
    actor_authority_id: UUID
    occurred_at: datetime
    reason: str


@dataclass(frozen=True, slots=True)
class ReplaceRightsCommand:
    request_id: UUID
    expected_current_record_id: UUID
    replacement: RightsRecord
    supersede_event_id: UUID
    issue_event_id: UUID
    actor_authority_id: UUID
    occurred_at: datetime
    reason: str


@dataclass(frozen=True, slots=True)
class RevokeRightsCommand:
    request_id: UUID
    subject: RightsSubject
    expected_current_record_id: UUID
    event_id: UUID
    actor_authority_id: UUID
    occurred_at: datetime
    reason: str
    provenance_references: tuple[str, ...]


class CurrentRightsAuthority(Protocol):
    def get_current_rights(self, subject: RightsSubject) -> CurrentRightsRead: ...

    def verify_currentness(self, token: RightsSourceToken) -> CurrentRightsRead: ...


T = TypeVar("T")


class DohaRightsAuthority:
    """Thread-safe reference authority used by adapters and deterministic tests."""

    def __init__(self, source_authority: SourceAuthority, producer_authority_id: UUID) -> None:
        if producer_authority_id.int == 0:
            raise RightsAuthorityError("RIGHTS_PRODUCER_INVALID")
        self.source_authority = source_authority
        self.producer_authority_id = producer_authority_id
        self._records: dict[UUID, RightsRecord] = {}
        self._current: dict[UUID, tuple[UUID, int]] = {}
        self._events: list[RightsLifecycleEvent] = []
        self._replays: dict[UUID, tuple[str, object]] = {}
        self._lock = threading.RLock()

    def _authorize(self, actor: UUID) -> None:
        if actor != self.producer_authority_id:
            raise RightsAuthorityError("RIGHTS_PRODUCER_UNAUTHORIZED")

    def _replay(self, request_id: UUID, command: object) -> object | None:
        if request_id.int == 0:
            raise RightsAuthorityError("RIGHTS_REQUEST_INVALID")
        previous = self._replays.get(request_id)
        if previous is None:
            return None
        if previous[0] != canonical_fingerprint(command):
            raise RightsAuthorityError("RIGHTS_REQUEST_CONFLICT")
        return previous[1]

    def _remember(self, request_id: UUID, command: object, result: T) -> T:
        self._replays[request_id] = (canonical_fingerprint(command), result)
        return result

    def _validate_record(self, record: RightsRecord) -> None:
        if record.source_authority != self.source_authority:
            raise RightsAuthorityError("RIGHTS_SOURCE_AUTHORITY_MISMATCH")
        if record.producer_authority_id != self.producer_authority_id:
            raise RightsAuthorityError("RIGHTS_PRODUCER_UNAUTHORIZED")

    def issue(self, command: IssueRightsCommand) -> CurrentRightsRead:
        with self._lock:
            replay = self._replay(command.request_id, command)
            if replay is not None:
                return cast(CurrentRightsRead, replay)
            self._authorize(command.actor_authority_id)
            self._validate_record(command.record)
            if command.record.previous_record_id is not None:
                raise RightsAuthorityError("RIGHTS_ISSUE_PREVIOUS_FORBIDDEN")
            subject_id = command.record.subject.rights_subject_id
            if subject_id in self._current:
                raise RightsAuthorityError("RIGHTS_CURRENT_ALREADY_EXISTS")
            if command.record.record_id in self._records:
                raise RightsAuthorityError("RIGHTS_RECORD_CONFLICT")
            self._records[command.record.record_id] = command.record
            self._events.append(
                RightsLifecycleEvent(
                    command.event_id,
                    RightsLifecycleEventType.ISSUED,
                    subject_id,
                    command.record.record_id,
                    command.actor_authority_id,
                    command.occurred_at,
                    None,
                    command.reason,
                    command.record.provenance_references,
                )
            )
            self._current[subject_id] = (command.record.record_id, 1)
            result = self.get_current_rights(command.record.subject)
            return self._remember(command.request_id, command, result)

    def replace(self, command: ReplaceRightsCommand) -> CurrentRightsRead:
        with self._lock:
            replay = self._replay(command.request_id, command)
            if replay is not None:
                return cast(CurrentRightsRead, replay)
            self._authorize(command.actor_authority_id)
            self._validate_record(command.replacement)
            subject_id = command.replacement.subject.rights_subject_id
            current = self._current.get(subject_id)
            if current is None or current[0] != command.expected_current_record_id:
                raise RightsAuthorityError("RIGHTS_EXPECTED_CURRENT_MISMATCH")
            if command.replacement.previous_record_id != command.expected_current_record_id:
                raise RightsAuthorityError("RIGHTS_REPLACEMENT_CHAIN_INVALID")
            if command.replacement.record_id in self._records:
                raise RightsAuthorityError("RIGHTS_RECORD_CONFLICT")
            previous = self._records[current[0]]
            if previous.subject != command.replacement.subject:
                raise RightsAuthorityError("RIGHTS_SUBJECT_MISMATCH")
            self._records[command.replacement.record_id] = command.replacement
            self._events.extend(
                (
                    RightsLifecycleEvent(
                        command.supersede_event_id,
                        RightsLifecycleEventType.SUPERSEDED,
                        subject_id,
                        previous.record_id,
                        command.actor_authority_id,
                        command.occurred_at,
                        previous.record_id,
                        command.reason,
                        command.replacement.provenance_references,
                    ),
                    RightsLifecycleEvent(
                        command.issue_event_id,
                        RightsLifecycleEventType.ISSUED,
                        subject_id,
                        command.replacement.record_id,
                        command.actor_authority_id,
                        command.occurred_at,
                        previous.record_id,
                        command.reason,
                        command.replacement.provenance_references,
                    ),
                )
            )
            self._current[subject_id] = (command.replacement.record_id, current[1] + 1)
            return self._remember(
                command.request_id, command, self.get_current_rights(command.replacement.subject)
            )

    def revoke(self, command: RevokeRightsCommand) -> RightsLifecycleEvent:
        with self._lock:
            replay = self._replay(command.request_id, command)
            if replay is not None:
                return cast(RightsLifecycleEvent, replay)
            self._authorize(command.actor_authority_id)
            current = self._current.get(command.subject.rights_subject_id)
            if current is None or current[0] != command.expected_current_record_id:
                raise RightsAuthorityError("RIGHTS_EXPECTED_CURRENT_MISMATCH")
            record = self._records[current[0]]
            if record.subject != command.subject:
                raise RightsAuthorityError("RIGHTS_SUBJECT_MISMATCH")
            event = RightsLifecycleEvent(
                command.event_id,
                RightsLifecycleEventType.REVOKED,
                command.subject.rights_subject_id,
                record.record_id,
                command.actor_authority_id,
                command.occurred_at,
                record.record_id,
                command.reason,
                command.provenance_references,
            )
            self._events.append(event)
            del self._current[command.subject.rights_subject_id]
            return self._remember(command.request_id, command, event)

    def get_current_rights(self, subject: RightsSubject) -> CurrentRightsRead:
        with self._lock:
            current = self._current.get(subject.rights_subject_id)
            if current is None:
                raise RightsAuthorityError("RIGHTS_CURRENT_MISSING")
            record = self._records.get(current[0])
            if record is None or record.subject != subject:
                raise RightsAuthorityError("RIGHTS_CURRENT_PROJECTION_INVALID")
            return CurrentRightsRead(record, RightsSourceToken.issue(record, current[1]))

    def verify_currentness(self, token: RightsSourceToken) -> CurrentRightsRead:
        with self._lock:
            if token.source_authority != self.source_authority:
                raise RightsAuthorityError("RIGHTS_SOURCE_AUTHORITY_MISMATCH")
            current = self.get_current_rights(token.subject)
            if current.source_token != token:
                raise RightsAuthorityError("RIGHTS_SOURCE_TOKEN_STALE")
            return current

    def history(self, subject: RightsSubject) -> tuple[RightsLifecycleEvent, ...]:
        with self._lock:
            return tuple(
                event for event in self._events if event.subject_id == subject.rights_subject_id
            )
