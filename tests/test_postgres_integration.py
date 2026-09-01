from __future__ import annotations

import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from src.doharights import (
    CurrentUseAuthorization,
    HistoricalAcquisitionReceiptState,
    IssueRightsCommand,
    PostgresCurrentRightsAuthority,
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
    RightsStatus,
    RightsSubject,
    RightsSubjectKind,
    SourceAuthority,
)

psycopg = pytest.importorskip("psycopg")

DSN = os.getenv("DOHARIGHTS_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.integration


def _connect_as(role: str):
    assert DSN is not None
    return psycopg.connect(DSN, user=role, password="doharights-test-only", autocommit=True)


@pytest.mark.skipif(DSN is None, reason="explicit ephemeral PostgreSQL DSN required")
def test_fresh_migration_lifecycle_replay_and_scoped_reader() -> None:
    assert DSN is not None
    migration = Path("src/doharights/postgres_migrations/0001_rights_authority.sql").read_text(
        encoding="utf-8"
    )
    current_use_migration = Path(
        "src/doharights/postgres_migrations/0002_current_use_rights.sql"
    ).read_text(encoding="utf-8")
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(migration)
        admin.execute(current_use_migration)
        admin.execute("CREATE ROLE rights_producer_py LOGIN PASSWORD 'doharights-test-only'")
        admin.execute("GRANT doharights_producer TO rights_producer_py")
        admin.execute("CREATE ROLE rights_reader_py LOGIN PASSWORD 'doharights-test-only'")
        admin.execute("GRANT doharights_reader TO rights_reader_py")
        admin.execute("CREATE ROLE rights_outsider_py LOGIN PASSWORD 'doharights-test-only'")

    now = datetime(2026, 9, 1, tzinfo=timezone.utc)
    current_use_subject = RightsSubject(
        UUID("66666666-6666-4666-8666-666666666666"),
        "AIHUB-71748-current-use",
        RightsSubjectKind.SOURCE_DATASET,
        "AIHUB-71748-current-use",
    )
    current_use_record = RightsRecord(
        UUID("77777777-7777-4777-8777-777777777777"),
        SourceAuthority(UUID("11111111-1111-4111-8111-111111111111")),
        current_use_subject,
        RightsPermissions(True, False, False, False, True, True),
        RightsStatus.APPROVED_LIMITED,
        RightsSourceClassification("external", False, False, False, False, True),
        RightsRetention(True, RightsRetentionMode.INDEFINITE_WHILE_CURRENT, "training"),
        (),
        "KR",
        RightsReview(UUID("88888888-8888-4888-8888-888888888888"), now),
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
                "evidence:aihub-current-policy",
                RightsEvidenceType.PROVIDER_USAGE_POLICY,
                "AI Hub",
                "https://aihub.or.kr/intrcn/guid/usagepolicy.do",
                now,
            ),
        ),
        now,
        ("evidence:aihub-current-policy",),
        UUID("22222222-2222-4222-8222-222222222222"),
    )
    writer = PostgresCurrentRightsAuthority(lambda: _connect_as("rights_producer_py"))
    issued = writer.issue(
        IssueRightsCommand(
            uuid4(),
            current_use_record,
            uuid4(),
            UUID("22222222-2222-4222-8222-222222222222"),
            now,
            "current-use authorization approved",
        )
    )
    reader_port = PostgresCurrentRightsAuthority(lambda: _connect_as("rights_reader_py"))
    assert reader_port.get_current_rights(current_use_subject) == issued
    assert reader_port.verify_currentness(issued.source_token) == issued
    replacement = replace(
        current_use_record,
        record_id=UUID("99999999-9999-4999-8999-999999999998"),
        previous_record_id=current_use_record.record_id,
    )
    replaced_current_use = writer.replace(
        ReplaceRightsCommand(
            uuid4(),
            current_use_record.record_id,
            replacement,
            uuid4(),
            uuid4(),
            UUID("22222222-2222-4222-8222-222222222222"),
            now,
            "current-use review renewed",
        )
    )
    assert reader_port.get_current_rights(current_use_subject) == replaced_current_use
    with pytest.raises(RightsAuthorityError, match="RIGHTS_SOURCE_TOKEN_STALE"):
        reader_port.verify_currentness(issued.source_token)

    record_hash = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    token1 = "sha256:" + "1" * 64
    token2 = "sha256:" + "2" * 64
    issue = """
        SELECT * FROM doharights_v1.issue_rights(
          'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', %s,
          '44444444-4444-4444-8444-444444444444',
          '11111111-1111-4111-8111-111111111111',
          '33333333-3333-4333-8333-333333333333',
          'AIHUB-71748', 'source_dataset', 'AIHUB-71748', %s,
          '{}'::jsonb, decode('7b7d','hex'), true, false, false, false,
          '2026-09-01T00:00:00Z', jsonb_build_array('evidence:test'),
          '22222222-2222-4222-8222-222222222222',
          'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
          '2026-09-01T00:00:00Z', 'approved', %s)
    """
    with _connect_as("rights_producer_py") as producer:
        first = producer.execute(issue, ("sha256:" + "a" * 64, record_hash, token1)).fetchone()
        replay = producer.execute(issue, ("sha256:" + "a" * 64, record_hash, token1)).fetchone()
        assert first == replay
        assert first == (UUID("44444444-4444-4444-8444-444444444444"), 1, token1)

    with _connect_as("rights_reader_py") as reader:
        current = reader.execute(
            "SELECT record_id::text, projection_revision, source_token_fingerprint "
            "FROM doharights_v1.get_current_rights(%s)",
            ("33333333-3333-4333-8333-333333333333",),
        ).fetchone()
        assert current == ("44444444-4444-4444-8444-444444444444", 1, token1)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            reader.execute(
                "INSERT INTO doharights_v1.rights_subject VALUES "
                "('99999999-9999-4999-8999-999999999999','x','source_dataset','x',0)"
            )

    with (
        _connect_as("rights_outsider_py") as outsider,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        outsider.execute(
            "SELECT * FROM doharights_v1.get_current_rights(%s)",
            ("33333333-3333-4333-8333-333333333333",),
        )

    replace_sql = """
        SELECT * FROM doharights_v1.replace_rights(
          'cccccccc-cccc-4ccc-8ccc-cccccccccccc', %s,
          '44444444-4444-4444-8444-444444444444',
          '55555555-5555-4555-8555-555555555555',
          '11111111-1111-4111-8111-111111111111',
          '33333333-3333-4333-8333-333333333333', %s,
          '{}'::jsonb, decode('7b7d','hex'), true, false, false, false,
          '2026-09-01T00:01:00Z', jsonb_build_array('evidence:test-2'),
          '22222222-2222-4222-8222-222222222222',
          'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
          'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
          '2026-09-01T00:01:00Z', 'renewed', %s)
    """
    with _connect_as("rights_producer_py") as producer:
        replaced = producer.execute(
            replace_sql, ("sha256:" + "c" * 64, record_hash, token2)
        ).fetchone()
        assert replaced == (UUID("55555555-5555-4555-8555-555555555555"), 2, token2)

    with _connect_as("rights_reader_py") as reader:
        old_current = reader.execute(
            "SELECT doharights_v1.verify_rights_token(%s,%s,%s,%s,%s)",
            (
                "33333333-3333-4333-8333-333333333333",
                "44444444-4444-4444-8444-444444444444",
                record_hash,
                1,
                token1,
            ),
        ).fetchone()
        new_current = reader.execute(
            "SELECT doharights_v1.verify_rights_token(%s,%s,%s,%s,%s)",
            (
                "33333333-3333-4333-8333-333333333333",
                "55555555-5555-4555-8555-555555555555",
                record_hash,
                2,
                token2,
            ),
        ).fetchone()
        assert old_current == (False,)
        assert new_current == (True,)

    with _connect_as("rights_producer_py") as producer:
        revoked = producer.execute(
            "SELECT * FROM doharights_v1.revoke_rights(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                "ffffffff-ffff-4fff-8fff-ffffffffffff",
                "sha256:" + "f" * 64,
                "33333333-3333-4333-8333-333333333333",
                "55555555-5555-4555-8555-555555555555",
                "12121212-1212-4212-8212-121212121212",
                "22222222-2222-4222-8222-222222222222",
                "2026-09-01T00:02:00Z",
                "withdrawn",
                psycopg.types.json.Jsonb(["case:test"]),
            ),
        ).fetchone()
        assert revoked == (UUID("55555555-5555-4555-8555-555555555555"), 3)

    with psycopg.connect(DSN, autocommit=True) as admin:
        counts = admin.execute(
            "SELECT (SELECT count(*) FROM doharights_v1.rights_record),"
            "(SELECT count(*) FROM doharights_v1.rights_lifecycle_event),"
            "(SELECT count(*) FROM doharights_v1.rights_current),"
            "(SELECT count(*) FROM doharights_v1.rights_record_current_use)"
        ).fetchone()
        assert counts == (4, 7, 1, 2)
