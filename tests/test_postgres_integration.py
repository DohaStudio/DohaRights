from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID

import pytest

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
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(migration)
        admin.execute("CREATE ROLE rights_producer_py LOGIN PASSWORD 'doharights-test-only'")
        admin.execute("GRANT doharights_producer TO rights_producer_py")
        admin.execute("CREATE ROLE rights_reader_py LOGIN PASSWORD 'doharights-test-only'")
        admin.execute("GRANT doharights_reader TO rights_reader_py")
        admin.execute("CREATE ROLE rights_outsider_py LOGIN PASSWORD 'doharights-test-only'")

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

    replace = """
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
        replaced = producer.execute(replace, ("sha256:" + "c" * 64, record_hash, token2)).fetchone()
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
            "(SELECT count(*) FROM doharights_v1.rights_current)"
        ).fetchone()
        assert counts == (2, 4, 0)
