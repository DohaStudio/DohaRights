from pathlib import Path

MIGRATION = Path("src/doharights/postgres_migrations/0001_rights_authority.sql")


def test_migration_has_append_only_unique_current_and_scoped_roles() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    required = (
        "CREATE ROLE doharights_producer NOLOGIN",
        "CREATE ROLE doharights_reader NOLOGIN",
        "CREATE TABLE doharights_v1.rights_record",
        "CREATE TABLE doharights_v1.rights_lifecycle_event",
        "CREATE TABLE doharights_v1.rights_current",
        "rights_subject_id uuid PRIMARY KEY",
        "reject_immutable_mutation",
        "CREATE FUNCTION doharights_v1.issue_rights",
        "CREATE FUNCTION doharights_v1.replace_rights",
        "CREATE FUNCTION doharights_v1.revoke_rights",
        "CREATE FUNCTION doharights_v1.get_current_rights",
        "CREATE FUNCTION doharights_v1.verify_rights_token",
        "REVOKE ALL ON ALL TABLES",
    )
    for fragment in required:
        assert fragment in sql


def test_reader_has_no_writer_function_or_table_dml_grant() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    issue_grant = sql[sql.index("GRANT EXECUTE ON FUNCTION doharights_v1.issue_rights") :]
    issue_grant = issue_grant[: issue_grant.index(";")]
    assert issue_grant.endswith("TO doharights_producer")
    assert "doharights_reader" not in issue_grant
    assert "TO doharights_reader, doharights_producer" in sql
    assert "GRANT INSERT" not in sql
    assert "GRANT UPDATE" not in sql
    assert "GRANT DELETE" not in sql


def test_public_access_is_revoked() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "REVOKE ALL ON SCHEMA doharights_v1 FROM PUBLIC" in sql
    assert "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA doharights_v1 FROM PUBLIC" in sql
