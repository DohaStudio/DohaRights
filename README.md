# DohaRights

DohaRights is the shared DohaStudio Rights/Licensing canonical authority. It owns append-only Dataset Training Rights
records, their unique-current projection, authenticated scoped reads, and source-issued currentness tokens.

The approved consumer boundary is intentionally narrow:

- a dedicated producer may issue, supersede, and revoke immutable records;
- a scoped reader may get the current record and verify an exact source token;
- public access and consumer DML are denied;
- files, manifests, fingerprints, and eligibility material are evidence inputs, not authority;
- a source token is immutable evidence identity, not an authorization capability.

This repository does not transfer ownership of DohaMusic or DohaVocal consent domains. Domain-specific evidence can be
linked as provenance without making those systems the canonical Dataset Training Rights owner.

## Development

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests
python -m ruff format --check src tests
```

PostgreSQL integration tests require an explicit test DSN in `DOHARIGHTS_TEST_POSTGRES_DSN`. Production credentials and
production Rights records are never created by the test suite.

## Status

The source contract and persistence implementation are repository code only. Production database provisioning, actual
Rights issuance, Dataset publication, and Training remain separate approved operations.

Shared DohaStudio Rights and Licensing canonical authority
