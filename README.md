# DohaRights

DohaRights is the shared DohaStudio Rights/Licensing canonical authority. It owns append-only Dataset Training Rights
records, their unique-current projection, authenticated scoped reads, and source-issued currentness tokens.

The approved consumer boundary is intentionally narrow:

- a dedicated producer may issue, supersede, and revoke immutable records;
- a scoped reader may get the current record and verify an exact source token;
- public access and consumer DML are denied;
- files, manifests, fingerprints, and eligibility material are evidence inputs, not authority;
- a source token is immutable evidence identity, not an authorization capability.

Current-use records also bind source classification, separate analysis/training/derivative permissions, retention
semantics, jurisdiction, a distinct reviewer authority, typed provider/source evidence, and acquisition-continuity
facts. An absent historical acquisition receipt is recorded as an audit fact; it is never synthesized. Indefinite
retention means `indefinite_while_current`, so supersession or revocation invalidates the owner-issued source token.
Consent references are a separate typed field and may be empty when consent is not the legal basis.

Migration `0002_current_use_rights.sql` adds this projection without rewriting v1 history. New current-use issuance uses
the producer-only `issue_current_use_rights` function, while authenticated readers use `get_current_use_rights`. The
Python `PostgresCurrentRightsAuthority` adapter calls only these protected functions and never grants table DML.

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

The source contract and persistence implementation are repository code. Production database provisioning and actual
Rights issuance require their own explicit operation approval; Dataset publication and Training remain separate.

Shared DohaStudio Rights and Licensing canonical authority
