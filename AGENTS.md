# DohaRights repository rules

- Preserve ADR-034 ownership: this repository owns canonical Dataset Training Rights records and lifecycle.
- Rights history is append-only. Never overwrite or delete issued records or lifecycle events.
- A logical Rights Subject has zero or one current record; ambiguity must fail closed.
- Producer and reader credentials remain separate. Readers cannot issue, replace, or revoke.
- Source tokens and composite evidence are identities, never authorization capabilities.
- Do not commit credentials, production Rights records, private legal text, or Dataset artifacts.
- Production mutations require a separate explicit provisioning/issuance approval.
