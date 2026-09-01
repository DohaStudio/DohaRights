CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'doharights_producer') THEN
        CREATE ROLE doharights_producer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'doharights_reader') THEN
        CREATE ROLE doharights_reader NOLOGIN;
    END IF;
END $$;

CREATE SCHEMA doharights_v1;
REVOKE ALL ON SCHEMA doharights_v1 FROM PUBLIC;

CREATE TABLE doharights_v1.source_authority (
    source_authority_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'rights-authority-v1'),
    origin_domain text NOT NULL CHECK (origin_domain = 'DohaRights'),
    registered_at timestamptz NOT NULL,
    producer_authority_id uuid NOT NULL
);

CREATE TABLE doharights_v1.rights_subject (
    rights_subject_id uuid PRIMARY KEY,
    dataset_source_identity text NOT NULL CHECK (
        dataset_source_identity <> ''
        AND dataset_source_identity = btrim(dataset_source_identity)
        AND dataset_source_identity !~ '[\\/]'
    ),
    subject_kind text NOT NULL CHECK (
        subject_kind IN ('source_dataset', 'dataset_version', 'derived_artifact')
    ),
    bound_identity text NOT NULL CHECK (bound_identity <> '' AND bound_identity = btrim(bound_identity)),
    projection_revision bigint NOT NULL DEFAULT 0 CHECK (projection_revision >= 0),
    UNIQUE (dataset_source_identity, subject_kind, bound_identity)
);

CREATE TABLE doharights_v1.rights_record (
    record_id uuid PRIMARY KEY,
    source_authority_id uuid NOT NULL REFERENCES doharights_v1.source_authority,
    rights_subject_id uuid NOT NULL REFERENCES doharights_v1.rights_subject,
    schema_version text NOT NULL CHECK (schema_version = 'rights-authority-v1'),
    record_fingerprint char(71) NOT NULL CHECK (record_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    canonical_payload jsonb NOT NULL,
    internal_training boolean NOT NULL,
    commercial_use boolean NOT NULL,
    redistribution boolean NOT NULL,
    external_model_publication boolean NOT NULL,
    effective_at timestamptz NOT NULL,
    provenance_references jsonb NOT NULL CHECK (
        jsonb_typeof(provenance_references) = 'array' AND jsonb_array_length(provenance_references) > 0
    ),
    producer_authority_id uuid NOT NULL,
    previous_record_id uuid NULL REFERENCES doharights_v1.rights_record,
    created_at timestamptz NOT NULL
);

CREATE TABLE doharights_v1.rights_lifecycle_event (
    event_id uuid PRIMARY KEY,
    event_type text NOT NULL CHECK (event_type IN ('issued', 'superseded', 'revoked')),
    rights_subject_id uuid NOT NULL REFERENCES doharights_v1.rights_subject,
    record_id uuid NOT NULL REFERENCES doharights_v1.rights_record,
    previous_record_id uuid NULL REFERENCES doharights_v1.rights_record,
    actor_authority_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    reason text NOT NULL CHECK (reason <> '' AND reason = btrim(reason)),
    provenance_references jsonb NOT NULL
);

CREATE TABLE doharights_v1.rights_current (
    rights_subject_id uuid PRIMARY KEY REFERENCES doharights_v1.rights_subject,
    record_id uuid NOT NULL UNIQUE REFERENCES doharights_v1.rights_record,
    projection_revision bigint NOT NULL CHECK (projection_revision >= 1),
    source_token_fingerprint char(71) NOT NULL CHECK (
        source_token_fingerprint ~ '^sha256:[0-9a-f]{64}$'
    )
);

CREATE TABLE doharights_v1.rights_request_replay (
    request_id uuid PRIMARY KEY,
    operation text NOT NULL CHECK (operation IN ('issue', 'replace', 'revoke')),
    request_fingerprint char(71) NOT NULL CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    rights_subject_id uuid NOT NULL REFERENCES doharights_v1.rights_subject,
    result_record_id uuid NOT NULL REFERENCES doharights_v1.rights_record,
    result_projection_revision bigint NOT NULL,
    result_source_token_fingerprint char(71) NULL CHECK (
        result_source_token_fingerprint IS NULL
        OR result_source_token_fingerprint ~ '^sha256:[0-9a-f]{64}$'
    ),
    created_at timestamptz NOT NULL
);

CREATE FUNCTION doharights_v1.reject_immutable_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'append-only Rights history required';
END $$;

CREATE TRIGGER source_authority_immutable BEFORE UPDATE OR DELETE ON doharights_v1.source_authority
FOR EACH ROW EXECUTE FUNCTION doharights_v1.reject_immutable_mutation();
CREATE TRIGGER rights_record_immutable BEFORE UPDATE OR DELETE ON doharights_v1.rights_record
FOR EACH ROW EXECUTE FUNCTION doharights_v1.reject_immutable_mutation();
CREATE TRIGGER rights_event_immutable BEFORE UPDATE OR DELETE ON doharights_v1.rights_lifecycle_event
FOR EACH ROW EXECUTE FUNCTION doharights_v1.reject_immutable_mutation();
CREATE TRIGGER rights_replay_immutable BEFORE UPDATE OR DELETE ON doharights_v1.rights_request_replay
FOR EACH ROW EXECUTE FUNCTION doharights_v1.reject_immutable_mutation();

CREATE FUNCTION doharights_v1.assert_producer()
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT pg_has_role(session_user, 'doharights_producer', 'MEMBER') THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'DohaRights producer authentication required';
    END IF;
END $$;

CREATE FUNCTION doharights_v1.issue_rights(
    requested_request_id uuid, requested_request_fingerprint char(71), requested_record_id uuid,
    requested_source_authority_id uuid, requested_subject_id uuid,
    requested_dataset_source_identity text, requested_subject_kind text, requested_bound_identity text,
    requested_record_fingerprint char(71), requested_payload jsonb, requested_payload_bytes bytea,
    requested_internal_training boolean, requested_commercial_use boolean,
    requested_redistribution boolean, requested_external_model_publication boolean,
    requested_effective_at timestamptz, requested_provenance jsonb,
    requested_producer_id uuid, requested_event_id uuid, requested_occurred_at timestamptz,
    requested_reason text, requested_token_fingerprint char(71)
)
RETURNS TABLE (record_id uuid, projection_revision bigint, source_token_fingerprint char(71))
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE replay_row doharights_v1.rights_request_replay%ROWTYPE; next_revision bigint;
BEGIN
    PERFORM doharights_v1.assert_producer();
    IF requested_record_fingerprint <> 'sha256:' || encode(public.digest(requested_payload_bytes, 'sha256'), 'hex') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Rights record fingerprint mismatch';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('rights' || chr(31) || requested_subject_id::text, 0));
    SELECT * INTO replay_row FROM doharights_v1.rights_request_replay WHERE request_id = requested_request_id;
    IF FOUND THEN
        IF replay_row.operation <> 'issue' OR replay_row.request_fingerprint <> requested_request_fingerprint THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Rights request conflict';
        END IF;
        RETURN QUERY SELECT replay_row.result_record_id, replay_row.result_projection_revision,
            replay_row.result_source_token_fingerprint;
        RETURN;
    END IF;
    INSERT INTO doharights_v1.source_authority VALUES (
        requested_source_authority_id, 'rights-authority-v1', 'DohaRights',
        requested_occurred_at, requested_producer_id
    ) ON CONFLICT (source_authority_id) DO NOTHING;
    IF NOT EXISTS (
        SELECT 1 FROM doharights_v1.source_authority
        WHERE source_authority_id = requested_source_authority_id
          AND producer_authority_id = requested_producer_id
    ) THEN RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Rights source authority mismatch'; END IF;
    INSERT INTO doharights_v1.rights_subject(
        rights_subject_id, dataset_source_identity, subject_kind, bound_identity
    ) VALUES (
        requested_subject_id, requested_dataset_source_identity, requested_subject_kind, requested_bound_identity
    ) ON CONFLICT (rights_subject_id) DO NOTHING;
    IF EXISTS (SELECT 1 FROM doharights_v1.rights_current WHERE rights_subject_id = requested_subject_id) THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'current Rights record already exists';
    END IF;
    UPDATE doharights_v1.rights_subject AS subject
    SET projection_revision = subject.projection_revision + 1
    WHERE subject.rights_subject_id = requested_subject_id
    RETURNING subject.projection_revision INTO next_revision;
    INSERT INTO doharights_v1.rights_record VALUES (
        requested_record_id, requested_source_authority_id, requested_subject_id, 'rights-authority-v1',
        requested_record_fingerprint, requested_payload, requested_internal_training,
        requested_commercial_use, requested_redistribution, requested_external_model_publication,
        requested_effective_at, requested_provenance, requested_producer_id, NULL, requested_occurred_at
    );
    INSERT INTO doharights_v1.rights_lifecycle_event VALUES (
        requested_event_id, 'issued', requested_subject_id, requested_record_id, NULL,
        requested_producer_id, requested_occurred_at, requested_reason, requested_provenance
    );
    INSERT INTO doharights_v1.rights_current VALUES (
        requested_subject_id, requested_record_id, next_revision, requested_token_fingerprint
    );
    INSERT INTO doharights_v1.rights_request_replay VALUES (
        requested_request_id, 'issue', requested_request_fingerprint, requested_subject_id,
        requested_record_id, next_revision, requested_token_fingerprint, requested_occurred_at
    );
    RETURN QUERY SELECT requested_record_id, next_revision, requested_token_fingerprint;
END $$;

CREATE FUNCTION doharights_v1.replace_rights(
    requested_request_id uuid, requested_request_fingerprint char(71),
    requested_expected_record_id uuid, requested_replacement_record_id uuid,
    requested_source_authority_id uuid, requested_subject_id uuid,
    requested_record_fingerprint char(71), requested_payload jsonb, requested_payload_bytes bytea,
    requested_internal_training boolean, requested_commercial_use boolean,
    requested_redistribution boolean, requested_external_model_publication boolean,
    requested_effective_at timestamptz, requested_provenance jsonb,
    requested_producer_id uuid, requested_supersede_event_id uuid, requested_issue_event_id uuid,
    requested_occurred_at timestamptz, requested_reason text, requested_token_fingerprint char(71)
)
RETURNS TABLE (record_id uuid, projection_revision bigint, source_token_fingerprint char(71))
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE replay_row doharights_v1.rights_request_replay%ROWTYPE; current_row doharights_v1.rights_current%ROWTYPE;
    next_revision bigint;
BEGIN
    PERFORM doharights_v1.assert_producer();
    IF requested_record_fingerprint <> 'sha256:' || encode(public.digest(requested_payload_bytes, 'sha256'), 'hex') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Rights record fingerprint mismatch';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('rights' || chr(31) || requested_subject_id::text, 0));
    SELECT * INTO replay_row FROM doharights_v1.rights_request_replay WHERE request_id = requested_request_id;
    IF FOUND THEN
        IF replay_row.operation <> 'replace' OR replay_row.request_fingerprint <> requested_request_fingerprint THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Rights request conflict';
        END IF;
        RETURN QUERY SELECT replay_row.result_record_id, replay_row.result_projection_revision,
            replay_row.result_source_token_fingerprint;
        RETURN;
    END IF;
    SELECT * INTO current_row FROM doharights_v1.rights_current
    WHERE rights_subject_id = requested_subject_id FOR UPDATE;
    IF NOT FOUND OR current_row.record_id <> requested_expected_record_id THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'expected current Rights record mismatch';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM doharights_v1.source_authority
        WHERE source_authority_id = requested_source_authority_id
          AND producer_authority_id = requested_producer_id
    ) THEN RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Rights source authority mismatch'; END IF;
    UPDATE doharights_v1.rights_subject AS subject
    SET projection_revision = subject.projection_revision + 1
    WHERE subject.rights_subject_id = requested_subject_id
    RETURNING subject.projection_revision INTO next_revision;
    INSERT INTO doharights_v1.rights_record VALUES (
        requested_replacement_record_id, requested_source_authority_id, requested_subject_id,
        'rights-authority-v1', requested_record_fingerprint, requested_payload,
        requested_internal_training, requested_commercial_use, requested_redistribution,
        requested_external_model_publication, requested_effective_at, requested_provenance,
        requested_producer_id, requested_expected_record_id, requested_occurred_at
    );
    INSERT INTO doharights_v1.rights_lifecycle_event VALUES
        (requested_supersede_event_id, 'superseded', requested_subject_id,
         requested_expected_record_id, requested_expected_record_id, requested_producer_id,
         requested_occurred_at, requested_reason, requested_provenance),
        (requested_issue_event_id, 'issued', requested_subject_id,
         requested_replacement_record_id, requested_expected_record_id, requested_producer_id,
         requested_occurred_at, requested_reason, requested_provenance);
    UPDATE doharights_v1.rights_current SET
        record_id = requested_replacement_record_id,
        projection_revision = next_revision,
        source_token_fingerprint = requested_token_fingerprint
    WHERE rights_subject_id = requested_subject_id;
    INSERT INTO doharights_v1.rights_request_replay VALUES (
        requested_request_id, 'replace', requested_request_fingerprint, requested_subject_id,
        requested_replacement_record_id, next_revision, requested_token_fingerprint,
        requested_occurred_at
    );
    RETURN QUERY SELECT requested_replacement_record_id, next_revision, requested_token_fingerprint;
END $$;

CREATE FUNCTION doharights_v1.revoke_rights(
    requested_request_id uuid, requested_request_fingerprint char(71), requested_subject_id uuid,
    requested_expected_record_id uuid, requested_event_id uuid, requested_producer_id uuid,
    requested_occurred_at timestamptz, requested_reason text, requested_provenance jsonb
)
RETURNS TABLE (record_id uuid, projection_revision bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE replay_row doharights_v1.rights_request_replay%ROWTYPE; current_row doharights_v1.rights_current%ROWTYPE;
    next_revision bigint;
BEGIN
    PERFORM doharights_v1.assert_producer();
    PERFORM pg_advisory_xact_lock(hashtextextended('rights' || chr(31) || requested_subject_id::text, 0));
    SELECT * INTO replay_row FROM doharights_v1.rights_request_replay WHERE request_id = requested_request_id;
    IF FOUND THEN
        IF replay_row.operation <> 'revoke' OR replay_row.request_fingerprint <> requested_request_fingerprint THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Rights request conflict';
        END IF;
        RETURN QUERY SELECT replay_row.result_record_id, replay_row.result_projection_revision;
        RETURN;
    END IF;
    SELECT * INTO current_row FROM doharights_v1.rights_current
    WHERE rights_subject_id = requested_subject_id FOR UPDATE;
    IF NOT FOUND OR current_row.record_id <> requested_expected_record_id THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'expected current Rights record mismatch';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM doharights_v1.rights_record AS record
        WHERE record.record_id = requested_expected_record_id
          AND record.producer_authority_id = requested_producer_id
    ) THEN RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Rights producer mismatch'; END IF;
    UPDATE doharights_v1.rights_subject AS subject
    SET projection_revision = subject.projection_revision + 1
    WHERE subject.rights_subject_id = requested_subject_id
    RETURNING subject.projection_revision INTO next_revision;
    INSERT INTO doharights_v1.rights_lifecycle_event VALUES (
        requested_event_id, 'revoked', requested_subject_id, requested_expected_record_id,
        requested_expected_record_id, requested_producer_id, requested_occurred_at,
        requested_reason, requested_provenance
    );
    DELETE FROM doharights_v1.rights_current WHERE rights_subject_id = requested_subject_id;
    INSERT INTO doharights_v1.rights_request_replay VALUES (
        requested_request_id, 'revoke', requested_request_fingerprint, requested_subject_id,
        requested_expected_record_id, next_revision, NULL, requested_occurred_at
    );
    RETURN QUERY SELECT requested_expected_record_id, next_revision;
END $$;

CREATE FUNCTION doharights_v1.get_current_rights(requested_subject_id uuid)
RETURNS TABLE (
    canonical_payload jsonb, record_id uuid, record_fingerprint char(71),
    projection_revision bigint, source_token_fingerprint char(71)
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT pg_has_role(session_user, 'doharights_reader', 'MEMBER')
       AND NOT pg_has_role(session_user, 'doharights_producer', 'MEMBER') THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'DohaRights authenticated reader required';
    END IF;
    RETURN QUERY SELECT r.canonical_payload, r.record_id, r.record_fingerprint,
        c.projection_revision, c.source_token_fingerprint
    FROM doharights_v1.rights_current c
    JOIN doharights_v1.rights_record r ON r.record_id = c.record_id
    WHERE c.rights_subject_id = requested_subject_id;
END $$;

CREATE FUNCTION doharights_v1.verify_rights_token(
    requested_subject_id uuid, requested_record_id uuid, requested_record_fingerprint char(71),
    requested_projection_revision bigint, requested_token_fingerprint char(71)
)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM doharights_v1.get_current_rights(requested_subject_id) current_row
        WHERE current_row.record_id = requested_record_id
          AND current_row.record_fingerprint = requested_record_fingerprint
          AND current_row.projection_revision = requested_projection_revision
          AND current_row.source_token_fingerprint = requested_token_fingerprint
    )
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA doharights_v1 FROM PUBLIC, doharights_producer, doharights_reader;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA doharights_v1 FROM PUBLIC;
GRANT USAGE ON SCHEMA doharights_v1 TO doharights_producer, doharights_reader;
GRANT EXECUTE ON FUNCTION doharights_v1.issue_rights(
    uuid, char, uuid, uuid, uuid, text, text, text, char, jsonb, bytea, boolean, boolean, boolean,
    boolean, timestamptz, jsonb, uuid, uuid, timestamptz, text, char
) TO doharights_producer;
GRANT EXECUTE ON FUNCTION doharights_v1.replace_rights(
    uuid, char, uuid, uuid, uuid, uuid, char, jsonb, bytea, boolean, boolean, boolean,
    boolean, timestamptz, jsonb, uuid, uuid, uuid, timestamptz, text, char
) TO doharights_producer;
GRANT EXECUTE ON FUNCTION doharights_v1.revoke_rights(
    uuid, char, uuid, uuid, uuid, uuid, timestamptz, text, jsonb
) TO doharights_producer;
GRANT EXECUTE ON FUNCTION doharights_v1.get_current_rights(uuid) TO doharights_reader, doharights_producer;
GRANT EXECUTE ON FUNCTION doharights_v1.verify_rights_token(uuid, uuid, char, bigint, char)
TO doharights_reader, doharights_producer;
