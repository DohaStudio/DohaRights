CREATE TABLE doharights_v1.rights_record_current_use (
    record_id uuid PRIMARY KEY REFERENCES doharights_v1.rights_record,
    rights_status text NOT NULL CHECK (
        rights_status IN ('approved', 'approved_limited', 'rejected')
    ),
    source_classification jsonb NOT NULL CHECK (
        jsonb_typeof(source_classification) = 'object'
    ),
    analysis_allowed boolean NOT NULL,
    derivative_generation_allowed boolean NOT NULL,
    retention jsonb NOT NULL CHECK (jsonb_typeof(retention) = 'object'),
    consent_evidence_references jsonb NOT NULL CHECK (
        jsonb_typeof(consent_evidence_references) = 'array'
    ),
    jurisdiction text NOT NULL CHECK (jurisdiction <> '' AND jurisdiction = btrim(jurisdiction)),
    reviewer_authority_id uuid NOT NULL,
    reviewed_at timestamptz NOT NULL,
    current_use_authorization jsonb NOT NULL CHECK (
        jsonb_typeof(current_use_authorization) = 'object'
    ),
    typed_evidence_references jsonb NOT NULL CHECK (
        jsonb_typeof(typed_evidence_references) = 'array'
        AND jsonb_array_length(typed_evidence_references) > 0
    )
);

CREATE TRIGGER rights_current_use_immutable
BEFORE UPDATE OR DELETE ON doharights_v1.rights_record_current_use
FOR EACH ROW EXECUTE FUNCTION doharights_v1.reject_immutable_mutation();

CREATE FUNCTION doharights_v1.assert_current_use_payload(
    requested_payload jsonb,
    requested_payload_bytes bytea,
    requested_producer_id uuid,
    requested_reviewer_id uuid,
    requested_rights_status text,
    requested_current_use_authorization jsonb,
    requested_evidence_references jsonb
)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF convert_from(requested_payload_bytes, 'UTF8')::jsonb <> requested_payload THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Rights canonical payload mismatch';
    END IF;
    IF requested_producer_id = requested_reviewer_id THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Rights reviewer and producer must differ';
    END IF;
    IF requested_rights_status NOT IN ('approved', 'approved_limited', 'rejected') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Rights status invalid';
    END IF;
    IF jsonb_typeof(requested_current_use_authorization) <> 'object'
       OR jsonb_typeof(requested_evidence_references) <> 'array'
       OR jsonb_array_length(requested_evidence_references) = 0 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Current-use Rights facts invalid';
    END IF;
END $$;

CREATE FUNCTION doharights_v1.issue_current_use_rights(
    requested_request_id uuid, requested_request_fingerprint char(71), requested_record_id uuid,
    requested_source_authority_id uuid, requested_subject_id uuid,
    requested_dataset_source_identity text, requested_subject_kind text, requested_bound_identity text,
    requested_record_fingerprint char(71), requested_payload jsonb, requested_payload_bytes bytea,
    requested_internal_training boolean, requested_commercial_use boolean,
    requested_redistribution boolean, requested_external_model_publication boolean,
    requested_effective_at timestamptz, requested_provenance jsonb,
    requested_producer_id uuid, requested_event_id uuid, requested_occurred_at timestamptz,
    requested_reason text, requested_token_fingerprint char(71),
    requested_rights_status text, requested_source_classification jsonb,
    requested_analysis_allowed boolean, requested_derivative_generation_allowed boolean,
    requested_retention jsonb, requested_consent_evidence_references jsonb,
    requested_jurisdiction text, requested_reviewer_id uuid, requested_reviewed_at timestamptz,
    requested_current_use_authorization jsonb, requested_typed_evidence_references jsonb
)
RETURNS TABLE (record_id uuid, projection_revision bigint, source_token_fingerprint char(71))
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE issued record;
BEGIN
    PERFORM doharights_v1.assert_current_use_payload(
        requested_payload, requested_payload_bytes, requested_producer_id,
        requested_reviewer_id, requested_rights_status,
        requested_current_use_authorization, requested_typed_evidence_references
    );
    IF requested_payload ->> 'status' <> requested_rights_status
       OR requested_payload -> 'source_classification' <> requested_source_classification
       OR (requested_payload #>> '{permissions,internal_training}')::boolean
            <> requested_internal_training
       OR (requested_payload #>> '{permissions,commercial_use}')::boolean
            <> requested_commercial_use
       OR (requested_payload #>> '{permissions,redistribution}')::boolean
            <> requested_redistribution
       OR (requested_payload #>> '{permissions,external_model_publication}')::boolean
            <> requested_external_model_publication
       OR (requested_payload #>> '{permissions,analysis}')::boolean
            <> requested_analysis_allowed
       OR (requested_payload #>> '{permissions,derivative_generation}')::boolean
            <> requested_derivative_generation_allowed
       OR requested_payload -> 'retention' <> requested_retention
       OR requested_payload -> 'consent_evidence_references'
            <> requested_consent_evidence_references
       OR requested_payload ->> 'jurisdiction' <> requested_jurisdiction
       OR (requested_payload #>> '{review,reviewer_authority_id}')::uuid
            <> requested_reviewer_id
       OR (requested_payload #>> '{review,reviewed_at}')::timestamptz
            <> requested_reviewed_at
       OR requested_payload -> 'current_use_authorization'
            <> requested_current_use_authorization
       OR requested_payload -> 'evidence_references' <> requested_typed_evidence_references
       OR (requested_payload ->> 'producer_authority_id')::uuid <> requested_producer_id THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Current-use Rights projection mismatch';
    END IF;
    SELECT * INTO issued FROM doharights_v1.issue_rights(
        requested_request_id, requested_request_fingerprint, requested_record_id,
        requested_source_authority_id, requested_subject_id,
        requested_dataset_source_identity, requested_subject_kind, requested_bound_identity,
        requested_record_fingerprint, requested_payload, requested_payload_bytes,
        requested_internal_training, requested_commercial_use, requested_redistribution,
        requested_external_model_publication, requested_effective_at, requested_provenance,
        requested_producer_id, requested_event_id, requested_occurred_at, requested_reason,
        requested_token_fingerprint
    );
    INSERT INTO doharights_v1.rights_record_current_use VALUES (
        requested_record_id, requested_rights_status, requested_source_classification,
        requested_analysis_allowed, requested_derivative_generation_allowed,
        requested_retention, requested_consent_evidence_references, requested_jurisdiction,
        requested_reviewer_id, requested_reviewed_at, requested_current_use_authorization,
        requested_typed_evidence_references
    ) ON CONFLICT ON CONSTRAINT rights_record_current_use_pkey DO NOTHING;
    RETURN QUERY SELECT issued.record_id, issued.projection_revision,
        issued.source_token_fingerprint;
END $$;

CREATE FUNCTION doharights_v1.get_current_use_rights(requested_subject_id uuid)
RETURNS TABLE (
    canonical_payload jsonb, record_id uuid, record_fingerprint char(71),
    projection_revision bigint, source_token_fingerprint char(71), rights_status text,
    source_classification jsonb, analysis_allowed boolean,
    derivative_generation_allowed boolean, retention jsonb,
    consent_evidence_references jsonb, jurisdiction text, reviewer_authority_id uuid,
    reviewed_at timestamptz, current_use_authorization jsonb, typed_evidence_references jsonb
)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_row.canonical_payload, current_row.record_id,
        current_row.record_fingerprint, current_row.projection_revision,
        current_row.source_token_fingerprint, facts.rights_status,
        facts.source_classification, facts.analysis_allowed,
        facts.derivative_generation_allowed, facts.retention,
        facts.consent_evidence_references, facts.jurisdiction,
        facts.reviewer_authority_id, facts.reviewed_at,
        facts.current_use_authorization, facts.typed_evidence_references
    FROM doharights_v1.get_current_rights(requested_subject_id) current_row
    JOIN doharights_v1.rights_record_current_use facts
      ON facts.record_id = current_row.record_id
$$;

CREATE FUNCTION doharights_v1.replace_current_use_rights(
    requested_request_id uuid, requested_request_fingerprint char(71),
    requested_expected_record_id uuid, requested_replacement_record_id uuid,
    requested_source_authority_id uuid, requested_subject_id uuid,
    requested_record_fingerprint char(71), requested_payload jsonb, requested_payload_bytes bytea,
    requested_internal_training boolean, requested_commercial_use boolean,
    requested_redistribution boolean, requested_external_model_publication boolean,
    requested_effective_at timestamptz, requested_provenance jsonb,
    requested_producer_id uuid, requested_supersede_event_id uuid, requested_issue_event_id uuid,
    requested_occurred_at timestamptz, requested_reason text, requested_token_fingerprint char(71),
    requested_rights_status text, requested_source_classification jsonb,
    requested_analysis_allowed boolean, requested_derivative_generation_allowed boolean,
    requested_retention jsonb, requested_consent_evidence_references jsonb,
    requested_jurisdiction text, requested_reviewer_id uuid, requested_reviewed_at timestamptz,
    requested_current_use_authorization jsonb, requested_typed_evidence_references jsonb
)
RETURNS TABLE (record_id uuid, projection_revision bigint, source_token_fingerprint char(71))
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE replaced record;
BEGIN
    PERFORM doharights_v1.assert_current_use_payload(
        requested_payload, requested_payload_bytes, requested_producer_id,
        requested_reviewer_id, requested_rights_status,
        requested_current_use_authorization, requested_typed_evidence_references
    );
    IF requested_payload ->> 'status' <> requested_rights_status
       OR requested_payload -> 'source_classification' <> requested_source_classification
       OR (requested_payload #>> '{permissions,internal_training}')::boolean
            <> requested_internal_training
       OR (requested_payload #>> '{permissions,commercial_use}')::boolean
            <> requested_commercial_use
       OR (requested_payload #>> '{permissions,redistribution}')::boolean
            <> requested_redistribution
       OR (requested_payload #>> '{permissions,external_model_publication}')::boolean
            <> requested_external_model_publication
       OR (requested_payload #>> '{permissions,analysis}')::boolean
            <> requested_analysis_allowed
       OR (requested_payload #>> '{permissions,derivative_generation}')::boolean
            <> requested_derivative_generation_allowed
       OR requested_payload -> 'retention' <> requested_retention
       OR requested_payload -> 'consent_evidence_references'
            <> requested_consent_evidence_references
       OR requested_payload ->> 'jurisdiction' <> requested_jurisdiction
       OR (requested_payload #>> '{review,reviewer_authority_id}')::uuid
            <> requested_reviewer_id
       OR (requested_payload #>> '{review,reviewed_at}')::timestamptz
            <> requested_reviewed_at
       OR requested_payload -> 'current_use_authorization'
            <> requested_current_use_authorization
       OR requested_payload -> 'evidence_references' <> requested_typed_evidence_references
       OR (requested_payload ->> 'producer_authority_id')::uuid <> requested_producer_id
       OR (requested_payload ->> 'previous_record_id')::uuid <> requested_expected_record_id THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Current-use Rights projection mismatch';
    END IF;
    SELECT * INTO replaced FROM doharights_v1.replace_rights(
        requested_request_id, requested_request_fingerprint, requested_expected_record_id,
        requested_replacement_record_id, requested_source_authority_id, requested_subject_id,
        requested_record_fingerprint, requested_payload, requested_payload_bytes,
        requested_internal_training, requested_commercial_use, requested_redistribution,
        requested_external_model_publication, requested_effective_at, requested_provenance,
        requested_producer_id, requested_supersede_event_id, requested_issue_event_id,
        requested_occurred_at, requested_reason, requested_token_fingerprint
    );
    INSERT INTO doharights_v1.rights_record_current_use VALUES (
        requested_replacement_record_id, requested_rights_status,
        requested_source_classification, requested_analysis_allowed,
        requested_derivative_generation_allowed, requested_retention,
        requested_consent_evidence_references, requested_jurisdiction,
        requested_reviewer_id, requested_reviewed_at, requested_current_use_authorization,
        requested_typed_evidence_references
    ) ON CONFLICT ON CONSTRAINT rights_record_current_use_pkey DO NOTHING;
    RETURN QUERY SELECT replaced.record_id, replaced.projection_revision,
        replaced.source_token_fingerprint;
END $$;

REVOKE ALL ON FUNCTION doharights_v1.assert_current_use_payload(
    jsonb, bytea, uuid, uuid, text, jsonb, jsonb
) FROM PUBLIC;
REVOKE ALL ON FUNCTION doharights_v1.issue_current_use_rights(
    uuid, char, uuid, uuid, uuid, text, text, text, char, jsonb, bytea, boolean,
    boolean, boolean, boolean, timestamptz, jsonb, uuid, uuid, timestamptz, text,
    char, text, jsonb, boolean, boolean, jsonb, jsonb, text, uuid, timestamptz,
    jsonb, jsonb
) FROM PUBLIC;
REVOKE ALL ON FUNCTION doharights_v1.get_current_use_rights(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION doharights_v1.replace_current_use_rights(
    uuid, char, uuid, uuid, uuid, uuid, char, jsonb, bytea, boolean, boolean,
    boolean, boolean, timestamptz, jsonb, uuid, uuid, uuid, timestamptz, text,
    char, text, jsonb, boolean, boolean, jsonb, jsonb, text, uuid, timestamptz,
    jsonb, jsonb
) FROM PUBLIC;
REVOKE ALL ON TABLE doharights_v1.rights_record_current_use
FROM PUBLIC, doharights_producer, doharights_reader;
GRANT EXECUTE ON FUNCTION doharights_v1.issue_current_use_rights(
    uuid, char, uuid, uuid, uuid, text, text, text, char, jsonb, bytea, boolean,
    boolean, boolean, boolean, timestamptz, jsonb, uuid, uuid, timestamptz, text,
    char, text, jsonb, boolean, boolean, jsonb, jsonb, text, uuid, timestamptz,
    jsonb, jsonb
) TO doharights_producer;
GRANT EXECUTE ON FUNCTION doharights_v1.get_current_use_rights(uuid)
TO doharights_reader, doharights_producer;
GRANT EXECUTE ON FUNCTION doharights_v1.replace_current_use_rights(
    uuid, char, uuid, uuid, uuid, uuid, char, jsonb, bytea, boolean, boolean,
    boolean, boolean, timestamptz, jsonb, uuid, uuid, uuid, timestamptz, text,
    char, text, jsonb, boolean, boolean, jsonb, jsonb, text, uuid, timestamptz,
    jsonb, jsonb
) TO doharights_producer;
