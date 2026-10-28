CREATE OR REPLACE PROCEDURE sp_register_evidence (
    p_actor_id IN NUMBER,
    p_incident_id IN NUMBER,
    p_evidence_type IN VARCHAR2,
    p_storage_key IN VARCHAR2,
    p_original_name IN VARCHAR2,
    p_collected_at IN TIMESTAMP WITH TIME ZONE,
    p_sha256 IN VARCHAR2,
    p_file_size IN NUMBER,
    p_sensitivity IN VARCHAR2,
    p_evidence_id OUT NUMBER
) AUTHID DEFINER
IS
    v_status incident.status%TYPE;
    v_collector NUMBER;
    v_now TIMESTAMP WITH TIME ZONE;
BEGIN
    SAVEPOINT cs_register_evidence_start;

    p_evidence_id := NULL;

    cs_security.require_operator(p_actor_id);

    IF TRIM(p_evidence_type) IS NULL
       OR LENGTH(p_evidence_type) > 40
       OR TRIM(p_storage_key) IS NULL
       OR LENGTH(p_storage_key) > 255
       OR TRIM(p_original_name) IS NULL
       OR LENGTH(p_original_name) > 255
       OR p_collected_at IS NULL
       OR p_sha256 IS NULL
       OR p_file_size IS NULL
       OR p_sensitivity IS NULL
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Missing or invalid evidence fields'
        );
    END IF;

    IF NOT REGEXP_LIKE(
           p_storage_key, '^[A-Za-z0-9][A-Za-z0-9_.-]*$'
       )
       OR INSTR(p_storage_key, '..') > 0
       OR LENGTH(p_sha256) <> 64
       OR NOT REGEXP_LIKE(p_sha256, '^[0-9A-Fa-f]{64}$')
       OR p_file_size < 0
       OR p_file_size > 10485760
       OR p_file_size <> TRUNC(p_file_size)
       OR p_sensitivity NOT IN ('INTERNAL', 'RESTRICTED')
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Invalid storage key hash size or sensitivity'
        );
    END IF;

    BEGIN
        SELECT status
        INTO v_status
        FROM incident
        WHERE incident_id = p_incident_id
        FOR UPDATE WAIT 5;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20001, 'Incident not found'
            );
    END;

    cs_security.require_incident_access(
        p_actor_id, p_incident_id, 1
    );

    IF v_status IN ('RESOLVED', 'CLOSED') THEN
        RAISE_APPLICATION_ERROR(
            -20004, 'Reopen the incident before adding evidence'
        );
    END IF;

    BEGIN
        SELECT i.investigator_id
        INTO v_collector
        FROM investigator i
        WHERE i.user_id = p_actor_id
          AND i.availability <> 'INACTIVE';
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20002, 'Evidence collector needs an active investigator profile'
            );
    END;

    v_now := SYSTIMESTAMP;

    IF p_collected_at > v_now THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Evidence collection time cannot be in the future'
        );
    END IF;

    INSERT INTO evidence (
        incident_id,
        evidence_type,
        storage_key,
        original_name,
        collected_at,
        collected_by,
        sha256,
        file_size,
        sensitivity,
        current_custodian_id
    ) VALUES (
        p_incident_id,
        p_evidence_type,
        p_storage_key,
        p_original_name,
        p_collected_at,
        v_collector,
        LOWER(p_sha256),
        p_file_size,
        p_sensitivity,
        v_collector
    )
    RETURNING evidence_id INTO p_evidence_id;

    INSERT INTO chain_of_custody (
        evidence_id,
        from_investigator_id,
        to_investigator_id,
        transferred_at,
        method,
        purpose,
        receipt_condition,
        performed_by
    ) VALUES (
        p_evidence_id,
        NULL,
        v_collector,
        v_now,
        'INTAKE',
        'Initial evidence registration',
        'Registered with supplied SHA-256 and metadata',
        p_actor_id
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO cs_register_evidence_start;
        p_evidence_id := NULL;
        RAISE;
END sp_register_evidence;
/


CREATE OR REPLACE PROCEDURE sp_transfer_evidence (
    p_actor_id IN NUMBER,
    p_evidence_id IN NUMBER,
    p_expected_custodian_id IN NUMBER,
    p_to_investigator_id IN NUMBER,
    p_method IN VARCHAR2,
    p_purpose IN VARCHAR2,
    p_receipt_condition IN VARCHAR2
) AUTHID DEFINER
IS
    v_incident_id NUMBER;
    v_status incident.status%TYPE;
    v_custodian NUMBER;
    v_current_user NUMBER;
    v_count NUMBER;
    v_now TIMESTAMP WITH TIME ZONE;
BEGIN
    SAVEPOINT cs_transfer_evidence_start;

    cs_security.require_operator(p_actor_id);

    IF p_expected_custodian_id IS NULL
       OR p_to_investigator_id IS NULL
       OR TRIM(p_method) IS NULL
       OR LENGTH(p_method) > 80
       OR TRIM(p_purpose) IS NULL
       OR LENGTH(p_purpose) > 1000
       OR TRIM(p_receipt_condition) IS NULL
       OR LENGTH(p_receipt_condition) > 200
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Required custody transfer fields are invalid'
        );
    END IF;

    BEGIN
        SELECT incident_id
        INTO v_incident_id
        FROM evidence
        WHERE evidence_id = p_evidence_id;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20001, 'Evidence not found'
            );
    END;

    SELECT status
    INTO v_status
    FROM incident
    WHERE incident_id = v_incident_id
    FOR UPDATE WAIT 5;

    cs_security.require_incident_access(
        p_actor_id, v_incident_id, 1
    );

    IF v_status IN ('RESOLVED', 'CLOSED') THEN
        RAISE_APPLICATION_ERROR(
            -20004, 'Reopen the incident before transferring evidence'
        );
    END IF;

    SELECT current_custodian_id
    INTO v_custodian
    FROM evidence
    WHERE evidence_id = p_evidence_id
    FOR UPDATE WAIT 5;

    IF v_custodian <> p_expected_custodian_id THEN
        RAISE_APPLICATION_ERROR(
            -20003, 'Custody changed; refresh and retry'
        );
    END IF;

    SELECT user_id
    INTO v_current_user
    FROM investigator
    WHERE investigator_id = v_custodian
      AND availability <> 'INACTIVE';

    IF v_current_user <> p_actor_id THEN
        RAISE_APPLICATION_ERROR(
            -20007, 'Only the current custodian can transfer evidence'
        );
    END IF;

    IF p_to_investigator_id = v_custodian THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Select a different receiving investigator'
        );
    END IF;

    SELECT COUNT(*)
    INTO v_count
    FROM investigator i
    JOIN app_user u ON u.user_id = i.user_id
    JOIN incident_assignment a
      ON a.investigator_id = i.investigator_id
    JOIN investigation_cycle c ON c.cycle_id = a.cycle_id
    WHERE i.investigator_id = p_to_investigator_id
      AND i.availability <> 'INACTIVE'
      AND u.is_active = 1
      AND u.role_code IN ('ADMIN', 'ANALYST')
      AND c.incident_id = v_incident_id
      AND c.ended_at IS NULL
      AND a.ended_at IS NULL;

    IF v_count = 0 THEN
        RAISE_APPLICATION_ERROR(
            -20002, 'Receiver must be an active assigned investigator'
        );
    END IF;

    v_now := SYSTIMESTAMP;

    INSERT INTO chain_of_custody (
        evidence_id,
        from_investigator_id,
        to_investigator_id,
        transferred_at,
        method,
        purpose,
        receipt_condition,
        performed_by
    ) VALUES (
        p_evidence_id,
        v_custodian,
        p_to_investigator_id,
        v_now,
        p_method,
        p_purpose,
        p_receipt_condition,
        p_actor_id
    );

    UPDATE evidence
    SET current_custodian_id = p_to_investigator_id
    WHERE evidence_id = p_evidence_id;

EXCEPTION
    WHEN NO_DATA_FOUND THEN
        ROLLBACK TO cs_transfer_evidence_start;
        RAISE_APPLICATION_ERROR(
            -20002, 'Current custodian is missing or inactive'
        );

    WHEN OTHERS THEN
        ROLLBACK TO cs_transfer_evidence_start;
        RAISE;
END sp_transfer_evidence;
/
CREATE OR REPLACE PROCEDURE sp_add_analysis (
    p_actor_id IN NUMBER,
    p_evidence_id IN NUMBER,
    p_supersedes_analysis_id IN NUMBER,
    p_technique IN VARCHAR2,
    p_findings IN CLOB,
    p_indicators IN CLOB,
    p_confidence IN NUMBER,
    p_analysis_id OUT NUMBER
) AUTHID DEFINER
IS
    v_incident_id NUMBER;
    v_status incident.status%TYPE;
    v_investigator NUMBER;
    v_previous_evidence NUMBER;
    v_locked_evidence NUMBER;
    v_count NUMBER;
BEGIN
    SAVEPOINT cs_add_analysis_start;

    p_analysis_id := NULL;

    cs_security.require_operator(p_actor_id);

    IF TRIM(p_technique) IS NULL
       OR LENGTH(p_technique) > 120
       OR p_findings IS NULL
       OR p_confidence IS NULL
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Technique findings and confidence are required'
        );
    END IF;

    IF DBMS_LOB.GETLENGTH(p_findings) = 0
       OR p_confidence NOT BETWEEN 0 AND 100
       OR p_confidence <> ROUND(p_confidence, 2)
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Invalid findings or confidence'
        );
    END IF;

    BEGIN
        SELECT incident_id
        INTO v_incident_id
        FROM evidence
        WHERE evidence_id = p_evidence_id;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20001, 'Evidence not found'
            );
    END;

    SELECT status
    INTO v_status
    FROM incident
    WHERE incident_id = v_incident_id
    FOR UPDATE WAIT 5;

    cs_security.require_incident_access(
        p_actor_id, v_incident_id, 1
    );

    IF v_status IN ('RESOLVED', 'CLOSED') THEN
        RAISE_APPLICATION_ERROR(
            -20004, 'Reopen the incident before adding analysis'
        );
    END IF;

    SELECT evidence_id
    INTO v_locked_evidence
    FROM evidence
    WHERE evidence_id = p_evidence_id
    FOR UPDATE WAIT 5;

    BEGIN
        SELECT investigator_id
        INTO v_investigator
        FROM investigator
        WHERE user_id = p_actor_id
          AND availability <> 'INACTIVE';
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20002, 'Analyst needs an active investigator profile'
            );
    END;

    IF p_supersedes_analysis_id IS NOT NULL THEN
        BEGIN
            SELECT evidence_id
            INTO v_previous_evidence
            FROM forensic_analysis
            WHERE analysis_id = p_supersedes_analysis_id;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                RAISE_APPLICATION_ERROR(
                    -20001, 'Previous analysis not found'
                );
        END;

        IF v_previous_evidence <> p_evidence_id THEN
            RAISE_APPLICATION_ERROR(
                -20010, 'Revision must reference the same evidence'
            );
        END IF;

        SELECT COUNT(*)
        INTO v_count
        FROM forensic_analysis
        WHERE supersedes_analysis_id = p_supersedes_analysis_id;

        IF v_count > 0 THEN
            RAISE_APPLICATION_ERROR(
                -20004, 'Analysis already has a revision; revise the latest version'
            );
        END IF;
    END IF;

    INSERT INTO forensic_analysis (
        evidence_id,
        investigator_id,
        supersedes_analysis_id,
        technique,
        findings,
        indicators,
        confidence
    ) VALUES (
        p_evidence_id,
        v_investigator,
        p_supersedes_analysis_id,
        p_technique,
        p_findings,
        p_indicators,
        p_confidence
    )
    RETURNING analysis_id INTO p_analysis_id;

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO cs_add_analysis_start;
        p_analysis_id := NULL;
        RAISE;
END sp_add_analysis;
/


CREATE OR REPLACE PROCEDURE sp_record_action (
    p_actor_id IN NUMBER,
    p_incident_id IN NUMBER,
    p_action_type IN VARCHAR2,
    p_description IN CLOB,
    p_outcome IN VARCHAR2,
    p_action_id OUT NUMBER
) AUTHID DEFINER
IS
    v_status incident.status%TYPE;
    v_cycle_id NUMBER;
BEGIN
    SAVEPOINT cs_record_action_start;

    p_action_id := NULL;

    cs_security.require_operator(p_actor_id);

    IF TRIM(p_action_type) IS NULL
       OR LENGTH(p_action_type) > 80
       OR p_description IS NULL
       OR TRIM(p_outcome) IS NULL
       OR LENGTH(p_outcome) > 1000
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Action type description and outcome are required'
        );
    END IF;

    IF DBMS_LOB.GETLENGTH(p_description) = 0 THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Response description cannot be empty'
        );
    END IF;

    BEGIN
        SELECT status
        INTO v_status
        FROM incident
        WHERE incident_id = p_incident_id
        FOR UPDATE WAIT 5;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20001, 'Incident not found'
            );
    END;

    cs_security.require_incident_access(
        p_actor_id, p_incident_id, 1
    );

    IF v_status NOT IN ('INVESTIGATING', 'CONTAINED') THEN
        RAISE_APPLICATION_ERROR(
            -20004, 'Response actions require an investigating or contained incident'
        );
    END IF;

    cs_security.get_active_cycle(
        p_incident_id, v_cycle_id
    );

    INSERT INTO response_action (
        cycle_id,
        performed_by,
        action_type,
        description,
        outcome
    ) VALUES (
        v_cycle_id,
        p_actor_id,
        p_action_type,
        p_description,
        p_outcome
    )
    RETURNING action_id INTO p_action_id;

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO cs_record_action_start;
        p_action_id := NULL;
        RAISE;
END sp_record_action;
/