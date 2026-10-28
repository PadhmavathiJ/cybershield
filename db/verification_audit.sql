SET SERVEROUTPUT ON

DECLARE
    v_tag VARCHAR2(32) := RAWTOHEX(SYS_GUID());
    v_admin NUMBER;
    v_investigator NUMBER;
    v_incident NUMBER;
    v_cycle NUMBER;
    v_evidence NUMBER;
    v_analysis NUMBER;
    v_action NUMBER;
    v_resolution NUMBER;
    v_count NUMBER;
    v_audit_before NUMBER;
    v_passed NUMBER := 0;
    v_previous_client VARCHAR2(64);

    PROCEDURE check_result(
        p_ok BOOLEAN,
        p_label VARCHAR2
    ) IS
    BEGIN
        IF p_ok THEN
            v_passed := v_passed + 1;
            DBMS_OUTPUT.PUT_LINE('PASS: ' || p_label);
        ELSE
            RAISE_APPLICATION_ERROR(
                -20999, 'FAIL: ' || p_label
            );
        END IF;
    END;

    PROCEDURE expect_protected(
        p_sql VARCHAR2,
        p_label VARCHAR2
    ) IS
    BEGIN
        EXECUTE IMMEDIATE p_sql;

        RAISE_APPLICATION_ERROR(
            -20999, 'FAIL: ' || p_label
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = -20008 THEN
                check_result(TRUE, p_label);
            ELSE
                RAISE;
            END IF;
    END;

    PROCEDURE restore_context IS
    BEGIN
        IF v_previous_client IS NULL THEN
            DBMS_SESSION.CLEAR_IDENTIFIER;
        ELSE
            DBMS_SESSION.SET_IDENTIFIER(v_previous_client);
        END IF;
    END;

BEGIN
    v_previous_client :=
        SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER');

    SELECT COUNT(*)
    INTO v_audit_before
    FROM audit_log;

    SAVEPOINT audit_test;

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'audit-' || v_tag || '@example.invalid',
        'test-only', 'Audit Test Admin', 'ADMIN'
    )
    RETURNING user_id INTO v_admin;

    DBMS_SESSION.SET_IDENTIFIER(
        TO_CHAR(v_admin, 'FM9999999990')
    );

    INSERT INTO investigator (
        user_id, specialization
    ) VALUES (
        v_admin, 'Audit verification'
    )
    RETURNING investigator_id INTO v_investigator;

    INSERT INTO incident (
        title, description, severity, status, created_by
    ) VALUES (
        'Audit verification',
        'Sensitive narrative must be redacted',
        'HIGH',
        'CONTAINED',
        v_admin
    )
    RETURNING incident_id INTO v_incident;

    SELECT COUNT(*)
    INTO v_count
    FROM audit_log
    WHERE entity_name = 'incident'
      AND entity_id = v_incident
      AND action = 'INSERT'
      AND actor_user_id = v_admin
      AND before_data IS NULL
      AND JSON_VALUE(after_data, '$.title') =
          'Audit verification'
      AND JSON_VALUE(after_data, '$.description') =
          '[REDACTED]';

    check_result(
        v_count = 1,
        'Insert audit captures actor and redacts narrative'
    );

    INSERT INTO investigation_cycle (
        incident_id, cycle_no
    ) VALUES (
        v_incident, 1
    )
    RETURNING cycle_id INTO v_cycle;

    INSERT INTO sla (
        cycle_id, response_due_at, resolution_due_at
    ) VALUES (
        v_cycle,
        SYSTIMESTAMP + INTERVAL '1' HOUR,
        SYSTIMESTAMP + INTERVAL '1' DAY
    );

    sp_register_evidence(
        v_admin,
        v_incident,
        'LOG',
        'audit-' || v_tag || '.log',
        'sensitive-original.log',
        SYSTIMESTAMP - INTERVAL '1' MINUTE,
        RPAD('a', 64, 'a'),
        100,
        'RESTRICTED',
        v_evidence
    );

    sp_add_analysis(
        v_admin,
        v_evidence,
        NULL,
        'Log examination',
        'Sensitive simulated findings',
        NULL,
        90,
        v_analysis
    );

    sp_record_action(
        v_admin,
        v_incident,
        'CONTAINMENT',
        'Simulated containment response',
        'Contained',
        v_action
    );

    sp_resolve_incident(
        v_admin,
        v_incident,
        'Investigation complete',
        'Simulated root cause',
        NULL,
        0,
        v_resolution
    );

    SELECT COUNT(*)
    INTO v_count
    FROM audit_log
    WHERE entity_name = 'incident'
      AND entity_id = v_incident
      AND action = 'UPDATE'
      AND actor_user_id = v_admin
      AND JSON_VALUE(before_data, '$.status') = 'CONTAINED'
      AND JSON_VALUE(after_data, '$.status') = 'RESOLVED';

    check_result(
        v_count = 1,
        'Update audit preserves previous and new incident status'
    );

    expect_protected(
        'UPDATE chain_of_custody SET purpose = purpose
         WHERE evidence_id = ' || TO_CHAR(v_evidence),
        'Custody UPDATE is blocked'
    );

    expect_protected(
        'DELETE FROM chain_of_custody
         WHERE evidence_id = ' || TO_CHAR(v_evidence),
        'Custody DELETE is blocked'
    );

    expect_protected(
        'UPDATE forensic_analysis SET confidence = confidence
         WHERE analysis_id = ' || TO_CHAR(v_analysis),
        'Analysis UPDATE is blocked'
    );

    expect_protected(
        'DELETE FROM forensic_analysis
         WHERE analysis_id = ' || TO_CHAR(v_analysis),
        'Analysis DELETE is blocked'
    );

    expect_protected(
        'UPDATE response_action SET outcome = outcome
         WHERE action_id = ' || TO_CHAR(v_action),
        'Response UPDATE is blocked'
    );

    expect_protected(
        'DELETE FROM response_action
         WHERE action_id = ' || TO_CHAR(v_action),
        'Response DELETE is blocked'
    );

    expect_protected(
        'UPDATE resolution SET financial_loss = financial_loss
         WHERE resolution_id = ' || TO_CHAR(v_resolution),
        'Resolution UPDATE is blocked'
    );

    expect_protected(
        'DELETE FROM resolution
         WHERE resolution_id = ' || TO_CHAR(v_resolution),
        'Resolution DELETE is blocked'
    );

    expect_protected(
        'UPDATE incident_status_history SET reason = reason
         WHERE cycle_id = ' || TO_CHAR(v_cycle),
        'Incident history UPDATE is blocked'
    );

    expect_protected(
        'DELETE FROM incident_status_history
         WHERE cycle_id = ' || TO_CHAR(v_cycle),
        'Incident history DELETE is blocked'
    );

    expect_protected(
        'UPDATE audit_log SET action = action
         WHERE entity_name = ''incident''
         AND entity_id = ' || TO_CHAR(v_incident),
        'Audit UPDATE is blocked'
    );

    expect_protected(
        'DELETE FROM audit_log
         WHERE entity_name = ''incident''
         AND entity_id = ' || TO_CHAR(v_incident),
        'Audit DELETE is blocked'
    );

    ROLLBACK TO audit_test;

    SELECT COUNT(*)
    INTO v_count
    FROM audit_log;

    check_result(
        v_count = v_audit_before,
        'Transaction rollback also removes its audit records'
    );

    restore_context;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: ' || v_passed ||
        ' audit checks passed; test records rolled back'
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO audit_test;
        restore_context;
        RAISE;
END;
/