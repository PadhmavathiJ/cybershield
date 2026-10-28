SET SERVEROUTPUT ON

DECLARE
    v_tag VARCHAR2(32) := RAWTOHEX(SYS_GUID());
    v_admin NUMBER;
    v_outsider NUMBER;
    v_investigator NUMBER;
    v_incident NUMBER;
    v_cycle NUMBER;
    v_evidence NUMBER;
    v_other_evidence NUMBER;
    v_original NUMBER;
    v_revision NUMBER;
    v_action NUMBER;
    v_resolution NUMBER;
    v_unused NUMBER;
    v_count NUMBER;
    v_passed NUMBER := 0;
    v_previous_client VARCHAR2(64);

    PROCEDURE set_actor(p_actor NUMBER) IS
    BEGIN
        DBMS_SESSION.SET_IDENTIFIER(
            TO_CHAR(p_actor, 'FM9999999990')
        );
    END;

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

    PROCEDURE expect_analysis_error(
        p_actor NUMBER,
        p_evidence NUMBER,
        p_previous NUMBER,
        p_confidence NUMBER,
        p_error NUMBER,
        p_label VARCHAR2
    ) IS
    BEGIN
        set_actor(p_actor);

        sp_add_analysis(
            p_actor,
            p_evidence,
            p_previous,
            'Test technique',
            'Test findings',
            NULL,
            p_confidence,
            v_unused
        );

        RAISE_APPLICATION_ERROR(
            -20999, 'FAIL: ' || p_label
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = p_error THEN
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

    SAVEPOINT analysis_response_test;

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'analysis-admin-' || v_tag || '@example.invalid',
        'test-only', 'Analysis Test Admin', 'ADMIN'
    )
    RETURNING user_id INTO v_admin;

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'analysis-outsider-' || v_tag || '@example.invalid',
        'test-only', 'Unassigned Analyst', 'ANALYST'
    )
    RETURNING user_id INTO v_outsider;

    set_actor(v_admin);

    INSERT INTO investigator (
        user_id, specialization
    ) VALUES (
        v_admin, 'Forensic verification'
    )
    RETURNING investigator_id INTO v_investigator;

    INSERT INTO incident (
        title, description, severity, created_by
    ) VALUES (
        'Analysis verification',
        'Temporary workflow fixture',
        'HIGH',
        v_admin
    )
    RETURNING incident_id INTO v_incident;

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
        'analysis-' || v_tag || '.log',
        'analysis.log',
        SYSTIMESTAMP - INTERVAL '1' MINUTE,
        RPAD('a', 64, 'a'),
        100,
        'INTERNAL',
        v_evidence
    );

    sp_register_evidence(
        v_admin,
        v_incident,
        'LOG',
        'other-' || v_tag || '.log',
        'other.log',
        SYSTIMESTAMP - INTERVAL '1' MINUTE,
        RPAD('b', 64, 'b'),
        100,
        'INTERNAL',
        v_other_evidence
    );

    sp_add_analysis(
        v_admin,
        v_evidence,
        NULL,
        'Log examination',
        'Initial simulated findings',
        '192.0.2.10',
        80,
        v_original
    );

    SELECT COUNT(*)
    INTO v_count
    FROM forensic_analysis
    WHERE analysis_id = v_original
      AND evidence_id = v_evidence
      AND investigator_id = v_investigator
      AND supersedes_analysis_id IS NULL
      AND confidence = 80;

    check_result(
        v_count = 1,
        'Analysis records evidence investigator and confidence'
    );

    sp_add_analysis(
        v_admin,
        v_evidence,
        v_original,
        'Extended log examination',
        'Revised simulated findings',
        '192.0.2.10',
        90,
        v_revision
    );

    SELECT COUNT(*)
    INTO v_count
    FROM forensic_analysis
    WHERE evidence_id = v_evidence
      AND (
          (
              analysis_id = v_original
              AND supersedes_analysis_id IS NULL
              AND confidence = 80
              AND DBMS_LOB.COMPARE(
                  findings,
                  TO_CLOB('Initial simulated findings')
              ) = 0
          )
          OR
          (
              analysis_id = v_revision
              AND supersedes_analysis_id = v_original
              AND confidence = 90
          )
      );

    check_result(
        v_count = 2,
        'Revision creates a new row and preserves original findings'
    );

    expect_analysis_error(
        v_admin, v_evidence, v_original, 95, -20004,
        'Already revised analysis cannot branch'
    );

    expect_analysis_error(
        v_admin, v_other_evidence, v_revision, 95, -20010,
        'Revision cannot reference another evidence item'
    );

    expect_analysis_error(
        v_admin, v_evidence, NULL, 101, -20010,
        'Confidence above 100 is rejected'
    );

    expect_analysis_error(
        v_outsider, v_evidence, NULL, 80, -20007,
        'Unassigned analyst cannot add findings'
    );

    set_actor(v_admin);

    BEGIN
        sp_record_action(
            v_admin,
            v_incident,
            'CONTAINMENT',
            'Simulated response',
            'Contained',
            v_unused
        );

        RAISE_APPLICATION_ERROR(
            -20999, 'Response action accepted in OPEN state'
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = -20004 THEN
                check_result(
                    TRUE,
                    'Response action requires investigation or containment'
                );
            ELSE
                RAISE;
            END IF;
    END;

    sp_change_status(
        v_admin, v_incident, 'TRIAGED', 'Test triage'
    );

    sp_change_status(
        v_admin, v_incident, 'INVESTIGATING', 'Test investigation'
    );

    sp_record_action(
        v_admin,
        v_incident,
        'CONTAINMENT',
        'Simulated containment operation',
        'Contained successfully',
        v_action
    );

    SELECT COUNT(*)
    INTO v_count
    FROM response_action
    WHERE action_id = v_action
      AND cycle_id = v_cycle
      AND performed_by = v_admin
      AND outcome = 'Contained successfully';

    check_result(
        v_count = 1,
        'Response procedure records the actor and active cycle'
    );

    sp_change_status(
        v_admin, v_incident, 'CONTAINED', 'Test containment'
    );

    sp_resolve_incident(
        v_admin,
        v_incident,
        'Test investigation completed',
        'Simulated configuration weakness',
        NULL,
        0,
        v_resolution
    );

    SELECT COUNT(*)
    INTO v_count
    FROM resolution r
    JOIN incident i ON i.incident_id = v_incident
    WHERE r.resolution_id = v_resolution
      AND r.cycle_id = v_cycle
      AND i.status = 'RESOLVED';

    check_result(
        v_count = 1,
        'Recorded response supports incident resolution'
    );

    ROLLBACK TO analysis_response_test;
    restore_context;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: ' || v_passed ||
        ' analysis/response checks passed; test records rolled back'
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO analysis_response_test;
        restore_context;
        RAISE;
END;
/