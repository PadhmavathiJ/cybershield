SET SERVEROUTPUT ON

DECLARE
    v_tag VARCHAR2(32) := RAWTOHEX(SYS_GUID());
    v_manager NUMBER;
    v_lead_user NUMBER;
    v_second_user NUMBER;
    v_inactive_user NUMBER;
    v_outsider NUMBER;
    v_lead_inv NUMBER;
    v_second_inv NUMBER;
    v_inactive_inv NUMBER;
    v_incident NUMBER;
    v_cycle NUMBER;
    v_assignment NUMBER;
    v_unused NUMBER;
    v_count NUMBER;
    v_passed NUMBER := 0;
    v_previous_client VARCHAR2(64);

    FUNCTION make_user(
        p_label VARCHAR2,
        p_role VARCHAR2
    ) RETURN NUMBER
    IS
        v_id NUMBER;
    BEGIN
        INSERT INTO app_user (
            email, password_hash, full_name, role_code
        ) VALUES (
            p_label || '-' || v_tag || '@example.invalid',
            'test-only',
            p_label,
            p_role
        )
        RETURNING user_id INTO v_id;

        RETURN v_id;
    END;

    FUNCTION make_investigator(
        p_user NUMBER,
        p_availability VARCHAR2
    ) RETURN NUMBER
    IS
        v_id NUMBER;
    BEGIN
        INSERT INTO investigator (
            user_id, specialization, availability
        ) VALUES (
            p_user, 'Workflow testing', p_availability
        )
        RETURNING investigator_id INTO v_id;

        RETURN v_id;
    END;

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

    PROCEDURE expect_assignment_error(
        p_actor NUMBER,
        p_investigator NUMBER,
        p_role VARCHAR2,
        p_expected NUMBER,
        p_label VARCHAR2
    ) IS
    BEGIN
        set_actor(p_actor);

        sp_assign_investigator(
            p_actor,
            v_incident,
            p_investigator,
            p_role,
            v_unused
        );

        RAISE_APPLICATION_ERROR(
            -20999, 'FAIL: ' || p_label
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = p_expected THEN
                check_result(TRUE, p_label);
            ELSE
                RAISE;
            END IF;
    END;

    PROCEDURE expect_status_error(
        p_actor NUMBER,
        p_status VARCHAR2,
        p_expected NUMBER,
        p_label VARCHAR2
    ) IS
    BEGIN
        set_actor(p_actor);

        sp_change_status(
            p_actor,
            v_incident,
            p_status,
            'Negative verification'
        );

        RAISE_APPLICATION_ERROR(
            -20999, 'FAIL: ' || p_label
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = p_expected THEN
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

    SAVEPOINT assignment_status_test;

    v_manager := make_user('manager', 'MANAGER');
    v_lead_user := make_user('lead', 'ANALYST');
    v_second_user := make_user('second', 'ANALYST');
    v_inactive_user := make_user('inactive', 'ANALYST');
    v_outsider := make_user('outsider', 'ANALYST');

    v_lead_inv :=
        make_investigator(v_lead_user, 'AVAILABLE');
    v_second_inv :=
        make_investigator(v_second_user, 'AVAILABLE');
    v_inactive_inv :=
        make_investigator(v_inactive_user, 'INACTIVE');

    INSERT INTO incident (
        title, description, severity, created_by
    ) VALUES (
        'Assignment verification',
        'Temporary verification fixture',
        'HIGH',
        v_manager
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

    set_actor(v_manager);

    sp_assign_investigator(
        v_manager,
        v_incident,
        v_lead_inv,
        'LEAD',
        v_assignment
    );

    SELECT COUNT(*)
    INTO v_count
    FROM incident_assignment
    WHERE assignment_id = v_assignment
      AND cycle_id = v_cycle
      AND investigator_id = v_lead_inv
      AND assigned_by = v_manager
      AND assignment_role = 'LEAD'
      AND ended_at IS NULL;

    check_result(
        v_count = 1,
        'Manager can assign the first lead'
    );

    expect_assignment_error(
        v_manager,
        v_second_inv,
        'LEAD',
        -20011,
        'Second active lead is rejected'
    );

    expect_assignment_error(
        v_manager,
        v_lead_inv,
        'SUPPORT',
        -20010,
        'Duplicate active membership is rejected'
    );

    expect_assignment_error(
        v_manager,
        v_inactive_inv,
        'SUPPORT',
        -20002,
        'Inactive investigator is rejected'
    );

    expect_assignment_error(
        v_lead_user,
        v_second_inv,
        'SUPPORT',
        -20007,
        'Analyst cannot assign investigators'
    );

    expect_status_error(
        v_outsider,
        'TRIAGED',
        -20007,
        'Unassigned analyst cannot change incident status'
    );

    expect_status_error(
        v_lead_user,
        'CONTAINED',
        -20004,
        'Skipping lifecycle stages is rejected'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM incident_status_history
    WHERE cycle_id = v_cycle;

    check_result(
        v_count = 0,
        'Rejected transitions create no status history'
    );

    set_actor(v_lead_user);

    sp_change_status(
        v_lead_user,
        v_incident,
        'TRIAGED',
        'Lead acknowledged the incident'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM incident i
    JOIN sla s ON s.cycle_id = v_cycle
    WHERE i.incident_id = v_incident
      AND i.status = 'TRIAGED'
      AND s.acknowledged_at IS NOT NULL;

    check_result(
        v_count = 1,
        'Assigned analyst can triage and acknowledge SLA'
    );

    sp_change_status(
        v_lead_user,
        v_incident,
        'INVESTIGATING',
        'Investigation started'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM incident
    WHERE incident_id = v_incident
      AND status = 'INVESTIGATING';

    check_result(
        v_count = 1,
        'TRIAGED to INVESTIGATING succeeds'
    );

    sp_change_status(
        v_lead_user,
        v_incident,
        'CONTAINED',
        'Simulated containment completed'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM incident i
    WHERE i.incident_id = v_incident
      AND i.status = 'CONTAINED'
      AND (
          SELECT COUNT(*)
          FROM incident_status_history h
          WHERE h.cycle_id = v_cycle
      ) = 3;

    check_result(
        v_count = 1,
        'Containment succeeds and all three changes have history'
    );

    expect_status_error(
        v_manager,
        'CLOSED',
        -20007,
        'Manager cannot bypass operational permissions'
    );

    ROLLBACK TO assignment_status_test;
    restore_context;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: ' || v_passed ||
        ' assignment/status checks passed; test records rolled back'
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO assignment_status_test;
        restore_context;
        RAISE;
END;
/