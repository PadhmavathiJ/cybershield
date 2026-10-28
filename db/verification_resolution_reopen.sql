SET SERVEROUTPUT ON

DECLARE
    v_tag VARCHAR2(32) := RAWTOHEX(SYS_GUID());
    v_admin NUMBER;
    v_manager NUMBER;
    v_analyst NUMBER;
    v_investigator NUMBER;
    v_incident NUMBER;
    v_old_cycle NUMBER;
    v_new_cycle NUMBER;
    v_assignment NUMBER;
    v_resolution NUMBER;
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

    PROCEDURE expect_error(
        p_operation VARCHAR2,
        p_actor NUMBER,
        p_expected NUMBER,
        p_label VARCHAR2
    ) IS
    BEGIN
        set_actor(p_actor);

        CASE p_operation
            WHEN 'END_ASSIGNMENT' THEN
                sp_end_assignment(
                    p_actor, v_assignment, 'Test ending'
                );

            WHEN 'RESOLVE' THEN
                sp_resolve_incident(
                    p_actor,
                    v_incident,
                    'Temporary resolution summary',
                    'Simulated root cause',
                    NULL,
                    0,
                    v_unused
                );

            WHEN 'ESCALATE' THEN
                sp_escalate_sla(
                    p_actor, v_incident, 'Test breach reason'
                );

            WHEN 'REOPEN' THEN
                sp_reopen_incident(
                    p_actor,
                    v_incident,
                    'New simulated information',
                    v_unused
                );

            ELSE
                RAISE_APPLICATION_ERROR(
                    -20998, 'Unknown test operation'
                );
        END CASE;

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

    SAVEPOINT resolution_reopen_test;

    MERGE INTO soc_policy p
    USING (
        SELECT 'response_hours' policy_key, 1 number_value
        FROM dual
        UNION ALL
        SELECT 'resolution_hours', 24 FROM dual
    ) s
    ON (p.policy_key = s.policy_key)
    WHEN MATCHED THEN
        UPDATE SET p.number_value = s.number_value
    WHEN NOT MATCHED THEN
        INSERT (policy_key, number_value, description)
        VALUES (
            s.policy_key,
            s.number_value,
            'Temporary lifecycle test policy'
        );

    v_admin := make_user('lifecycle-admin', 'ADMIN');
    v_manager := make_user('lifecycle-manager', 'MANAGER');
    v_analyst := make_user('lifecycle-analyst', 'ANALYST');

    set_actor(v_admin);

    INSERT INTO investigator (
        user_id, specialization, availability
    ) VALUES (
        v_analyst, 'Lifecycle testing', 'AVAILABLE'
    )
    RETURNING investigator_id INTO v_investigator;

    INSERT INTO incident (
        title, description, severity, status, created_by
    ) VALUES (
        'Lifecycle verification',
        'Temporary contained incident fixture',
        'HIGH',
        'CONTAINED',
        v_admin
    )
    RETURNING incident_id INTO v_incident;

    INSERT INTO investigation_cycle (
        incident_id, cycle_no
    ) VALUES (
        v_incident, 1
    )
    RETURNING cycle_id INTO v_old_cycle;

    INSERT INTO sla (
        cycle_id, response_due_at, resolution_due_at
    ) VALUES (
        v_old_cycle,
        SYSTIMESTAMP + INTERVAL '1' HOUR,
        SYSTIMESTAMP + INTERVAL '1' DAY
    );

    sp_assign_investigator(
        v_admin,
        v_incident,
        v_investigator,
        'LEAD',
        v_assignment
    );

    sp_end_assignment(
        v_admin,
        v_assignment,
        'Temporary assignment ended for testing'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM incident_assignment a
    WHERE a.assignment_id = v_assignment
      AND a.ended_at IS NOT NULL
      AND EXISTS (
          SELECT 1
          FROM audit_log l
          WHERE l.entity_id = a.assignment_id
            AND l.entity_name = 'incident_assignment'
            AND l.action = 'ASSIGNMENT_END_REASON'
            AND l.actor_user_id = v_admin
      );

    check_result(
        v_count = 1,
        'Ending assignment preserves row and audit reason'
    );

    expect_error(
        'END_ASSIGNMENT', v_admin, -20004,
        'Already ended assignment is rejected'
    );

    expect_error(
        'RESOLVE', v_admin, -20006,
        'Resolution without response action is rejected'
    );

    expect_error(
        'ESCALATE', v_manager, -20004,
        'SLA without a breach cannot be escalated'
    );

    set_actor(v_admin);

    UPDATE sla
    SET response_due_at = SYSTIMESTAMP - INTERVAL '1' HOUR
    WHERE cycle_id = v_old_cycle;

    set_actor(v_manager);

    sp_escalate_sla(
        v_manager,
        v_incident,
        'Simulated response deadline breach'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM sla
    WHERE cycle_id = v_old_cycle
      AND escalated_at IS NOT NULL
      AND escalated_by = v_manager
      AND breach_reason = 'Simulated response deadline breach';

    check_result(
        v_count = 1,
        'Manager can escalate a breached SLA'
    );

    set_actor(v_admin);

    sp_assign_investigator(
        v_admin,
        v_incident,
        v_investigator,
        'LEAD',
        v_assignment
    );

    INSERT INTO response_action (
        cycle_id,
        performed_by,
        action_type,
        description,
        outcome
    ) VALUES (
        v_old_cycle,
        v_admin,
        'CONTAINMENT',
        'Simulated containment action',
        'Contained'
    );

    sp_resolve_incident(
        v_admin,
        v_incident,
        'Simulated investigation completed',
        'Simulated configuration weakness',
        'Improve configuration validation',
        0,
        v_resolution
    );

    SELECT COUNT(*)
    INTO v_count
    FROM incident i
    JOIN resolution r ON r.cycle_id = v_old_cycle
    WHERE i.incident_id = v_incident
      AND i.status = 'RESOLVED'
      AND i.closed_at IS NULL
      AND r.resolution_id = v_resolution;

    check_result(
        v_count = 1,
        'Resolution is recorded and incident becomes RESOLVED'
    );

    expect_error(
        'RESOLVE', v_admin, -20005,
        'Duplicate resolution is rejected'
    );

    set_actor(v_admin);

    sp_change_status(
        v_admin,
        v_incident,
        'CLOSED',
        'Closure verification'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM incident i
    JOIN investigation_cycle c
      ON c.incident_id = i.incident_id
    WHERE i.incident_id = v_incident
      AND i.status = 'CLOSED'
      AND i.closed_at IS NOT NULL
      AND c.cycle_id = v_old_cycle
      AND c.ended_at IS NOT NULL
      AND NOT EXISTS (
          SELECT 1
          FROM incident_assignment a
          WHERE a.cycle_id = c.cycle_id
            AND a.ended_at IS NULL
      );

    check_result(
        v_count = 1,
        'Closure ends cycle and active assignments'
    );

    expect_error(
        'REOPEN', v_analyst, -20007,
        'Analyst cannot reopen an incident'
    );

    set_actor(v_manager);

    sp_reopen_incident(
        v_manager,
        v_incident,
        'New simulated information requires investigation',
        v_new_cycle
    );

    SELECT COUNT(*)
    INTO v_count
    FROM incident i
    JOIN investigation_cycle c
      ON c.incident_id = i.incident_id
    JOIN sla s ON s.cycle_id = c.cycle_id
    WHERE i.incident_id = v_incident
      AND i.status = 'OPEN'
      AND i.closed_at IS NULL
      AND c.cycle_id = v_new_cycle
      AND c.cycle_no = 2
      AND c.ended_at IS NULL
      AND s.acknowledged_at IS NULL
      AND s.response_due_at =
          c.started_at + NUMTODSINTERVAL(1, 'HOUR')
      AND s.resolution_due_at =
          c.started_at + NUMTODSINTERVAL(24, 'HOUR');

    check_result(
        v_count = 1,
        'Reopening creates cycle 2 and fresh SLA'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM resolution r
    JOIN investigation_cycle c ON c.cycle_id = r.cycle_id
    WHERE r.resolution_id = v_resolution
      AND c.cycle_id = v_old_cycle
      AND c.ended_at IS NOT NULL
      AND EXISTS (
          SELECT 1
          FROM incident_status_history h
          WHERE h.cycle_id = v_new_cycle
            AND h.from_status = 'CLOSED'
            AND h.to_status = 'OPEN'
            AND h.changed_by = v_manager
      );

    check_result(
        v_count = 1,
        'Previous resolution is preserved and reopening has history'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM incident_assignment
    WHERE cycle_id = v_new_cycle;

    check_result(
        v_count = 0,
        'Reopened investigation requires fresh assignments'
    );

    ROLLBACK TO resolution_reopen_test;
    restore_context;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: ' || v_passed ||
        ' lifecycle checks passed; test records rolled back'
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO resolution_reopen_test;
        restore_context;
        RAISE;
END;
/