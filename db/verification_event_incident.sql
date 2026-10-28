SET SERVEROUTPUT ON

DECLARE
    v_tag VARCHAR2(32) := RAWTOHEX(SYS_GUID());
    v_actor NUMBER;
    v_server NUMBER;
    v_ip NUMBER;
    v_attack NUMBER;
    v_event NUMBER;
    v_alert NUMBER;
    v_repeat_event NUMBER;
    v_repeat_alert NUMBER;
    v_low_event NUMBER;
    v_low_alert NUMBER;
    v_incident NUMBER;
    v_unused NUMBER;
    v_count NUMBER;
    v_before NUMBER;
    v_after NUMBER;
    v_passed NUMBER := 0;
    v_time TIMESTAMP WITH TIME ZONE := SYSTIMESTAMP;
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

    SAVEPOINT event_incident_test;

    MERGE INTO soc_policy p
    USING (
        SELECT 'alert_threshold' policy_key, 70 number_value
        FROM dual
        UNION ALL
        SELECT 'response_hours', 1 FROM dual
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
            'Temporary workflow test policy'
        );

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'workflow-' || v_tag || '@example.invalid',
        'test-only',
        'Workflow Test Admin',
        'ADMIN'
    )
    RETURNING user_id INTO v_actor;

    DBMS_SESSION.SET_IDENTIFIER(
        TO_CHAR(v_actor, 'FM9999999990')
    );

    INSERT INTO server (
        hostname, os_name, department, criticality
    ) VALUES (
        'TEST-' || v_tag, 'Test OS', 'Test Department', 'HIGH'
    )
    RETURNING server_id INTO v_server;

    BEGIN
        SELECT ip_id
        INTO v_ip
        FROM ip_address
        WHERE ip_text = '192.0.2.200';
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            INSERT INTO ip_address (
                ip_text, country_code, is_simulated
            ) VALUES (
                '192.0.2.200', NULL, 1
            )
            RETURNING ip_id INTO v_ip;
    END;

    INSERT INTO attack_type (
        name, description
    ) VALUES (
        'TEST-' || v_tag,
        'Simulated workflow verification'
    )
    RETURNING attack_type_id INTO v_attack;

    sp_ingest_event(
        v_actor,
        'HIGH-' || v_tag,
        v_server,
        v_ip,
        v_attack,
        v_time,
        'HTTPS',
        10,
        100,
        200,
        95,
        'Simulated high severity event',
        v_event,
        v_alert
    );

    SELECT COUNT(*)
    INTO v_count
    FROM alert
    WHERE alert_id = v_alert
      AND event_id = v_event
      AND severity = 'CRITICAL'
      AND status = 'NEW';

    check_result(
        v_count = 1,
        'High severity event creates a critical alert'
    );

    sp_ingest_event(
        v_actor,
        'HIGH-' || v_tag,
        v_server,
        v_ip,
        v_attack,
        v_time,
        'HTTPS',
        10,
        100,
        200,
        95,
        'Simulated high severity event',
        v_repeat_event,
        v_repeat_alert
    );

    SELECT COUNT(*)
    INTO v_count
    FROM security_event
    WHERE source_event_key = 'HIGH-' || v_tag;

    check_result(
        v_repeat_event = v_event
        AND v_repeat_alert = v_alert
        AND v_count = 1,
        'Identical retry returns existing event and alert'
    );

    BEGIN
        sp_ingest_event(
            v_actor,
            'HIGH-' || v_tag,
            v_server,
            v_ip,
            v_attack,
            v_time,
            'HTTPS',
            10,
            100,
            200,
            96,
            'Simulated high severity event',
            v_repeat_event,
            v_repeat_alert
        );

        RAISE_APPLICATION_ERROR(
            -20999, 'Conflicting retry was accepted'
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = -20009 THEN
                check_result(
                    TRUE,
                    'Conflicting retry is rejected'
                );
            ELSE
                RAISE;
            END IF;
    END;

    sp_ingest_event(
        v_actor,
        'LOW-' || v_tag,
        v_server,
        v_ip,
        v_attack,
        v_time,
        'HTTPS',
        1,
        20,
        30,
        20,
        'Simulated low severity event',
        v_low_event,
        v_low_alert
    );

    SELECT COUNT(*)
    INTO v_count
    FROM alert
    WHERE event_id = v_low_event;

    check_result(
        v_low_event IS NOT NULL
        AND v_low_alert IS NULL
        AND v_count = 0,
        'Below-threshold event creates no alert'
    );

    sp_create_incident(
        v_actor,
        v_alert,
        'Workflow verification',
        'Temporary incident for verification',
        'CRITICAL',
        NULL,
        v_incident
    );

    SELECT COUNT(*)
    INTO v_count
    FROM incident i
    JOIN investigation_cycle c
      ON c.incident_id = i.incident_id
    JOIN incident_alert ia
      ON ia.incident_id = i.incident_id
    JOIN incident_status_history h
      ON h.cycle_id = c.cycle_id
    WHERE i.incident_id = v_incident
      AND i.status = 'OPEN'
      AND c.cycle_no = 1
      AND c.ended_at IS NULL
      AND ia.alert_id = v_alert
      AND h.from_status IS NULL
      AND h.to_status = 'OPEN';

    check_result(
        v_count = 1,
        'Incident has alert link cycle and initial history'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM sla s
    JOIN investigation_cycle c
      ON c.cycle_id = s.cycle_id
    WHERE c.incident_id = v_incident
      AND s.response_due_at =
          c.started_at + NUMTODSINTERVAL(1, 'HOUR')
      AND s.resolution_due_at =
          c.started_at + NUMTODSINTERVAL(24, 'HOUR')
      AND s.acknowledged_at IS NULL;

    check_result(
        v_count = 1,
        'SLA deadlines follow configured policies'
    );

    SELECT COUNT(*)
    INTO v_before
    FROM incident;

    BEGIN
        sp_create_incident(
            v_actor,
            v_alert,
            'Duplicate incident',
            'Must not be created',
            'HIGH',
            NULL,
            v_unused
        );

        RAISE_APPLICATION_ERROR(
            -20999, 'Duplicate incident was accepted'
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = -20009 THEN
                check_result(
                    TRUE,
                    'Alert cannot create a second incident'
                );
            ELSE
                RAISE;
            END IF;
    END;

    SELECT COUNT(*)
    INTO v_after
    FROM incident;

    check_result(
        v_before = v_after,
        'Rejected duplicate leaves incident count unchanged'
    );

    ROLLBACK TO event_incident_test;
    restore_context;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: ' || v_passed ||
        ' workflow checks passed; test records rolled back'
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO event_incident_test;
        restore_context;
        RAISE;
END;
/