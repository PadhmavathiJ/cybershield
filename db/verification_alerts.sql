SET SERVEROUTPUT ON

DECLARE
    v_tag VARCHAR2(32) := RAWTOHEX(SYS_GUID());
    v_admin NUMBER;
    v_outsider NUMBER;
    v_server NUMBER;
    v_ip NUMBER;
    v_attack NUMBER;
    v_incident NUMBER;
    v_other_incident NUMBER;
    v_cycle NUMBER;
    v_alert NUMBER;
    v_other_alert NUMBER;
    v_dismissed_alert NUMBER;
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

    FUNCTION make_alert(p_suffix VARCHAR2)
        RETURN NUMBER
    IS
        v_event NUMBER;
        v_new_alert NUMBER;
    BEGIN
        INSERT INTO security_event (
            source_event_key,
            server_id,
            source_ip_id,
            attack_type_id,
            protocol,
            severity_score
        ) VALUES (
            v_tag || '-' || p_suffix,
            v_server,
            v_ip,
            v_attack,
            'HTTPS',
            95
        )
        RETURNING event_id INTO v_event;

        INSERT INTO alert (
            event_id, severity
        ) VALUES (
            v_event, 'CRITICAL'
        )
        RETURNING alert_id INTO v_new_alert;

        RETURN v_new_alert;
    END;

    PROCEDURE expect_link_error(
        p_incident NUMBER,
        p_alert NUMBER,
        p_expected NUMBER,
        p_label VARCHAR2
    ) IS
    BEGIN
        sp_link_alert(v_admin, p_incident, p_alert);

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

    PROCEDURE expect_triage_error(
        p_actor NUMBER,
        p_alert NUMBER,
        p_status VARCHAR2,
        p_expected NUMBER,
        p_label VARCHAR2
    ) IS
    BEGIN
        set_actor(p_actor);

        sp_triage_alert(
            p_actor, p_alert, p_status, 'Negative test'
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

    SAVEPOINT alerts_test;

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'alert-admin-' || v_tag || '@example.invalid',
        'test-only', 'Alert Test Admin', 'ADMIN'
    )
    RETURNING user_id INTO v_admin;

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'alert-outsider-' || v_tag || '@example.invalid',
        'test-only', 'Unassigned Analyst', 'ANALYST'
    )
    RETURNING user_id INTO v_outsider;

    set_actor(v_admin);

    INSERT INTO server (
        hostname, os_name, department, criticality
    ) VALUES (
        'ALERT-' || v_tag, 'Test OS', 'Testing', 'HIGH'
    )
    RETURNING server_id INTO v_server;

    BEGIN
        SELECT ip_id INTO v_ip
        FROM ip_address
        WHERE ip_text = '192.0.2.201';
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            INSERT INTO ip_address (
                ip_text, is_simulated
            ) VALUES (
                '192.0.2.201', 1
            )
            RETURNING ip_id INTO v_ip;
    END;

    INSERT INTO attack_type (
        name, description
    ) VALUES (
        'ALERT-' || v_tag, 'Simulated alert test'
    )
    RETURNING attack_type_id INTO v_attack;

    INSERT INTO incident (
        title, description, severity, created_by
    ) VALUES (
        'Alert test incident',
        'Temporary fixture',
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

    INSERT INTO incident (
        title, description, severity, created_by
    ) VALUES (
        'Other alert test incident',
        'Temporary fixture',
        'HIGH',
        v_admin
    )
    RETURNING incident_id INTO v_other_incident;

    INSERT INTO investigation_cycle (
        incident_id, cycle_no
    ) VALUES (
        v_other_incident, 1
    );

    v_alert := make_alert('LINK');
    v_other_alert := make_alert('SECOND');
    v_dismissed_alert := make_alert('DISMISS');

    sp_link_alert(v_admin, v_incident, v_alert);
    sp_link_alert(v_admin, v_incident, v_other_alert);

    SELECT COUNT(*)
    INTO v_count
    FROM incident_alert
    WHERE incident_id = v_incident;

    check_result(
        v_count = 2,
        'One incident can aggregate multiple alerts'
    );

    sp_link_alert(v_admin, v_incident, v_alert);

    SELECT COUNT(*)
    INTO v_count
    FROM incident_alert
    WHERE incident_id = v_incident;

    check_result(
        v_count = 2,
        'Repeated link does not duplicate records'
    );

    expect_link_error(
        v_other_incident,
        v_alert,
        -20009,
        'Alert cannot belong to another incident'
    );

    sp_triage_alert(
        v_admin, v_alert, 'ACKNOWLEDGED',
        'Alert reviewed'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM alert a
    JOIN sla s ON s.cycle_id = v_cycle
    WHERE a.alert_id = v_alert
      AND a.status = 'ACKNOWLEDGED'
      AND a.triaged_by = v_admin
      AND a.acknowledged_at IS NOT NULL
      AND s.acknowledged_at IS NOT NULL;

    check_result(
        v_count = 1,
        'Acknowledgement records actor and acknowledges SLA'
    );

    sp_triage_alert(
        v_admin, v_alert, 'ESCALATED',
        'Escalated for investigation'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM alert
    WHERE alert_id = v_alert
      AND status = 'ESCALATED';

    check_result(
        v_count = 1,
        'Acknowledged alert can be escalated'
    );

    expect_triage_error(
        v_admin,
        v_other_alert,
        'DISMISSED',
        -20004,
        'Incident-linked alert cannot be dismissed'
    );

    expect_triage_error(
        v_outsider,
        v_other_alert,
        'ACKNOWLEDGED',
        -20007,
        'Unassigned analyst cannot triage linked alert'
    );

    set_actor(v_admin);

    sp_triage_alert(
        v_admin, v_dismissed_alert, 'DISMISSED',
        'Simulated false positive'
    );

    expect_link_error(
        v_incident,
        v_dismissed_alert,
        -20004,
        'Dismissed alert cannot be linked'
    );

    expect_triage_error(
        v_admin,
        v_dismissed_alert,
        'ACKNOWLEDGED',
        -20004,
        'Dismissed alert cannot return to acknowledged'
    );

    ROLLBACK TO alerts_test;
    restore_context;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: ' || v_passed ||
        ' alert checks passed; test records rolled back'
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO alerts_test;
        restore_context;
        RAISE;
END;
/