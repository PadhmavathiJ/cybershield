SET SERVEROUTPUT ON

DECLARE
    v_tag VARCHAR2(32) := RAWTOHEX(SYS_GUID());
    v_admin NUMBER;
    v_spare_user NUMBER;
    v_lead NUMBER;
    v_spare NUMBER;
    v_server NUMBER;
    v_ip NUMBER;
    v_attack NUMBER;
    v_event NUMBER;
    v_alert NUMBER;
    v_incident NUMBER;
    v_cycle NUMBER;
    v_assignment NUMBER;
    v_evidence NUMBER;
    v_count NUMBER;
    v_passed NUMBER := 0;
    v_previous_client VARCHAR2(64);
    v_baseline vw_dashboard_summary%ROWTYPE;
    v_current vw_dashboard_summary%ROWTYPE;

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

    SELECT *
    INTO v_baseline
    FROM vw_dashboard_summary;

    SAVEPOINT views_test;

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'views-admin-' || v_tag || '@example.invalid',
        'test-only', 'View Test Lead', 'ADMIN'
    )
    RETURNING user_id INTO v_admin;

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'views-spare-' || v_tag || '@example.invalid',
        'test-only', 'View Test Spare', 'ANALYST'
    )
    RETURNING user_id INTO v_spare_user;

    DBMS_SESSION.SET_IDENTIFIER(
        TO_CHAR(v_admin, 'FM9999999990')
    );

    INSERT INTO investigator (
        user_id, specialization
    ) VALUES (
        v_admin, 'Reporting verification'
    )
    RETURNING investigator_id INTO v_lead;

    INSERT INTO investigator (
        user_id, specialization
    ) VALUES (
        v_spare_user, 'Reporting verification'
    )
    RETURNING investigator_id INTO v_spare;

    INSERT INTO server (
        hostname, os_name, department, criticality
    ) VALUES (
        'VIEW-' || v_tag, 'Test OS', 'Testing', 'HIGH'
    )
    RETURNING server_id INTO v_server;

    BEGIN
        SELECT ip_id
        INTO v_ip
        FROM ip_address
        WHERE ip_text = '192.0.2.202';
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            INSERT INTO ip_address (
                ip_text, is_simulated
            ) VALUES (
                '192.0.2.202', 1
            )
            RETURNING ip_id INTO v_ip;
    END;

    INSERT INTO attack_type (
        name, description
    ) VALUES (
        'VIEW-' || v_tag, 'Simulated reporting fixture'
    )
    RETURNING attack_type_id INTO v_attack;

    INSERT INTO security_event (
        source_event_key,
        server_id,
        source_ip_id,
        attack_type_id,
        protocol,
        severity_score
    ) VALUES (
        'VIEW-' || v_tag,
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
    RETURNING alert_id INTO v_alert;

    INSERT INTO incident (
        title, description, severity, created_by, opened_at
    ) VALUES (
        'View test incident',
        'Temporary reporting fixture',
        'CRITICAL',
        v_admin,
        SYSTIMESTAMP - INTERVAL '2' HOUR
    )
    RETURNING incident_id INTO v_incident;

    INSERT INTO investigation_cycle (
        incident_id, cycle_no, started_at
    ) VALUES (
        v_incident,
        1,
        SYSTIMESTAMP - INTERVAL '2' HOUR
    )
    RETURNING cycle_id INTO v_cycle;

    INSERT INTO sla (
        cycle_id, response_due_at, resolution_due_at
    ) VALUES (
        v_cycle,
        SYSTIMESTAMP - INTERVAL '1' HOUR,
        SYSTIMESTAMP + INTERVAL '1' DAY
    );

    sp_assign_investigator(
        v_admin, v_incident, v_lead,
        'LEAD', v_assignment
    );

    sp_link_alert(
        v_admin, v_incident, v_alert
    );

    sp_register_evidence(
        v_admin,
        v_incident,
        'LOG',
        'views-' || v_tag || '.log',
        'simulated.log',
        SYSTIMESTAMP - INTERVAL '1' MINUTE,
        RPAD('a', 64, 'a'),
        100,
        'INTERNAL',
        v_evidence
    );

    SELECT COUNT(*)
    INTO v_count
    FROM vw_open_incidents
    WHERE incident_id = v_incident
      AND cycle_id = v_cycle
      AND cycle_no = 1
      AND lead_name = 'View Test Lead'
      AND status = 'OPEN';

    check_result(
        v_count = 1,
        'Open incident view returns its cycle and lead'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM vw_critical_alerts
    WHERE alert_id = v_alert
      AND event_id = v_event
      AND incident_id = v_incident
      AND hostname = 'VIEW-' || v_tag;

    check_result(
        v_count = 1,
        'Critical alert view links event server and incident'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM vw_investigator_workload
    WHERE investigator_id = v_lead
      AND active_cases = 1
      AND lead_cases = 1;

    check_result(
        v_count = 1,
        'Lead workload counts one active case'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM vw_investigator_workload
    WHERE investigator_id = v_spare
      AND active_cases = 0
      AND lead_cases = 0;

    check_result(
        v_count = 1,
        'Unassigned investigator remains visible with zero workload'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM vw_sla_status
    WHERE cycle_id = v_cycle
      AND response_breached = 1
      AND resolution_breached = 0;

    check_result(
        v_count = 1,
        'SLA view distinguishes response and resolution breaches'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM vw_custody_history
    WHERE evidence_id = v_evidence
      AND from_name IS NULL
      AND to_name = 'View Test Lead'
      AND method = 'INTAKE';

    check_result(
        v_count = 1,
        'Custody view correctly displays initial intake'
    );

    SELECT *
    INTO v_current
    FROM vw_dashboard_summary;

    check_result(
        v_current.active_servers =
            v_baseline.active_servers + 1
        AND v_current.total_events =
            v_baseline.total_events + 1
        AND v_current.critical_alerts =
            v_baseline.critical_alerts + 1
        AND v_current.open_incidents =
            v_baseline.open_incidents + 1
        AND v_current.active_investigators =
            v_baseline.active_investigators + 2
        AND v_current.sla_breaches =
            v_baseline.sla_breaches + 1,
        'Dashboard counts match the reporting fixture'
    );

    ROLLBACK TO views_test;
    restore_context;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: ' || v_passed ||
        ' view checks passed; test records rolled back'
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO views_test;
        restore_context;
        RAISE;
END;
/