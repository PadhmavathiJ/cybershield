CREATE OR REPLACE PROCEDURE sp_ingest_event (
    p_actor_id IN NUMBER,
    p_source_event_key IN VARCHAR2,
    p_server_id IN NUMBER,
    p_source_ip_id IN NUMBER,
    p_attack_type_id IN NUMBER,
    p_event_at IN TIMESTAMP WITH TIME ZONE,
    p_protocol IN VARCHAR2,
    p_packet_count IN NUMBER,
    p_bytes_in IN NUMBER,
    p_bytes_out IN NUMBER,
    p_severity_score IN NUMBER,
    p_details IN CLOB,
    p_event_id OUT NUMBER,
    p_alert_id OUT NUMBER
) AUTHID DEFINER
IS
    v_threshold NUMBER;
    v_count NUMBER;
    v_severity alert.severity%TYPE;

    PROCEDURE load_existing IS
        v_event security_event%ROWTYPE;
        v_same_details BOOLEAN := FALSE;
    BEGIN
        SELECT *
        INTO v_event
        FROM security_event
        WHERE source_event_key = p_source_event_key;

        IF v_event.details IS NULL AND p_details IS NULL THEN
            v_same_details := TRUE;
        ELSIF v_event.details IS NOT NULL
              AND p_details IS NOT NULL
        THEN
            v_same_details :=
                DBMS_LOB.COMPARE(v_event.details, p_details) = 0;
        END IF;

        IF v_event.server_id <> p_server_id
           OR v_event.source_ip_id <> p_source_ip_id
           OR v_event.attack_type_id <> p_attack_type_id
           OR v_event.event_at <> p_event_at
           OR v_event.protocol <> p_protocol
           OR v_event.packet_count <> p_packet_count
           OR v_event.bytes_in <> p_bytes_in
           OR v_event.bytes_out <> p_bytes_out
           OR v_event.severity_score <> p_severity_score
           OR v_event.is_simulated <> 1
           OR NOT v_same_details
        THEN
            RAISE_APPLICATION_ERROR(
                -20009,
                'Source event key belongs to different event data'
            );
        END IF;

        p_event_id := v_event.event_id;

        SELECT MAX(alert_id)
        INTO p_alert_id
        FROM alert
        WHERE event_id = p_event_id;
    END load_existing;

BEGIN
    SAVEPOINT cs_ingest_start;

    p_event_id := NULL;
    p_alert_id := NULL;

    cs_security.require_operator(p_actor_id);

    IF TRIM(p_source_event_key) IS NULL
       OR LENGTH(p_source_event_key) > 100
       OR p_source_event_key <> TRIM(p_source_event_key)
       OR p_server_id IS NULL
       OR p_source_ip_id IS NULL
       OR p_attack_type_id IS NULL
       OR p_event_at IS NULL
       OR TRIM(p_protocol) IS NULL
       OR LENGTH(p_protocol) > 16
       OR p_packet_count IS NULL
       OR p_bytes_in IS NULL
       OR p_bytes_out IS NULL
       OR p_severity_score IS NULL
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Missing or invalid event fields'
        );
    END IF;

    IF p_packet_count < 0
       OR p_bytes_in < 0
       OR p_bytes_out < 0
       OR p_packet_count <> TRUNC(p_packet_count)
       OR p_bytes_in <> TRUNC(p_bytes_in)
       OR p_bytes_out <> TRUNC(p_bytes_out)
       OR p_packet_count >= 1E18
       OR p_bytes_in >= 1E18
       OR p_bytes_out >= 1E18
       OR p_severity_score NOT BETWEEN 0 AND 100
       OR p_severity_score <> ROUND(p_severity_score, 2)
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Invalid traffic counts or severity score'
        );
    END IF;

    BEGIN
        load_existing;
        RETURN;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            NULL;
    END;

    SELECT COUNT(*)
    INTO v_count
    FROM server
    WHERE server_id = p_server_id
      AND is_active = 1;

    IF v_count = 0 THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Select an active server'
        );
    END IF;

    SELECT COUNT(*)
    INTO v_count
    FROM ip_address
    WHERE ip_id = p_source_ip_id;

    IF v_count = 0 THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Source IP does not exist'
        );
    END IF;

    SELECT COUNT(*)
    INTO v_count
    FROM attack_type
    WHERE attack_type_id = p_attack_type_id;

    IF v_count = 0 THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Attack type does not exist'
        );
    END IF;

    BEGIN
        SELECT number_value
        INTO v_threshold
        FROM soc_policy
        WHERE policy_key = 'alert_threshold';
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20010, 'Alert threshold policy is not configured'
            );
    END;

    BEGIN
        INSERT INTO security_event (
            source_event_key,
            server_id,
            source_ip_id,
            attack_type_id,
            event_at,
            protocol,
            packet_count,
            bytes_in,
            bytes_out,
            severity_score,
            details,
            is_simulated
        ) VALUES (
            p_source_event_key,
            p_server_id,
            p_source_ip_id,
            p_attack_type_id,
            p_event_at,
            p_protocol,
            p_packet_count,
            p_bytes_in,
            p_bytes_out,
            p_severity_score,
            p_details,
            1
        )
        RETURNING event_id INTO p_event_id;
    EXCEPTION
        WHEN DUP_VAL_ON_INDEX THEN
            load_existing;
            RETURN;
    END;

    IF p_severity_score >= v_threshold THEN
        v_severity :=
            CASE
                WHEN p_severity_score < 40 THEN 'LOW'
                WHEN p_severity_score < 70 THEN 'MEDIUM'
                WHEN p_severity_score < 90 THEN 'HIGH'
                ELSE 'CRITICAL'
            END;

        INSERT INTO alert (
            event_id, severity, status
        ) VALUES (
            p_event_id, v_severity, 'NEW'
        )
        RETURNING alert_id INTO p_alert_id;
    END IF;

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO cs_ingest_start;
        p_event_id := NULL;
        p_alert_id := NULL;
        RAISE;
END sp_ingest_event;
/


CREATE OR REPLACE PROCEDURE sp_create_incident (
    p_actor_id IN NUMBER,
    p_alert_id IN NUMBER,
    p_title IN VARCHAR2,
    p_description IN CLOB,
    p_severity IN VARCHAR2,
    p_campaign_id IN NUMBER,
    p_incident_id OUT NUMBER
) AUTHID DEFINER
IS
    v_alert_id NUMBER;
    v_alert_status alert.status%TYPE;
    v_acknowledged_at TIMESTAMP WITH TIME ZONE;
    v_cycle_id NUMBER;
    v_count NUMBER;
    v_response_hours NUMBER;
    v_resolution_hours NUMBER;
    v_now TIMESTAMP WITH TIME ZONE := SYSTIMESTAMP;
BEGIN
    SAVEPOINT cs_create_incident_start;

    p_incident_id := NULL;

    cs_security.require_operator(p_actor_id);

    IF p_alert_id IS NULL
       OR TRIM(p_title) IS NULL
       OR LENGTH(p_title) > 200
       OR p_description IS NULL
       OR p_severity IS NULL
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Required incident fields are missing or invalid'
        );
    END IF;

    IF DBMS_LOB.GETLENGTH(p_description) = 0
       OR p_severity NOT IN ('LOW','MEDIUM','HIGH','CRITICAL')
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Invalid incident description or severity'
        );
    END IF;

    BEGIN
        SELECT alert_id, status, acknowledged_at
        INTO v_alert_id, v_alert_status, v_acknowledged_at
        FROM alert
        WHERE alert_id = p_alert_id
        FOR UPDATE WAIT 5;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20001, 'Alert not found'
            );
    END;

    IF v_alert_status = 'DISMISSED' THEN
        RAISE_APPLICATION_ERROR(
            -20004, 'Cannot create an incident from a dismissed alert'
        );
    END IF;

    SELECT COUNT(*)
    INTO v_count
    FROM incident_alert
    WHERE alert_id = p_alert_id;

    IF v_count > 0 THEN
        RAISE_APPLICATION_ERROR(
            -20009, 'Alert already belongs to an incident'
        );
    END IF;

    IF p_campaign_id IS NOT NULL THEN
        SELECT COUNT(*)
        INTO v_count
        FROM attack_campaign
        WHERE campaign_id = p_campaign_id;

        IF v_count = 0 THEN
            RAISE_APPLICATION_ERROR(
                -20010, 'Campaign does not exist'
            );
        END IF;
    END IF;

    BEGIN
        SELECT number_value
        INTO v_response_hours
        FROM soc_policy
        WHERE policy_key = 'response_hours';

        SELECT number_value
        INTO v_resolution_hours
        FROM soc_policy
        WHERE policy_key = 'resolution_hours';
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20010, 'SLA policies are not configured'
            );
    END;

    IF v_response_hours <= 0
       OR v_resolution_hours < v_response_hours
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Invalid SLA policy values'
        );
    END IF;

    INSERT INTO incident (
        title,
        description,
        severity,
        status,
        campaign_id,
        created_by,
        opened_at
    ) VALUES (
        p_title,
        p_description,
        p_severity,
        'OPEN',
        p_campaign_id,
        p_actor_id,
        v_now
    )
    RETURNING incident_id INTO p_incident_id;

    INSERT INTO investigation_cycle (
        incident_id, cycle_no, started_at
    ) VALUES (
        p_incident_id, 1, v_now
    )
    RETURNING cycle_id INTO v_cycle_id;

    INSERT INTO incident_alert (
        incident_id, alert_id, linked_at
    ) VALUES (
        p_incident_id, p_alert_id, v_now
    );

    INSERT INTO sla (
        cycle_id,
        response_due_at,
        resolution_due_at,
        acknowledged_at
    ) VALUES (
        v_cycle_id,
        v_now + NUMTODSINTERVAL(v_response_hours, 'HOUR'),
        v_now + NUMTODSINTERVAL(v_resolution_hours, 'HOUR'),
        CASE
            WHEN v_acknowledged_at IS NOT NULL THEN v_now
            ELSE NULL
        END
    );

    INSERT INTO incident_status_history (
        cycle_id,
        from_status,
        to_status,
        changed_by,
        changed_at,
        reason
    ) VALUES (
        v_cycle_id,
        NULL,
        'OPEN',
        p_actor_id,
        v_now,
        'Incident created from alert'
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO cs_create_incident_start;
        p_incident_id := NULL;
        RAISE;
END sp_create_incident;
/
CREATE OR REPLACE PROCEDURE sp_assign_investigator (
    p_actor_id IN NUMBER,
    p_incident_id IN NUMBER,
    p_investigator_id IN NUMBER,
    p_assignment_role IN VARCHAR2,
    p_assignment_id OUT NUMBER
) AUTHID DEFINER
IS
    v_status incident.status%TYPE;
    v_cycle_id NUMBER;
    v_count NUMBER;
    v_available investigator.availability%TYPE;
    v_active app_user.is_active%TYPE;
    v_role app_user.role_code%TYPE;
BEGIN
    SAVEPOINT cs_assign_start;

    p_assignment_id := NULL;

    cs_security.require_manager(p_actor_id);

    IF p_assignment_role IS NULL
       OR p_assignment_role NOT IN ('LEAD', 'SUPPORT')
       OR p_investigator_id IS NULL
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Select an investigator and valid assignment role'
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

    IF v_status IN ('RESOLVED', 'CLOSED') THEN
        RAISE_APPLICATION_ERROR(
            -20004, 'Reopen the incident before assigning investigators'
        );
    END IF;

    cs_security.get_active_cycle(
        p_incident_id, v_cycle_id
    );

    BEGIN
        SELECT i.availability, u.is_active, u.role_code
        INTO v_available, v_active, v_role
        FROM investigator i
        JOIN app_user u ON u.user_id = i.user_id
        WHERE i.investigator_id = p_investigator_id
        FOR UPDATE OF i.availability, u.is_active WAIT 5;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20001, 'Investigator not found'
            );
    END;

    IF v_available = 'INACTIVE'
       OR v_active <> 1
       OR v_role NOT IN ('ADMIN', 'ANALYST')
    THEN
        RAISE_APPLICATION_ERROR(
            -20002, 'Investigator is not eligible for assignment'
        );
    END IF;

    SELECT COUNT(*)
    INTO v_count
    FROM incident_assignment
    WHERE cycle_id = v_cycle_id
      AND investigator_id = p_investigator_id
      AND ended_at IS NULL;

    IF v_count > 0 THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Investigator already has an active assignment'
        );
    END IF;

    IF p_assignment_role = 'LEAD' THEN
        SELECT COUNT(*)
        INTO v_count
        FROM incident_assignment
        WHERE cycle_id = v_cycle_id
          AND assignment_role = 'LEAD'
          AND ended_at IS NULL;

        IF v_count > 0 THEN
            RAISE_APPLICATION_ERROR(
                -20011, 'An active lead already exists'
            );
        END IF;
    END IF;

    INSERT INTO incident_assignment (
        cycle_id,
        investigator_id,
        assigned_by,
        assignment_role
    ) VALUES (
        v_cycle_id,
        p_investigator_id,
        p_actor_id,
        p_assignment_role
    )
    RETURNING assignment_id INTO p_assignment_id;

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO cs_assign_start;
        p_assignment_id := NULL;
        RAISE;
END sp_assign_investigator;
/


CREATE OR REPLACE PROCEDURE sp_change_status (
    p_actor_id IN NUMBER,
    p_incident_id IN NUMBER,
    p_to_status IN VARCHAR2,
    p_reason IN VARCHAR2
) AUTHID DEFINER
IS
    v_from_status incident.status%TYPE;
    v_cycle_id NUMBER;
    v_resolution_count NUMBER;
    v_now TIMESTAMP WITH TIME ZONE := SYSTIMESTAMP;
    v_allowed BOOLEAN := FALSE;
BEGIN
    SAVEPOINT cs_status_start;

    cs_security.require_operator(p_actor_id);

    IF p_to_status IS NULL
       OR TRIM(p_reason) IS NULL
       OR LENGTH(p_reason) > 1000
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'A target status and reason are required'
        );
    END IF;

    BEGIN
        SELECT status
        INTO v_from_status
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

    cs_security.get_active_cycle(
        p_incident_id, v_cycle_id
    );

    v_allowed :=
        (v_from_status = 'OPEN' AND p_to_status = 'TRIAGED')
        OR
        (v_from_status = 'TRIAGED'
         AND p_to_status = 'INVESTIGATING')
        OR
        (v_from_status = 'INVESTIGATING'
         AND p_to_status = 'CONTAINED')
        OR
        (v_from_status = 'RESOLVED'
         AND p_to_status = 'CLOSED');

    IF NOT v_allowed THEN
        RAISE_APPLICATION_ERROR(
            -20004,
            'Invalid transition; resolution and reopening use dedicated procedures'
        );
    END IF;

    IF p_to_status = 'CLOSED' THEN
        SELECT COUNT(*)
        INTO v_resolution_count
        FROM resolution
        WHERE cycle_id = v_cycle_id;

        IF v_resolution_count <> 1 THEN
            RAISE_APPLICATION_ERROR(
                -20006, 'A resolution is required before closure'
            );
        END IF;
    END IF;

    UPDATE incident
    SET status = p_to_status,
        closed_at =
            CASE
                WHEN p_to_status = 'CLOSED' THEN v_now
                ELSE NULL
            END
    WHERE incident_id = p_incident_id;

    INSERT INTO incident_status_history (
        cycle_id,
        from_status,
        to_status,
        changed_by,
        changed_at,
        reason
    ) VALUES (
        v_cycle_id,
        v_from_status,
        p_to_status,
        p_actor_id,
        v_now,
        p_reason
    );

    IF p_to_status = 'TRIAGED' THEN
        UPDATE sla
        SET acknowledged_at = COALESCE(acknowledged_at, v_now)
        WHERE cycle_id = v_cycle_id;

        IF SQL%ROWCOUNT <> 1 THEN
            RAISE_APPLICATION_ERROR(
                -20010, 'Investigation cycle is missing its SLA'
            );
        END IF;
    END IF;

    IF p_to_status = 'CLOSED' THEN
        UPDATE incident_assignment
        SET ended_at = v_now
        WHERE cycle_id = v_cycle_id
          AND ended_at IS NULL;

        UPDATE investigation_cycle
        SET ended_at = v_now
        WHERE cycle_id = v_cycle_id
          AND ended_at IS NULL;
    END IF;

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO cs_status_start;
        RAISE;
END sp_change_status;
/
CREATE OR REPLACE PROCEDURE sp_link_alert (
    p_actor_id IN NUMBER,
    p_incident_id IN NUMBER,
    p_alert_id IN NUMBER
) AUTHID DEFINER
IS
    v_incident_status incident.status%TYPE;
    v_alert_status alert.status%TYPE;
    v_existing_incident NUMBER;
BEGIN
    SAVEPOINT cs_link_alert_start;

    cs_security.require_operator(p_actor_id);

    BEGIN
        SELECT status
        INTO v_incident_status
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

    IF v_incident_status IN ('RESOLVED', 'CLOSED') THEN
        RAISE_APPLICATION_ERROR(
            -20004, 'Reopen the incident before linking alerts'
        );
    END IF;

    BEGIN
        SELECT status
        INTO v_alert_status
        FROM alert
        WHERE alert_id = p_alert_id
        FOR UPDATE WAIT 5;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20001, 'Alert not found'
            );
    END;

    SELECT MAX(incident_id)
    INTO v_existing_incident
    FROM incident_alert
    WHERE alert_id = p_alert_id;

    IF v_existing_incident = p_incident_id THEN
        RETURN;
    ELSIF v_existing_incident IS NOT NULL THEN
        RAISE_APPLICATION_ERROR(
            -20009, 'Alert already belongs to another incident'
        );
    END IF;

    IF v_alert_status = 'DISMISSED' THEN
        RAISE_APPLICATION_ERROR(
            -20004, 'Cannot link a dismissed alert'
        );
    END IF;

    INSERT INTO incident_alert (
        incident_id, alert_id
    ) VALUES (
        p_incident_id, p_alert_id
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO cs_link_alert_start;
        RAISE;
END sp_link_alert;
/


CREATE OR REPLACE PROCEDURE sp_triage_alert (
    p_actor_id IN NUMBER,
    p_alert_id IN NUMBER,
    p_status IN VARCHAR2,
    p_note IN VARCHAR2
) AUTHID DEFINER
IS
    v_incident_id NUMBER;
    v_current_incident NUMBER;
    v_incident_status incident.status%TYPE;
    v_old_status alert.status%TYPE;
    v_now TIMESTAMP WITH TIME ZONE := SYSTIMESTAMP;
    v_allowed BOOLEAN := FALSE;
BEGIN
    SAVEPOINT cs_triage_alert_start;

    cs_security.require_operator(p_actor_id);

    IF p_status IS NULL
       OR p_status NOT IN (
           'ACKNOWLEDGED', 'ESCALATED', 'DISMISSED'
       )
       OR TRIM(p_note) IS NULL
       OR LENGTH(p_note) > 1000
    THEN
        RAISE_APPLICATION_ERROR(
            -20010, 'Select a valid alert status and provide a note'
        );
    END IF;

    SELECT MAX(incident_id)
    INTO v_incident_id
    FROM incident_alert
    WHERE alert_id = p_alert_id;

    IF v_incident_id IS NOT NULL THEN
        SELECT status
        INTO v_incident_status
        FROM incident
        WHERE incident_id = v_incident_id
        FOR UPDATE WAIT 5;

        cs_security.require_incident_access(
            p_actor_id, v_incident_id, 1
        );

        IF v_incident_status IN ('RESOLVED', 'CLOSED') THEN
            RAISE_APPLICATION_ERROR(
                -20004, 'Cannot triage alerts of a resolved or closed incident'
            );
        END IF;
    END IF;

    BEGIN
        SELECT status
        INTO v_old_status
        FROM alert
        WHERE alert_id = p_alert_id
        FOR UPDATE WAIT 5;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20001, 'Alert not found'
            );
    END;

    SELECT MAX(incident_id)
    INTO v_current_incident
    FROM incident_alert
    WHERE alert_id = p_alert_id;

    IF (v_incident_id IS NULL AND v_current_incident IS NOT NULL)
       OR (v_incident_id IS NOT NULL AND v_current_incident IS NULL)
       OR (
           v_incident_id IS NOT NULL
           AND v_current_incident IS NOT NULL
           AND v_incident_id <> v_current_incident
       )
    THEN
        RAISE_APPLICATION_ERROR(
            -20004, 'Alert linkage changed; refresh and retry'
        );
    END IF;

    IF v_current_incident IS NOT NULL
       AND p_status = 'DISMISSED'
    THEN
        RAISE_APPLICATION_ERROR(
            -20004, 'An incident-linked alert cannot be dismissed'
        );
    END IF;

    v_allowed :=
        (
            v_old_status = 'NEW'
            AND p_status IN (
                'ACKNOWLEDGED', 'ESCALATED', 'DISMISSED'
            )
        )
        OR
        (
            v_old_status = 'ACKNOWLEDGED'
            AND p_status IN ('ESCALATED', 'DISMISSED')
        );

    IF NOT v_allowed THEN
        RAISE_APPLICATION_ERROR(
            -20004, 'Alert status transition is not allowed'
        );
    END IF;

    UPDATE alert
    SET status = p_status,
        triaged_by = p_actor_id,
        triage_note = p_note,
        acknowledged_at =
            CASE
                WHEN p_status IN ('ACKNOWLEDGED', 'ESCALATED')
                THEN COALESCE(acknowledged_at, v_now)
                ELSE acknowledged_at
            END
    WHERE alert_id = p_alert_id;

    IF v_current_incident IS NOT NULL
       AND p_status IN ('ACKNOWLEDGED', 'ESCALATED')
    THEN
        UPDATE sla
        SET acknowledged_at =
            COALESCE(acknowledged_at, v_now)
        WHERE cycle_id IN (
            SELECT cycle_id
            FROM investigation_cycle
            WHERE incident_id = v_current_incident
              AND ended_at IS NULL
        );

        IF SQL%ROWCOUNT <> 1 THEN
            RAISE_APPLICATION_ERROR(
                -20010, 'Incident is missing an active cycle or SLA'
            );
        END IF;
    END IF;

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO cs_triage_alert_start;
        RAISE;
END sp_triage_alert;
/