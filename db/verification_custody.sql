SET SERVEROUTPUT ON

DECLARE
    v_tag VARCHAR2(32) := RAWTOHEX(SYS_GUID());
    v_admin NUMBER;
    v_receiver_user NUMBER;
    v_collector NUMBER;
    v_receiver NUMBER;
    v_incident NUMBER;
    v_cycle NUMBER;
    v_assignment NUMBER;
    v_evidence NUMBER;
    v_unused NUMBER;
    v_count NUMBER;
    v_custodian NUMBER;
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

    PROCEDURE expect_transfer_error(
        p_actor NUMBER,
        p_expected_custodian NUMBER,
        p_receiver NUMBER,
        p_error NUMBER,
        p_label VARCHAR2
    ) IS
    BEGIN
        set_actor(p_actor);

        sp_transfer_evidence(
            p_actor,
            v_evidence,
            p_expected_custodian,
            p_receiver,
            'CONTROLLED_HANDOVER',
            'Verification transfer',
            'Intact'
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

    SAVEPOINT custody_test;

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'custody-admin-' || v_tag || '@example.invalid',
        'test-only', 'Custody Test Admin', 'ADMIN'
    )
    RETURNING user_id INTO v_admin;

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'custody-receiver-' || v_tag || '@example.invalid',
        'test-only', 'Custody Test Receiver', 'ANALYST'
    )
    RETURNING user_id INTO v_receiver_user;

    set_actor(v_admin);

    INSERT INTO investigator (
        user_id, specialization
    ) VALUES (
        v_admin, 'Evidence intake'
    )
    RETURNING investigator_id INTO v_collector;

    INSERT INTO investigator (
        user_id, specialization
    ) VALUES (
        v_receiver_user, 'Forensic analysis'
    )
    RETURNING investigator_id INTO v_receiver;

    INSERT INTO incident (
        title, description, severity, created_by
    ) VALUES (
        'Custody verification',
        'Temporary evidence workflow fixture',
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

    sp_assign_investigator(
        v_admin, v_incident, v_collector,
        'LEAD', v_assignment
    );

    sp_assign_investigator(
        v_admin, v_incident, v_receiver,
        'SUPPORT', v_assignment
    );

    sp_register_evidence(
        v_admin,
        v_incident,
        'LOG',
        'test-' || v_tag || '.log',
        'simulated.log',
        SYSTIMESTAMP - INTERVAL '1' MINUTE,
        RPAD('a', 64, 'a'),
        100,
        'INTERNAL',
        v_evidence
    );

    SELECT COUNT(*)
    INTO v_count
    FROM evidence e
    JOIN chain_of_custody c
      ON c.evidence_id = e.evidence_id
    WHERE e.evidence_id = v_evidence
      AND e.collected_by = v_collector
      AND e.current_custodian_id = v_collector
      AND c.from_investigator_id IS NULL
      AND c.to_investigator_id = v_collector
      AND c.method = 'INTAKE'
      AND c.performed_by = v_admin;

    check_result(
        v_count = 1,
        'Registration creates evidence and initial custody'
    );

    BEGIN
        sp_register_evidence(
            v_admin,
            v_incident,
            'LOG',
            'invalid-' || v_tag || '.log',
            'invalid.log',
            SYSTIMESTAMP - INTERVAL '1' MINUTE,
            'not-a-valid-sha256',
            100,
            'INTERNAL',
            v_unused
        );

        RAISE_APPLICATION_ERROR(
            -20999, 'Invalid hash was accepted'
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = -20010 THEN
                check_result(
                    TRUE, 'Invalid evidence hash is rejected'
                );
            ELSE
                RAISE;
            END IF;
    END;

    expect_transfer_error(
        v_receiver_user,
        v_collector,
        v_receiver,
        -20007,
        'Assigned non-custodian cannot transfer evidence'
    );

    expect_transfer_error(
        v_admin,
        v_collector,
        -1,
        -20002,
        'Missing receiving investigator is rejected'
    );

    SELECT current_custodian_id
    INTO v_custodian
    FROM evidence
    WHERE evidence_id = v_evidence;

    SELECT COUNT(*)
    INTO v_count
    FROM chain_of_custody
    WHERE evidence_id = v_evidence;

    check_result(
        v_custodian = v_collector AND v_count = 1,
        'Failed transfers leave custodian and history unchanged'
    );

    set_actor(v_admin);

    sp_transfer_evidence(
        v_admin,
        v_evidence,
        v_collector,
        v_receiver,
        'CONTROLLED_HANDOVER',
        'Transfer for forensic analysis',
        'Intact'
    );

    SELECT COUNT(*)
    INTO v_count
    FROM evidence e
    JOIN chain_of_custody c
      ON c.evidence_id = e.evidence_id
    WHERE e.evidence_id = v_evidence
      AND e.current_custodian_id = v_receiver
      AND c.from_investigator_id = v_collector
      AND c.to_investigator_id = v_receiver
      AND c.performed_by = v_admin;

    check_result(
        v_count = 1,
        'Valid transfer records handover and updates custodian'
    );

    expect_transfer_error(
        v_admin,
        v_collector,
        v_receiver,
        -20003,
        'Stale expected custodian is rejected'
    );

    SELECT current_custodian_id
    INTO v_custodian
    FROM evidence
    WHERE evidence_id = v_evidence;

    SELECT COUNT(*)
    INTO v_count
    FROM chain_of_custody
    WHERE evidence_id = v_evidence;

    check_result(
        v_custodian = v_receiver AND v_count = 2,
        'Rejected stale transfer preserves the completed handover'
    );

    ROLLBACK TO custody_test;
    restore_context;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: ' || v_passed ||
        ' custody checks passed; test records rolled back'
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO custody_test;
        restore_context;
        RAISE;
END;
/