SET SERVEROUTPUT ON

DECLARE
    v_user_id NUMBER;
    v_incident_id NUMBER;
    v_cycle_id NUMBER;
    v_inv_id NUMBER;

    PROCEDURE expect_error(
        p_sql VARCHAR2,
        p_expected NUMBER,
        p_label VARCHAR2
    ) IS
    BEGIN
        EXECUTE IMMEDIATE p_sql;
        RAISE_APPLICATION_ERROR(
            -20999, 'FAIL: ' || p_label || ' was accepted'
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = p_expected THEN
                DBMS_OUTPUT.PUT_LINE('PASS: ' || p_label);
            ELSE
                RAISE;
            END IF;
    END;
BEGIN
    SAVEPOINT integrity_test;

    expect_error(
        'INSERT INTO app_user
         (email,password_hash,full_name,role_code)
         VALUES
         (''invalid-role@example.invalid'',''test-only'',
          ''Test User'',''ENGINEER'')',
        -2290,
        'Invalid role rejected'
    );

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'integrity-check@example.invalid',
        'test-only',
        'Integrity Test',
        'ANALYST'
    )
    RETURNING user_id INTO v_user_id;

    expect_error(
        'INSERT INTO app_user
         (email,password_hash,full_name,role_code)
         VALUES
         (''INTEGRITY-CHECK@example.invalid'',''test-only'',
          ''Duplicate User'',''ANALYST'')',
        -1,
        'Case-insensitive duplicate email rejected'
    );

    expect_error(
        'INSERT INTO investigator
         (user_id,specialization)
         VALUES (-1,''Test'')',
        -2291,
        'Missing parent user rejected'
    );

    INSERT INTO investigator (
        user_id, specialization
    ) VALUES (
        v_user_id, 'Test'
    )
    RETURNING investigator_id INTO v_inv_id;

    INSERT INTO incident (
        title, description, severity, created_by
    ) VALUES (
        'Integrity test', 'Temporary test', 'HIGH', v_user_id
    )
    RETURNING incident_id INTO v_incident_id;

    INSERT INTO investigation_cycle (
        incident_id, cycle_no
    ) VALUES (
        v_incident_id, 1
    )
    RETURNING cycle_id INTO v_cycle_id;

    expect_error(
        'INSERT INTO investigation_cycle
         (incident_id,cycle_no,reopen_reason)
         VALUES (' || TO_CHAR(v_incident_id) ||
         ',2,''Test reopen'')',
        -1,
        'Second active investigation cycle rejected'
    );

    INSERT INTO incident_assignment (
        cycle_id, investigator_id, assigned_by, assignment_role
    ) VALUES (
        v_cycle_id, v_inv_id, v_user_id, 'LEAD'
    );

    expect_error(
        'INSERT INTO incident_assignment
         (cycle_id,investigator_id,assigned_by,assignment_role)
         VALUES (' || TO_CHAR(v_cycle_id) || ',' ||
         TO_CHAR(v_inv_id) || ',' || TO_CHAR(v_user_id) ||
         ',''SUPPORT'')',
        -1,
        'Duplicate active membership rejected'
    );

    expect_error(
        'UPDATE incident SET status = ''CLOSED''
         WHERE incident_id = ' || TO_CHAR(v_incident_id),
        -2290,
        'Closed incident without timestamp rejected'
    );

    expect_error(
        'INSERT INTO ip_address (ip_text,is_simulated)
         VALUES (''192.0.2.250'',2)',
        -2290,
        'Invalid boolean flag rejected'
    );

    ROLLBACK TO integrity_test;
    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: all 7 checks passed; test records rolled back'
    );
EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO integrity_test;
        RAISE;
END;
/