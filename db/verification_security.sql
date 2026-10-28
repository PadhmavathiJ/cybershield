SET SERVEROUTPUT ON

DECLARE
    v_admin NUMBER;
    v_manager NUMBER;
    v_analyst NUMBER;
    v_auditor NUMBER;
    v_inactive NUMBER;
    v_role VARCHAR2(10);
    v_previous_client VARCHAR2(64);
    v_passed NUMBER := 0;

    PROCEDURE set_actor(p_id NUMBER) IS
    BEGIN
        DBMS_SESSION.SET_IDENTIFIER(
            TO_CHAR(p_id, 'FM9999999990')
        );
    END;

    PROCEDURE expect_denied(
        p_actor NUMBER,
        p_operation VARCHAR2,
        p_label VARCHAR2
    ) IS
    BEGIN
        IF p_operation = 'MANAGER' THEN
            cs_security.require_manager(p_actor);
        ELSE
            cs_security.require_operator(p_actor);
        END IF;

        RAISE_APPLICATION_ERROR(
            -20999, 'FAIL: ' || p_label
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = -20007 THEN
                v_passed := v_passed + 1;
                DBMS_OUTPUT.PUT_LINE('PASS: ' || p_label);
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

    SAVEPOINT security_test;

    INSERT INTO app_user
        (email, password_hash, full_name, role_code)
    VALUES
        ('security-admin@example.invalid',
         'test-only', 'Test Admin', 'ADMIN')
    RETURNING user_id INTO v_admin;

    INSERT INTO app_user
        (email, password_hash, full_name, role_code)
    VALUES
        ('security-manager@example.invalid',
         'test-only', 'Test Manager', 'MANAGER')
    RETURNING user_id INTO v_manager;

    INSERT INTO app_user
        (email, password_hash, full_name, role_code)
    VALUES
        ('security-analyst@example.invalid',
         'test-only', 'Test Analyst', 'ANALYST')
    RETURNING user_id INTO v_analyst;

    INSERT INTO app_user
        (email, password_hash, full_name, role_code)
    VALUES
        ('security-auditor@example.invalid',
         'test-only', 'Test Auditor', 'AUDITOR')
    RETURNING user_id INTO v_auditor;

    INSERT INTO app_user
        (email, password_hash, full_name, role_code, is_active)
    VALUES
        ('security-inactive@example.invalid',
         'test-only', 'Inactive Admin', 'ADMIN', 0)
    RETURNING user_id INTO v_inactive;

    set_actor(v_admin);
    cs_security.require_manager(v_admin);
    cs_security.require_operator(v_admin);
    v_passed := v_passed + 1;
    DBMS_OUTPUT.PUT_LINE('PASS: Admin has both permissions');

    set_actor(v_manager);
    cs_security.require_manager(v_manager);
    v_passed := v_passed + 1;
    DBMS_OUTPUT.PUT_LINE('PASS: Manager has management permission');

    expect_denied(
        v_manager, 'OPERATOR',
        'Manager cannot perform analyst operations'
    );

    set_actor(v_analyst);
    cs_security.require_operator(v_analyst);
    v_passed := v_passed + 1;
    DBMS_OUTPUT.PUT_LINE('PASS: Analyst has operational permission');

    expect_denied(
        v_analyst, 'MANAGER',
        'Analyst cannot perform management operations'
    );

    set_actor(v_auditor);
    expect_denied(
        v_auditor, 'OPERATOR',
        'Auditor cannot perform operational writes'
    );

    set_actor(v_inactive);
    expect_denied(
        v_inactive, 'MANAGER',
        'Inactive admin is rejected'
    );

    set_actor(v_analyst);
    expect_denied(
        v_admin, 'MANAGER',
        'Mismatched actor context is rejected'
    );

    DBMS_SESSION.CLEAR_IDENTIFIER;
    expect_denied(
        v_admin, 'MANAGER',
        'Missing actor context is rejected'
    );

    ROLLBACK TO security_test;
    restore_context;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: ' || v_passed ||
        ' security checks passed; test records rolled back'
    );
EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO security_test;
        restore_context;
        RAISE;
END;
/