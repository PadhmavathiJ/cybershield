CREATE OR REPLACE PACKAGE cs_security AUTHID DEFINER AS
    PROCEDURE assert_actor(
        p_actor_id IN NUMBER,
        p_role OUT VARCHAR2
    );

    PROCEDURE require_operator(
        p_actor_id IN NUMBER
    );

    PROCEDURE require_manager(
        p_actor_id IN NUMBER
    );

    PROCEDURE require_incident_access(
        p_actor_id IN NUMBER,
        p_incident_id IN NUMBER,
        p_write IN NUMBER DEFAULT 0
    );

    PROCEDURE get_active_cycle(
        p_incident_id IN NUMBER,
        p_cycle_id OUT NUMBER
    );
END cs_security;
/

CREATE OR REPLACE PACKAGE BODY cs_security AS

    PROCEDURE assert_actor(
        p_actor_id IN NUMBER,
        p_role OUT VARCHAR2
    ) IS
        v_active app_user.is_active%TYPE;
        v_client_id VARCHAR2(64);
    BEGIN
        IF p_actor_id IS NULL
           OR p_actor_id <= 0
           OR p_actor_id <> TRUNC(p_actor_id)
        THEN
            RAISE_APPLICATION_ERROR(
                -20007, 'Invalid application actor'
            );
        END IF;

        v_client_id := SYS_CONTEXT(
            'USERENV', 'CLIENT_IDENTIFIER'
        );

        IF v_client_id IS NULL
           OR v_client_id <> TO_CHAR(
               p_actor_id,
               'FM9999999990',
               'NLS_NUMERIC_CHARACTERS=''.,'''
           )
        THEN
            RAISE_APPLICATION_ERROR(
                -20007, 'Application actor context mismatch'
            );
        END IF;

        BEGIN
            SELECT role_code, is_active
            INTO p_role, v_active
            FROM app_user
            WHERE user_id = p_actor_id;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                RAISE_APPLICATION_ERROR(
                    -20007, 'Application actor not found'
                );
        END;

        IF v_active <> 1 THEN
            RAISE_APPLICATION_ERROR(
                -20007, 'Application actor is inactive'
            );
        END IF;
    END assert_actor;


    PROCEDURE require_operator(
        p_actor_id IN NUMBER
    ) IS
        v_role app_user.role_code%TYPE;
    BEGIN
        assert_actor(p_actor_id, v_role);

        IF v_role NOT IN ('ADMIN', 'ANALYST') THEN
            RAISE_APPLICATION_ERROR(
                -20007, 'Operational permission required'
            );
        END IF;
    END require_operator;


    PROCEDURE require_manager(
        p_actor_id IN NUMBER
    ) IS
        v_role app_user.role_code%TYPE;
    BEGIN
        assert_actor(p_actor_id, v_role);

        IF v_role NOT IN ('ADMIN', 'MANAGER') THEN
            RAISE_APPLICATION_ERROR(
                -20007, 'Management permission required'
            );
        END IF;
    END require_manager;


    PROCEDURE require_incident_access(
        p_actor_id IN NUMBER,
        p_incident_id IN NUMBER,
        p_write IN NUMBER DEFAULT 0
    ) IS
        v_role app_user.role_code%TYPE;
        v_count NUMBER;
    BEGIN
        assert_actor(p_actor_id, v_role);

        IF p_write IS NULL OR p_write NOT IN (0, 1) THEN
            RAISE_APPLICATION_ERROR(
                -20010, 'Invalid access mode'
            );
        END IF;

        SELECT COUNT(*)
        INTO v_count
        FROM incident
        WHERE incident_id = p_incident_id;

        IF v_count = 0 THEN
            RAISE_APPLICATION_ERROR(
                -20001, 'Incident not found'
            );
        END IF;

        IF v_role = 'ADMIN' THEN
            RETURN;
        END IF;

        IF p_write = 0
           AND v_role IN ('MANAGER', 'AUDITOR')
        THEN
            RETURN;
        END IF;

        IF v_role = 'ANALYST' THEN
            SELECT COUNT(*)
            INTO v_count
            FROM incident_assignment a
            JOIN investigation_cycle c
              ON c.cycle_id = a.cycle_id
            JOIN investigator i
              ON i.investigator_id = a.investigator_id
            WHERE c.incident_id = p_incident_id
              AND i.user_id = p_actor_id
              AND i.availability <> 'INACTIVE'
              AND (
                  p_write = 0
                  OR (
                      c.ended_at IS NULL
                      AND a.ended_at IS NULL
                  )
              );

            IF v_count > 0 THEN
                RETURN;
            END IF;
        END IF;

        RAISE_APPLICATION_ERROR(
            -20007, 'Incident access denied'
        );
    END require_incident_access;


    PROCEDURE get_active_cycle(
        p_incident_id IN NUMBER,
        p_cycle_id OUT NUMBER
    ) IS
    BEGIN
        SELECT cycle_id
        INTO p_cycle_id
        FROM investigation_cycle
        WHERE incident_id = p_incident_id
          AND ended_at IS NULL;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(
                -20004, 'Incident has no active investigation cycle'
            );
    END get_active_cycle;

END cs_security;
/