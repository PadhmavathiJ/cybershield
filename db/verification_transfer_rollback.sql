SET SERVEROUTPUT ON

CREATE OR REPLACE TRIGGER trg_test_transfer_failure
BEFORE UPDATE OF current_custodian_id ON evidence
FOR EACH ROW
BEGIN
    IF SYS_CONTEXT('USERENV', 'CLIENT_INFO') = 'CS_ROLLBACK_TEST'
       AND :NEW.current_custodian_id <> :OLD.current_custodian_id
    THEN
        RAISE_APPLICATION_ERROR(
            -20990, 'Intentional transfer verification failure'
        );
    END IF;
END;
/

DECLARE
    v_evidence NUMBER;
    v_incident NUMBER;
    v_custodian NUMBER;
    v_actor NUMBER;
    v_receiver NUMBER;
    v_custody_before NUMBER;
    v_custody_after NUMBER;
    v_audit_before NUMBER;
    v_audit_after NUMBER;
    v_actual_custodian NUMBER;
    v_previous_client VARCHAR2(64);
    v_previous_info VARCHAR2(64);
    v_failed BOOLEAN := FALSE;

    PROCEDURE restore_context IS
    BEGIN
        IF v_previous_client IS NULL THEN
            DBMS_SESSION.CLEAR_IDENTIFIER;
        ELSE
            DBMS_SESSION.SET_IDENTIFIER(v_previous_client);
        END IF;

        DBMS_APPLICATION_INFO.SET_CLIENT_INFO(v_previous_info);
    END;

    PROCEDURE remove_test_trigger IS
    BEGIN
        EXECUTE IMMEDIATE 'DROP TRIGGER trg_test_transfer_failure';
    END;

BEGIN
    v_previous_client :=
        SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER');
    v_previous_info :=
        SYS_CONTEXT('USERENV', 'CLIENT_INFO');

    SAVEPOINT transfer_failure_test;

    SELECT
        e.evidence_id,
        e.incident_id,
        e.current_custodian_id,
        inv.user_id
    INTO
        v_evidence,
        v_incident,
        v_custodian,
        v_actor
    FROM evidence e
    JOIN incident i ON i.incident_id = e.incident_id
    JOIN investigator inv
      ON inv.investigator_id = e.current_custodian_id
    JOIN app_user u ON u.user_id = inv.user_id
    WHERE i.status = 'CONTAINED'
      AND inv.availability <> 'INACTIVE'
      AND u.is_active = 1
      AND u.role_code IN ('ADMIN', 'ANALYST')
      AND EXISTS (
          SELECT 1
          FROM incident_assignment a
          JOIN investigation_cycle c ON c.cycle_id = a.cycle_id
          WHERE c.incident_id = i.incident_id
            AND c.ended_at IS NULL
            AND a.ended_at IS NULL
            AND a.investigator_id = inv.investigator_id
      )
    ORDER BY e.evidence_id
    FETCH FIRST 1 ROW ONLY;

    SELECT MIN(a.investigator_id)
    INTO v_receiver
    FROM incident_assignment a
    JOIN investigation_cycle c ON c.cycle_id = a.cycle_id
    JOIN investigator inv
      ON inv.investigator_id = a.investigator_id
    JOIN app_user u ON u.user_id = inv.user_id
    WHERE c.incident_id = v_incident
      AND c.ended_at IS NULL
      AND a.ended_at IS NULL
      AND a.investigator_id <> v_custodian
      AND inv.availability <> 'INACTIVE'
      AND u.is_active = 1
      AND u.role_code IN ('ADMIN', 'ANALYST');

    IF v_receiver IS NULL THEN
        RAISE_APPLICATION_ERROR(
            -20999, 'No eligible receiving investigator'
        );
    END IF;

    SELECT COUNT(*)
    INTO v_custody_before
    FROM chain_of_custody
    WHERE evidence_id = v_evidence;

    SELECT COUNT(*)
    INTO v_audit_before
    FROM audit_log;

    DBMS_SESSION.SET_IDENTIFIER(
        TO_CHAR(v_actor, 'FM9999999990')
    );

    DBMS_APPLICATION_INFO.SET_CLIENT_INFO('CS_ROLLBACK_TEST');

    BEGIN
        sp_transfer_evidence(
            v_actor,
            v_evidence,
            v_custodian,
            v_receiver,
            'CONTROLLED_HANDOVER',
            'Intentional rollback verification',
            'Intact'
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = -20990 THEN
                v_failed := TRUE;
            ELSE
                RAISE;
            END IF;
    END;

    IF NOT v_failed THEN
        RAISE_APPLICATION_ERROR(
            -20999, 'Intentional update failure did not occur'
        );
    END IF;

    DBMS_OUTPUT.PUT_LINE(
        'PASS: Transfer encountered the intentional mid-operation failure'
    );

    SELECT current_custodian_id
    INTO v_actual_custodian
    FROM evidence
    WHERE evidence_id = v_evidence;

    SELECT COUNT(*)
    INTO v_custody_after
    FROM chain_of_custody
    WHERE evidence_id = v_evidence;

    SELECT COUNT(*)
    INTO v_audit_after
    FROM audit_log;

    IF v_actual_custodian <> v_custodian
       OR v_custody_after <> v_custody_before
       OR v_audit_after <> v_audit_before
    THEN
        RAISE_APPLICATION_ERROR(
            -20999, 'Failed transfer left partial changes'
        );
    END IF;

    DBMS_OUTPUT.PUT_LINE(
        'PASS: Custodian custody history and audit all remain unchanged'
    );

    ROLLBACK TO transfer_failure_test;
    restore_context;
    remove_test_trigger;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: Mid-operation rollback verified; temporary trigger removed'
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO transfer_failure_test;
        restore_context;
        remove_test_trigger;
        RAISE;
END;
/