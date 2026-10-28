SET SERVEROUTPUT ON

DECLARE
    v_count NUMBER;
    v_event NUMBER;
    v_alert NUMBER;
BEGIN
    IF SYS_CONTEXT('USERENV', 'SESSION_USER') <> 'CS_APP' THEN
        RAISE_APPLICATION_ERROR(
            -20999, 'Run this test while connected as CS_APP'
        );
    END IF;

    SELECT COUNT(*)
    INTO v_count
    FROM all_tab_privs
    WHERE grantee = 'CS_APP'
      AND table_schema = 'CS_OWNER'
      AND privilege = 'EXECUTE'
      AND table_name IN (
          'SP_INGEST_EVENT',
          'SP_CREATE_INCIDENT',
          'SP_LINK_ALERT',
          'SP_TRIAGE_ALERT',
          'SP_ASSIGN_INVESTIGATOR',
          'SP_END_ASSIGNMENT',
          'SP_CHANGE_STATUS',
          'SP_REGISTER_EVIDENCE',
          'SP_TRANSFER_EVIDENCE',
          'SP_ADD_ANALYSIS',
          'SP_RECORD_ACTION',
          'SP_RESOLVE_INCIDENT',
          'SP_REOPEN_INCIDENT',
          'SP_ESCALATE_SLA'
      );

    IF v_count <> 14 THEN
        RAISE_APPLICATION_ERROR(
            -20999, 'Expected execute grants on 14 procedures'
        );
    END IF;

    DBMS_OUTPUT.PUT_LINE(
        'PASS: 14 workflow procedures accessible'
    );

    BEGIN
        EXECUTE IMMEDIATE
            'UPDATE cs_owner.incident
             SET title = title
             WHERE 1 = 0';

        RAISE_APPLICATION_ERROR(
            -20999, 'Direct incident writes were allowed'
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE IN (-1031, -41900) THEN
                DBMS_OUTPUT.PUT_LINE(
                    'PASS: Direct incident writes blocked'
                );
            ELSE
                RAISE;
            END IF;
    END;

    BEGIN
        EXECUTE IMMEDIATE
            'DELETE FROM cs_owner.audit_log WHERE 1 = 0';

        RAISE_APPLICATION_ERROR(
            -20999, 'Direct audit deletion was allowed'
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE IN (-1031, -41900) THEN
                DBMS_OUTPUT.PUT_LINE(
                    'PASS: Direct audit deletion blocked'
                );
            ELSE
                RAISE;
            END IF;
    END;

    BEGIN
        cs_owner.sp_ingest_event(
            -1,
            'permission-test',
            -1,
            -1,
            -1,
            SYSTIMESTAMP,
            'HTTPS',
            0,
            0,
            0,
            95,
            NULL,
            v_event,
            v_alert
        );

        RAISE_APPLICATION_ERROR(
            -20999, 'Invalid actor was accepted'
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = -20007 THEN
                DBMS_OUTPUT.PUT_LINE(
                    'PASS: Procedure executes and rejects invalid actor'
                );
            ELSE
                RAISE;
            END IF;
    END;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: Runtime permission checks passed'
    );
END;
/