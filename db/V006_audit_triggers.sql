CREATE OR REPLACE PACKAGE cs_audit AUTHID DEFINER AS
    PROCEDURE record_change(
        p_action IN VARCHAR2,
        p_entity_name IN VARCHAR2,
        p_entity_id IN NUMBER,
        p_before IN CLOB,
        p_after IN CLOB
    );
END cs_audit;
/


CREATE OR REPLACE PACKAGE BODY cs_audit AS

    PROCEDURE record_change(
        p_action IN VARCHAR2,
        p_entity_name IN VARCHAR2,
        p_entity_id IN NUMBER,
        p_before IN CLOB,
        p_after IN CLOB
    ) IS
        v_client_id VARCHAR2(64);
        v_actor_id NUMBER;
        v_role VARCHAR2(10);
        v_action VARCHAR2(40);
    BEGIN
        v_client_id := SYS_CONTEXT(
            'USERENV', 'CLIENT_IDENTIFIER'
        );

        IF v_client_id IS NULL THEN
            v_actor_id := NULL;
            v_action := 'SYSTEM_' || p_action;
        ELSE
            BEGIN
                v_actor_id := TO_NUMBER(v_client_id);
            EXCEPTION
                WHEN VALUE_ERROR OR INVALID_NUMBER THEN
                    RAISE_APPLICATION_ERROR(
                        -20007, 'Invalid audit actor context'
                    );
            END;

            cs_security.assert_actor(v_actor_id, v_role);
            v_action := p_action;
        END IF;

        INSERT INTO audit_log (
            actor_user_id,
            action,
            entity_name,
            entity_id,
            occurred_at,
            before_data,
            after_data
        ) VALUES (
            v_actor_id,
            v_action,
            p_entity_name,
            p_entity_id,
            SYSTIMESTAMP,
            p_before,
            p_after
        );
    END record_change;

END cs_audit;
/


DECLARE
    v_table VARCHAR2(128);
    v_trigger VARCHAR2(128);
    v_sql VARCHAR2(32767);
BEGIN
    FOR r IN (
        SELECT column_value AS table_name
        FROM TABLE(SYS.ODCIVARCHAR2LIST(
            'CHAIN_OF_CUSTODY',
            'FORENSIC_ANALYSIS',
            'RESOLUTION',
            'RESPONSE_ACTION',
            'INCIDENT_STATUS_HISTORY',
            'AUDIT_LOG'
        ))
    ) LOOP
        v_table := r.table_name;
        v_trigger := 'TRG_IMM_' || v_table;

        v_sql :=
            'CREATE OR REPLACE TRIGGER ' || v_trigger ||
            ' BEFORE UPDATE OR DELETE ON ' || v_table ||
            ' BEGIN ' ||
            ' RAISE_APPLICATION_ERROR(-20008,' ||
            '''Historical records cannot be edited or deleted'');' ||
            ' END;';

        EXECUTE IMMEDIATE v_sql;
    END LOOP;
END;
/


DECLARE
    v_table VARCHAR2(128);
    v_pk VARCHAR2(128);
    v_trigger VARCHAR2(128);
    v_old_fields VARCHAR2(14000);
    v_new_fields VARCHAR2(14000);
    v_old_expression VARCHAR2(15000);
    v_new_expression VARCHAR2(15000);
    v_sql VARCHAR2(32767);
    v_separator VARCHAR2(2);

    FUNCTION redact_column(
        p_name VARCHAR2,
        p_type VARCHAR2
    ) RETURN BOOLEAN
    IS
    BEGIN
        RETURN p_type IN ('CLOB', 'NCLOB', 'BLOB', 'BFILE')
            OR p_name IN (
                'PASSWORD_HASH',
                'STORAGE_KEY',
                'ORIGINAL_NAME',
                'TRIAGE_NOTE',
                'PURPOSE',
                'RECEIPT_CONDITION',
                'REASON',
                'REOPEN_REASON',
                'BREACH_REASON',
                'OUTCOME',
                'SOURCE_REF'
            );
    END;

BEGIN
    FOR r IN (
        SELECT column_value AS table_name
        FROM TABLE(SYS.ODCIVARCHAR2LIST(
            'SECURITY_EVENT',
            'ALERT',
            'INCIDENT',
            'INCIDENT_ALERT',
            'INVESTIGATION_CYCLE',
            'INCIDENT_ASSIGNMENT',
            'SLA',
            'INCIDENT_STATUS_HISTORY',
            'EVIDENCE',
            'CHAIN_OF_CUSTODY',
            'FORENSIC_ANALYSIS',
            'RESPONSE_ACTION',
            'RESOLUTION'
        ))
    ) LOOP
        v_table := r.table_name;
        v_trigger := 'TRG_AUD_' || v_table;

        v_pk :=
            CASE v_table
                WHEN 'SECURITY_EVENT' THEN 'EVENT_ID'
                WHEN 'ALERT' THEN 'ALERT_ID'
                WHEN 'INCIDENT' THEN 'INCIDENT_ID'
                WHEN 'INCIDENT_ALERT' THEN 'INCIDENT_ID'
                WHEN 'INVESTIGATION_CYCLE' THEN 'CYCLE_ID'
                WHEN 'INCIDENT_ASSIGNMENT' THEN 'ASSIGNMENT_ID'
                WHEN 'SLA' THEN 'SLA_ID'
                WHEN 'INCIDENT_STATUS_HISTORY' THEN 'HISTORY_ID'
                WHEN 'EVIDENCE' THEN 'EVIDENCE_ID'
                WHEN 'CHAIN_OF_CUSTODY' THEN 'CUSTODY_ID'
                WHEN 'FORENSIC_ANALYSIS' THEN 'ANALYSIS_ID'
                WHEN 'RESPONSE_ACTION' THEN 'ACTION_ID'
                WHEN 'RESOLUTION' THEN 'RESOLUTION_ID'
            END;

        v_old_fields := NULL;
        v_new_fields := NULL;
        v_separator := NULL;

        FOR c IN (
            SELECT column_name, data_type
            FROM user_tab_columns
            WHERE table_name = v_table
            ORDER BY column_id
        ) LOOP
            IF redact_column(c.column_name, c.data_type) THEN
                v_old_expression := '''[REDACTED]''';
                v_new_expression := '''[REDACTED]''';
            ELSE
                v_old_expression := ':OLD.' || c.column_name;
                v_new_expression := ':NEW.' || c.column_name;
            END IF;

            v_old_fields :=
                v_old_fields || v_separator ||
                '''' || LOWER(c.column_name) ||
                ''' VALUE ' || v_old_expression;

            v_new_fields :=
                v_new_fields || v_separator ||
                '''' || LOWER(c.column_name) ||
                ''' VALUE ' || v_new_expression;

            v_separator := ', ';
        END LOOP;

        IF v_old_fields IS NULL THEN
            RAISE_APPLICATION_ERROR(
                -20010, 'Audit table not found: ' || v_table
            );
        END IF;

        v_sql :=
            'CREATE OR REPLACE TRIGGER ' || v_trigger ||
            ' AFTER INSERT OR UPDATE OR DELETE ON ' || v_table ||
            ' FOR EACH ROW ' ||
            ' DECLARE ' ||
            '   v_action VARCHAR2(10); ' ||
            '   v_entity_id NUMBER; ' ||
            '   v_before CLOB; ' ||
            '   v_after CLOB; ' ||
            ' BEGIN ' ||
            '   IF INSERTING THEN ' ||
            '     v_action := ''INSERT''; ' ||
            '     v_entity_id := :NEW.' || v_pk || '; ' ||
            '   ELSIF UPDATING THEN ' ||
            '     v_action := ''UPDATE''; ' ||
            '     v_entity_id := :NEW.' || v_pk || '; ' ||
            '   ELSE ' ||
            '     v_action := ''DELETE''; ' ||
            '     v_entity_id := :OLD.' || v_pk || '; ' ||
            '   END IF; ' ||
            '   IF UPDATING OR DELETING THEN ' ||
            '     SELECT JSON_OBJECT(' || v_old_fields ||
            '       RETURNING CLOB) INTO v_before FROM dual; ' ||
            '   END IF; ' ||
            '   IF INSERTING OR UPDATING THEN ' ||
            '     SELECT JSON_OBJECT(' || v_new_fields ||
            '       RETURNING CLOB) INTO v_after FROM dual; ' ||
            '   END IF; ' ||
            '   cs_audit.record_change(' ||
            '     v_action, ''' || LOWER(v_table) || ''',' ||
            '     v_entity_id, v_before, v_after); ' ||
            ' END;';

        EXECUTE IMMEDIATE v_sql;
    END LOOP;
END;
/