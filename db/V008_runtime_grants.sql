GRANT CREATE SESSION TO cs_app;

BEGIN
    FOR r IN (
        SELECT table_name
        FROM all_tables
        WHERE owner = 'CS_OWNER'
          AND table_name <> 'SCHEMA_MIGRATION'
    ) LOOP
        EXECUTE IMMEDIATE
            'GRANT SELECT ON cs_owner.' ||
            DBMS_ASSERT.SIMPLE_SQL_NAME(r.table_name) ||
            ' TO cs_app';
    END LOOP;

    FOR r IN (
        SELECT view_name
        FROM all_views
        WHERE owner = 'CS_OWNER'
          AND view_name IN (
              'VW_OPEN_INCIDENTS',
              'VW_CRITICAL_ALERTS',
              'VW_INVESTIGATOR_WORKLOAD',
              'VW_SLA_STATUS',
              'VW_CUSTODY_HISTORY',
              'VW_DASHBOARD_SUMMARY'
          )
    ) LOOP
        EXECUTE IMMEDIATE
            'GRANT SELECT ON cs_owner.' ||
            DBMS_ASSERT.SIMPLE_SQL_NAME(r.view_name) ||
            ' TO cs_app';
    END LOOP;

    FOR r IN (
        SELECT column_value AS procedure_name
        FROM TABLE(SYS.ODCIVARCHAR2LIST(
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
        ))
    ) LOOP
        EXECUTE IMMEDIATE
            'GRANT EXECUTE ON cs_owner.' ||
            DBMS_ASSERT.SIMPLE_SQL_NAME(r.procedure_name) ||
            ' TO cs_app';
    END LOOP;
END;
/