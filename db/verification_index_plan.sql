SET PAGESIZE 100
SET LINESIZE 200
SET SERVEROUTPUT ON

BEGIN
    IF SYS_CONTEXT('USERENV', 'SESSION_USER') <> 'CS_OWNER' THEN
        RAISE_APPLICATION_ERROR(
            -20999, 'Run this demonstration as CS_OWNER'
        );
    END IF;
END;
/

CREATE TABLE cs_index_demo AS
SELECT
    LEVEL AS demo_id,
    MOD(LEVEL, 1000) + 1 AS server_id,
    TO_TIMESTAMP_TZ(
        '2026-01-01 00:00:00 +00:00',
        'YYYY-MM-DD HH24:MI:SS TZH:TZM'
    ) + NUMTODSINTERVAL(
        MOD(LEVEL, 86400), 'SECOND'
    ) AS event_at,
    RPAD('Synthetic demonstration data', 200, '.') AS details
FROM dual
CONNECT BY LEVEL <= 100000;

BEGIN
    DBMS_STATS.GATHER_TABLE_STATS(
        ownname => USER,
        tabname => 'CS_INDEX_DEMO'
    );
END;
/

PROMPT BEFORE INDEX

EXPLAIN PLAN
SET STATEMENT_ID = 'CS_DEMO_BEFORE'
FOR
SELECT demo_id, event_at
FROM cs_index_demo
WHERE server_id = 42
  AND event_at >= TO_TIMESTAMP_TZ(
      '2026-01-01 00:00:00 +00:00',
      'YYYY-MM-DD HH24:MI:SS TZH:TZM'
  )
  AND event_at < TO_TIMESTAMP_TZ(
      '2026-01-01 12:00:00 +00:00',
      'YYYY-MM-DD HH24:MI:SS TZH:TZM'
  );

SELECT plan_table_output
FROM TABLE(
    DBMS_XPLAN.DISPLAY(
        'PLAN_TABLE',
        'CS_DEMO_BEFORE',
        'TYPICAL'
    )
);

CREATE INDEX cs_ix_demo
ON cs_index_demo (server_id, event_at);

BEGIN
    DBMS_STATS.GATHER_TABLE_STATS(
        ownname => USER,
        tabname => 'CS_INDEX_DEMO',
        cascade => TRUE
    );
END;
/

PROMPT AFTER INDEX

EXPLAIN PLAN
SET STATEMENT_ID = 'CS_DEMO_AFTER'
FOR
SELECT demo_id, event_at
FROM cs_index_demo
WHERE server_id = 42
  AND event_at >= TO_TIMESTAMP_TZ(
      '2026-01-01 00:00:00 +00:00',
      'YYYY-MM-DD HH24:MI:SS TZH:TZM'
  )
  AND event_at < TO_TIMESTAMP_TZ(
      '2026-01-01 12:00:00 +00:00',
      'YYYY-MM-DD HH24:MI:SS TZH:TZM'
  );

SELECT plan_table_output
FROM TABLE(
    DBMS_XPLAN.DISPLAY(
        'PLAN_TABLE',
        'CS_DEMO_AFTER',
        'TYPICAL'
    )
);

DECLARE
    v_full_scan_count NUMBER;
    v_index_count NUMBER;
    v_rows NUMBER;
BEGIN
    SELECT COUNT(*)
    INTO v_full_scan_count
    FROM plan_table
    WHERE statement_id = 'CS_DEMO_BEFORE'
      AND operation = 'TABLE ACCESS'
      AND options = 'FULL'
      AND object_name = 'CS_INDEX_DEMO';

    SELECT COUNT(*)
    INTO v_index_count
    FROM plan_table
    WHERE statement_id = 'CS_DEMO_AFTER'
      AND operation = 'INDEX'
      AND object_name = 'CS_IX_DEMO';

    SELECT COUNT(*)
    INTO v_rows
    FROM cs_index_demo
    WHERE server_id = 42
      AND event_at >= TO_TIMESTAMP_TZ(
          '2026-01-01 00:00:00 +00:00',
          'YYYY-MM-DD HH24:MI:SS TZH:TZM'
      )
      AND event_at < TO_TIMESTAMP_TZ(
          '2026-01-01 12:00:00 +00:00',
          'YYYY-MM-DD HH24:MI:SS TZH:TZM'
      );

    IF v_rows <> 57 THEN
        RAISE_APPLICATION_ERROR(
            -20999, 'Unexpected fixture result count: ' || v_rows
        );
    END IF;

    DBMS_OUTPUT.PUT_LINE(
        'PASS: Demonstration query returns 57 matching rows'
    );

    IF v_full_scan_count > 0 THEN
        DBMS_OUTPUT.PUT_LINE(
            'OBSERVED: Full table scan before index creation'
        );
    END IF;

    IF v_index_count > 0 THEN
        DBMS_OUTPUT.PUT_LINE(
            'OBSERVED: Optimizer selected the new index'
        );
    ELSE
        DBMS_OUTPUT.PUT_LINE(
            'REVIEW: Optimizer did not select the new index'
        );
    END IF;
END;
/

DROP TABLE cs_index_demo PURGE;

DELETE FROM plan_table
WHERE statement_id IN ('CS_DEMO_BEFORE', 'CS_DEMO_AFTER');

COMMIT;

PROMPT Demonstration finished and synthetic table removed.