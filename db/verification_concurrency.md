# Two session custody lock test

Run against the seeded local database using two SQL*Plus
connections as CS_OWNER in FREEPDB1.

## Window A

Select one contained incident and keep its row locked:

```sql
VARIABLE locked_incident NUMBER

BEGIN
    SELECT incident_id
    INTO :locked_incident
    FROM incident
    WHERE status = 'CONTAINED'
    ORDER BY incident_id
    FETCH FIRST 1 ROW ONLY;
END;
/

SELECT incident_id
FROM incident
WHERE incident_id = :locked_incident
FOR UPDATE;
```

Leave this transaction open. Do not commit or roll back yet.

## Window B

Connect separately as CS_OWNER in FREEPDB1.
Run this block while Window A still holds its lock:

```sql
SET SERVEROUTPUT ON

DECLARE
    v_incident NUMBER;
    v_evidence NUMBER;
    v_custodian NUMBER;
    v_actor NUMBER;
    v_receiver NUMBER;
    v_before NUMBER;
    v_after NUMBER;
    v_actual NUMBER;
    v_blocked BOOLEAN := FALSE;
    v_previous_client VARCHAR2(64);

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

    SAVEPOINT contention_test;

    SELECT incident_id
    INTO v_incident
    FROM incident
    WHERE status = 'CONTAINED'
    ORDER BY incident_id
    FETCH FIRST 1 ROW ONLY;

    SELECT
        e.evidence_id,
        e.current_custodian_id,
        inv.user_id
    INTO v_evidence, v_custodian, v_actor
    FROM evidence e
    JOIN investigator inv
      ON inv.investigator_id = e.current_custodian_id
    WHERE e.incident_id = v_incident
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
            -20999, 'No eligible receiver'
        );
    END IF;

    SELECT COUNT(*)
    INTO v_before
    FROM chain_of_custody
    WHERE evidence_id = v_evidence;

    DBMS_SESSION.SET_IDENTIFIER(
        TO_CHAR(v_actor, 'FM9999999990')
    );

    BEGIN
        sp_transfer_evidence(
            v_actor,
            v_evidence,
            v_custodian,
            v_receiver,
            'CONTROLLED_HANDOVER',
            'Lock contention verification',
            'Intact'
        );
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE IN (-30006, -54) THEN
                v_blocked := TRUE;
            ELSE
                RAISE;
            END IF;
    END;

    IF NOT v_blocked THEN
        RAISE_APPLICATION_ERROR(
            -20999, 'Expected lock timeout did not occur'
        );
    END IF;

    DBMS_OUTPUT.PUT_LINE(
        'PASS: Concurrent transfer timed out on the held lock'
    );

    SELECT current_custodian_id
    INTO v_actual
    FROM evidence
    WHERE evidence_id = v_evidence;

    SELECT COUNT(*)
    INTO v_after
    FROM chain_of_custody
    WHERE evidence_id = v_evidence;

    IF v_actual <> v_custodian OR v_before <> v_after THEN
        RAISE_APPLICATION_ERROR(
            -20999, 'Custody changed during rejected transfer'
        );
    END IF;

    DBMS_OUTPUT.PUT_LINE(
        'PASS: Custodian and custody history remain unchanged'
    );

    ROLLBACK TO contention_test;
    restore_context;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: Two-session lock contention test passed'
    );
EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO contention_test;
        restore_context;
        RAISE;
END;
/
```

Expected: approximately five seconds of waiting, two PASS
messages and the SUCCESS line.

## Release Window A

Always run this, including after a Window B error:

```sql
ROLLBACK;
```

## Recorded execution

The original test passed using:
- Incident: 71
- Evidence: 51
- Custodian investigator: 42
- Custodian application user: 102

The reusable version above discovers IDs from the seed dataset.
Run without other sessions changing incident status or assignments.

This verifies lock contention and rejection without custody
changes. It does not demonstrate two successful competing
transfers or a stale retry after another session commits.