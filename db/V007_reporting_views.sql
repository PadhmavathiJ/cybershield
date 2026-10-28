CREATE OR REPLACE VIEW vw_open_incidents AS
SELECT
    i.incident_id,
    i.title,
    i.severity,
    i.status,
    i.opened_at,
    c.cycle_id,
    c.cycle_no,
    u.full_name AS lead_name,
    s.response_due_at,
    s.resolution_due_at
FROM incident i
JOIN investigation_cycle c
  ON c.incident_id = i.incident_id
 AND c.ended_at IS NULL
LEFT JOIN incident_assignment a
  ON a.cycle_id = c.cycle_id
 AND a.assignment_role = 'LEAD'
 AND a.ended_at IS NULL
LEFT JOIN investigator inv
  ON inv.investigator_id = a.investigator_id
LEFT JOIN app_user u
  ON u.user_id = inv.user_id
LEFT JOIN sla s
  ON s.cycle_id = c.cycle_id
WHERE i.status NOT IN ('RESOLVED', 'CLOSED');


CREATE OR REPLACE VIEW vw_critical_alerts AS
SELECT
    a.alert_id,
    a.event_id,
    srv.hostname,
    e.event_at,
    a.severity,
    a.status,
    ia.incident_id
FROM alert a
JOIN security_event e
  ON e.event_id = a.event_id
JOIN server srv
  ON srv.server_id = e.server_id
LEFT JOIN incident_alert ia
  ON ia.alert_id = a.alert_id
WHERE a.severity = 'CRITICAL';


CREATE OR REPLACE VIEW vw_investigator_workload AS
SELECT
    inv.investigator_id,
    u.full_name,
    inv.availability,
    NVL(w.active_cases, 0) AS active_cases,
    NVL(w.lead_cases, 0) AS lead_cases
FROM investigator inv
JOIN app_user u
  ON u.user_id = inv.user_id
LEFT JOIN (
    SELECT
        a.investigator_id,
        COUNT(*) AS active_cases,
        SUM(
            CASE
                WHEN a.assignment_role = 'LEAD' THEN 1
                ELSE 0
            END
        ) AS lead_cases
    FROM incident_assignment a
    JOIN investigation_cycle c
      ON c.cycle_id = a.cycle_id
     AND c.ended_at IS NULL
    JOIN incident i
      ON i.incident_id = c.incident_id
    WHERE a.ended_at IS NULL
      AND i.status NOT IN ('RESOLVED', 'CLOSED')
    GROUP BY a.investigator_id
) w
  ON w.investigator_id = inv.investigator_id;


CREATE OR REPLACE VIEW vw_sla_status AS
SELECT
    c.incident_id,
    c.cycle_id,
    s.response_due_at,
    s.resolution_due_at,
    s.acknowledged_at,
    r.resolved_at,
    CASE
        WHEN s.response_due_at <
             COALESCE(s.acknowledged_at, SYSTIMESTAMP)
        THEN 1
        ELSE 0
    END AS response_breached,
    CASE
        WHEN s.resolution_due_at <
             COALESCE(r.resolved_at, SYSTIMESTAMP)
        THEN 1
        ELSE 0
    END AS resolution_breached
FROM investigation_cycle c
JOIN sla s
  ON s.cycle_id = c.cycle_id
LEFT JOIN resolution r
  ON r.cycle_id = c.cycle_id;


CREATE OR REPLACE VIEW vw_custody_history AS
SELECT
    c.custody_id,
    c.evidence_id,
    source_user.full_name AS from_name,
    destination_user.full_name AS to_name,
    c.transferred_at,
    c.method,
    c.purpose,
    c.receipt_condition
FROM chain_of_custody c
LEFT JOIN investigator source_inv
  ON source_inv.investigator_id = c.from_investigator_id
LEFT JOIN app_user source_user
  ON source_user.user_id = source_inv.user_id
JOIN investigator destination_inv
  ON destination_inv.investigator_id = c.to_investigator_id
JOIN app_user destination_user
  ON destination_user.user_id = destination_inv.user_id;


CREATE OR REPLACE VIEW vw_dashboard_summary AS
SELECT
    (
        SELECT COUNT(*)
        FROM server
        WHERE is_active = 1
    ) AS active_servers,
    (
        SELECT COUNT(*)
        FROM security_event
    ) AS total_events,
    (
        SELECT COUNT(*)
        FROM alert
        WHERE severity = 'CRITICAL'
          AND status IN ('NEW', 'ACKNOWLEDGED', 'ESCALATED')
    ) AS critical_alerts,
    (
        SELECT COUNT(*)
        FROM incident
        WHERE status NOT IN ('RESOLVED', 'CLOSED')
    ) AS open_incidents,
    (
        SELECT COUNT(*)
        FROM investigator inv
        JOIN app_user u
          ON u.user_id = inv.user_id
        WHERE inv.availability <> 'INACTIVE'
          AND u.is_active = 1
          AND u.role_code IN ('ADMIN', 'ANALYST')
    ) AS active_investigators,
    (
        SELECT COUNT(*)
        FROM vw_sla_status s
        JOIN investigation_cycle c
          ON c.cycle_id = s.cycle_id
        JOIN incident i
          ON i.incident_id = c.incident_id
        WHERE c.ended_at IS NULL
          AND i.status NOT IN ('RESOLVED', 'CLOSED')
          AND (
              s.response_breached = 1
              OR s.resolution_breached = 1
          )
    ) AS sla_breaches
FROM dual;