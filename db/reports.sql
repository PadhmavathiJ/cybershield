SET PAGESIZE 100
SET LINESIZE 220
SET VERIFY OFF

VARIABLE from_utc VARCHAR2(40)
VARIABLE to_utc VARCHAR2(40)
VARIABLE report_evidence_id NUMBER

BEGIN
    :from_utc := TO_CHAR(
        SYSTIMESTAMP AT TIME ZONE 'UTC' - INTERVAL '30' DAY,
        'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
    );

    :to_utc := TO_CHAR(
        SYSTIMESTAMP AT TIME ZONE 'UTC' + INTERVAL '1' DAY,
        'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
    );

    SELECT MIN(evidence_id)
    INTO :report_evidence_id
    FROM evidence;
END;
/

PROMPT Q01 Daily events using UTC calendar dates

SELECT
    TRUNC(CAST(SYS_EXTRACT_UTC(event_at) AS DATE)) AS event_day_utc,
    COUNT(*) AS event_count
FROM security_event
WHERE event_at >= TO_TIMESTAMP_TZ(
          :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
  AND event_at < TO_TIMESTAMP_TZ(
          :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
GROUP BY TRUNC(CAST(SYS_EXTRACT_UTC(event_at) AS DATE))
ORDER BY event_day_utc;


PROMPT Q02 Alert severity by event occurrence time

SELECT
    a.severity,
    COUNT(*) AS alert_count
FROM alert a
JOIN security_event e ON e.event_id = a.event_id
WHERE e.event_at >= TO_TIMESTAMP_TZ(
          :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
  AND e.event_at < TO_TIMESTAMP_TZ(
          :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
GROUP BY a.severity
ORDER BY CASE a.severity
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH' THEN 2
    WHEN 'MEDIUM' THEN 3
    ELSE 4
END;


PROMPT Q03 Most targeted servers with dense ranking

WITH server_counts AS (
    SELECT
        s.server_id,
        s.hostname,
        COUNT(*) AS event_count
    FROM server s
    JOIN security_event e ON e.server_id = s.server_id
    WHERE e.event_at >= TO_TIMESTAMP_TZ(
              :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
          )
      AND e.event_at < TO_TIMESTAMP_TZ(
              :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
          )
    GROUP BY s.server_id, s.hostname
),
ranked AS (
    SELECT
        server_id,
        hostname,
        event_count,
        DENSE_RANK() OVER (
            ORDER BY event_count DESC
        ) AS attack_rank
    FROM server_counts
)
SELECT *
FROM ranked
WHERE attack_rank <= 10
ORDER BY attack_rank, hostname;


PROMPT Q04 Events by attack type

SELECT
    t.attack_type_id,
    t.name,
    COUNT(*) AS event_count
FROM attack_type t
JOIN security_event e ON e.attack_type_id = t.attack_type_id
WHERE e.event_at >= TO_TIMESTAMP_TZ(
          :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
  AND e.event_at < TO_TIMESTAMP_TZ(
          :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
GROUP BY t.attack_type_id, t.name
ORDER BY event_count DESC, t.name;


PROMPT Q05 Repeat source IP addresses

SELECT
    ip.ip_id,
    ip.ip_text,
    COUNT(*) AS event_count,
    COUNT(DISTINCT e.server_id) AS targeted_servers
FROM ip_address ip
JOIN security_event e ON e.source_ip_id = ip.ip_id
WHERE e.event_at >= TO_TIMESTAMP_TZ(
          :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
  AND e.event_at < TO_TIMESTAMP_TZ(
          :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
GROUP BY ip.ip_id, ip.ip_text
HAVING COUNT(*) > 1
ORDER BY event_count DESC, ip.ip_text;


PROMPT Q06 Events by synthetic source country metadata

SELECT
    NVL(ip.country_code, 'UNKNOWN') AS country_code,
    COUNT(*) AS event_count
FROM security_event e
JOIN ip_address ip ON ip.ip_id = e.source_ip_id
WHERE e.event_at >= TO_TIMESTAMP_TZ(
          :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
  AND e.event_at < TO_TIMESTAMP_TZ(
          :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
GROUP BY NVL(ip.country_code, 'UNKNOWN')
ORDER BY event_count DESC, country_code;


PROMPT Q07 Current status of incidents opened in range

SELECT
    status,
    COUNT(*) AS incident_count
FROM incident
WHERE opened_at >= TO_TIMESTAMP_TZ(
          :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
  AND opened_at < TO_TIMESTAMP_TZ(
          :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
GROUP BY status
ORDER BY status;


PROMPT Q08 Current investigator workload across all dates

SELECT
    investigator_id,
    full_name,
    availability,
    active_cases,
    lead_cases
FROM vw_investigator_workload
ORDER BY active_cases DESC, lead_cases DESC, investigator_id;


PROMPT Q09 Breached SLA cycles started in range

SELECT
    i.incident_id,
    i.title,
    c.cycle_no,
    s.response_due_at,
    s.resolution_due_at,
    s.acknowledged_at,
    s.resolved_at,
    s.response_breached,
    s.resolution_breached
FROM vw_sla_status s
JOIN investigation_cycle c ON c.cycle_id = s.cycle_id
JOIN incident i ON i.incident_id = c.incident_id
WHERE c.started_at >= TO_TIMESTAMP_TZ(
          :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
  AND c.started_at < TO_TIMESTAMP_TZ(
          :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
  AND (
      s.response_breached = 1
      OR s.resolution_breached = 1
  )
ORDER BY c.started_at, c.cycle_id;


PROMPT Q10 Mean time to acknowledge first investigation in minutes

WITH elapsed AS (
    SELECT
        SYS_EXTRACT_UTC(s.acknowledged_at)
        - SYS_EXTRACT_UTC(i.opened_at) AS duration
    FROM incident i
    JOIN investigation_cycle c
      ON c.incident_id = i.incident_id
     AND c.cycle_no = 1
    JOIN sla s ON s.cycle_id = c.cycle_id
    WHERE s.acknowledged_at IS NOT NULL
      AND i.opened_at >= TO_TIMESTAMP_TZ(
              :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
          )
      AND i.opened_at < TO_TIMESTAMP_TZ(
              :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
          )
)
SELECT
    COUNT(*) AS acknowledged_incidents,
    ROUND(AVG(
        EXTRACT(DAY FROM duration) * 1440
        + EXTRACT(HOUR FROM duration) * 60
        + EXTRACT(MINUTE FROM duration)
        + EXTRACT(SECOND FROM duration) / 60
    ), 4) AS mtta_minutes
FROM elapsed;


PROMPT Q11 Mean time to resolve completed cycles in minutes

WITH elapsed AS (
    SELECT
        SYS_EXTRACT_UTC(r.resolved_at)
        - SYS_EXTRACT_UTC(c.started_at) AS duration
    FROM investigation_cycle c
    JOIN resolution r ON r.cycle_id = c.cycle_id
    WHERE c.started_at >= TO_TIMESTAMP_TZ(
              :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
          )
      AND c.started_at < TO_TIMESTAMP_TZ(
              :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
          )
)
SELECT
    COUNT(*) AS resolved_cycles,
    ROUND(AVG(
        EXTRACT(DAY FROM duration) * 1440
        + EXTRACT(HOUR FROM duration) * 60
        + EXTRACT(MINUTE FROM duration)
        + EXTRACT(SECOND FROM duration) / 60
    ), 4) AS mttr_minutes
FROM elapsed;


PROMPT Q12 Current closure rate for incidents opened in range

SELECT
    COUNT(*) AS opened_incidents,
    COUNT(CASE WHEN status = 'CLOSED' THEN 1 END)
        AS currently_closed,
    ROUND(
        100.0 * COUNT(CASE WHEN status = 'CLOSED' THEN 1 END)
        / NULLIF(COUNT(*), 0),
        2
    ) AS closure_rate_percent
FROM incident
WHERE opened_at >= TO_TIMESTAMP_TZ(
          :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
  AND opened_at < TO_TIMESTAMP_TZ(
          :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      );


PROMPT Q13 Campaign event coverage in the selected event range

SELECT
    c.campaign_id,
    c.name,
    (
        SELECT COUNT(*)
        FROM campaign_event ce
        JOIN security_event e ON e.event_id = ce.event_id
        WHERE ce.campaign_id = c.campaign_id
          AND e.event_at >= TO_TIMESTAMP_TZ(
                  :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
              )
          AND e.event_at < TO_TIMESTAMP_TZ(
                  :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
              )
    ) AS event_count
FROM attack_campaign c
ORDER BY event_count DESC, c.campaign_id;


PROMPT Q14 Complete custody history for selected evidence

SELECT
    custody_id,
    evidence_id,
    from_name,
    to_name,
    transferred_at,
    method,
    purpose,
    receipt_condition
FROM vw_custody_history
WHERE evidence_id = :report_evidence_id
ORDER BY transferred_at, custody_id;


PROMPT Q15 Unlinked critical alerts by event occurrence time

SELECT
    a.alert_id,
    a.event_id,
    e.event_at,
    a.status,
    s.hostname
FROM alert a
JOIN security_event e ON e.event_id = a.event_id
JOIN server s ON s.server_id = e.server_id
WHERE a.severity = 'CRITICAL'
  AND a.status <> 'DISMISSED'
  AND e.event_at >= TO_TIMESTAMP_TZ(
          :from_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
  AND e.event_at < TO_TIMESTAMP_TZ(
          :to_utc, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM'
      )
  AND NOT EXISTS (
      SELECT 1
      FROM incident_alert ia
      WHERE ia.alert_id = a.alert_id
  )
ORDER BY e.event_at DESC, a.alert_id;