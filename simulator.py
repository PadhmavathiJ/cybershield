"""Atomic Oracle-only simulator ingestion and threshold-incident creation.
Rule: each alert returned by SP_INGEST_EVENT (severity_score >= the persisted
SOC_POLICY.alert_threshold when ingested) has exactly one linked incident.
The database procedure locks the alert and rejects duplicate incident links.
"""
from dataclasses import dataclass
from datetime import datetime
import oracledb
from db import get_connection


@dataclass(frozen=True)
class SimulationResult:
    event_id: int
    alert_id: int | None
    incident_id: int | None


def ingest_simulation(actor, *, source_key, server_id, source_ip_id,
                      attack_type_id, event_at, protocol, packet_count,
                      bytes_in, bytes_out, severity_score, details):
    if actor is None:
        raise PermissionError('Authenticated actor required')
    if not isinstance(event_at, datetime) or event_at.tzinfo is None:
        raise ValueError('Simulation time must include a UTC offset')
    con = get_connection()
    cur = None
    try:
        con.client_identifier = str(actor)
        cur = con.cursor()
        timestamp = cur.var(oracledb.DB_TYPE_TIMESTAMP_TZ)
        timestamp.setvalue(0, event_at)
        event_id = cur.var(oracledb.NUMBER)
        alert_id = cur.var(oracledb.NUMBER)
        cur.callproc('CS_OWNER.SP_INGEST_EVENT', [
            actor, source_key, server_id, source_ip_id, attack_type_id,
            timestamp, protocol, packet_count, bytes_in, bytes_out,
            severity_score, details, event_id, alert_id,
        ])
        event = int(event_id.getvalue())
        alert = alert_id.getvalue()
        incident = None
        if alert is not None:
            alert = int(alert)
            cur.execute('SELECT incident_id FROM CS_OWNER.INCIDENT_ALERT WHERE alert_id=:alert_id', {'alert_id': alert})
            linked = cur.fetchone()
            if linked:
                incident = int(linked[0])
            else:
                cur.execute('SELECT severity FROM CS_OWNER.ALERT WHERE alert_id=:alert_id', {'alert_id': alert})
                severity = cur.fetchone()[0]
                incident_id = cur.var(oracledb.NUMBER)
                description = (
                    'SIMULATED: automatically opened from the Oracle severity-score threshold alert. '
                    'Rule: severity_score >= SOC_POLICY.alert_threshold at ingestion. '
                    f'Source event key: {source_key}. Score: {severity_score}.\n{details}'
                )
                try:
                    # SP_CREATE_INCIDENT locks the alert before checking its unique link.
                    # Keep both procedures on this connection; neither call commits here.
                    cur.callproc('CS_OWNER.SP_CREATE_INCIDENT', [
                        actor, alert, f'SIMULATED threshold event {source_key}',
                        description, severity, None, incident_id,
                    ])
                    incident = int(incident_id.getvalue())
                except oracledb.DatabaseError as exc:
                    if getattr(exc.args[0], 'code', None) != 20009:
                        raise
                    # A concurrent creator committed while SP_CREATE_INCIDENT waited.
                    # Its savepoint rollback preserves this call's ingestion transaction.
                    cur.execute('SELECT incident_id FROM CS_OWNER.INCIDENT_ALERT WHERE alert_id=:alert_id', {'alert_id': alert})
                    linked = cur.fetchone()
                    if not linked:
                        raise
                    incident = int(linked[0])
        con.commit()
        return SimulationResult(event, alert, incident)
    except Exception:
        con.rollback()
        raise
    finally:
        try:
            if cur is not None:
                cur.close()
        finally:
            try:
                con.client_identifier = None
            finally:
                con.close()
