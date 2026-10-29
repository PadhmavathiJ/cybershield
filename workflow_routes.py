"""Additional root-app workflows; persistence is exclusively Oracle procedures."""
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import secrets
from flask import abort, flash, redirect, render_template, request, url_for
from simulator import ingest_simulation


def register_workflows(app, api):
    roles_required = api['roles_required']
    call_proc = api['call_proc']
    actor_id = api['actor_id']
    obj = api['obj']
    safe_read = api['safe_read']
    safe_one = api['safe_one']
    require_case = api['require_case']
    workflow_error = api['workflow_error']

    @app.route('/events/new', methods=['GET','POST'])
    @roles_required('ADMIN')
    def ingest_event():
        if request.method == 'POST':
            try:
                event_at = datetime.fromisoformat(request.form.get('event_at','').replace('Z','+00:00'))
                if event_at.tzinfo is None:
                    raise ValueError('Include the UTC offset in event time.')
                ids = [int(request.form.get(name,'')) for name in ('server_id','source_ip_id','attack_type_id')]
                counts = [int(request.form.get(name,'0')) for name in ('packet_count','bytes_in','bytes_out')]
                score = Decimal(request.form.get('severity_score',''))
                if any(n <= 0 for n in ids) or any(n < 0 or n >= 10**18 for n in counts):
                    raise ValueError('Select existing assets and non-negative traffic counts below 10^18.')
                if not score.is_finite() or not 0 <= score <= 100 or score != score.quantize(Decimal('0.01')):
                    raise ValueError('Severity score must be 0 to 100 with at most two decimal places.')
                key = request.form.get('source_event_key','').strip()
                protocol = request.form.get('protocol','').strip().upper()
                details = request.form.get('details','').strip()
                if not key or len(key)>100 or not protocol or len(protocol)>16 or not details:
                    raise ValueError('Source key, protocol and simulation details are required.')
            except (ValueError, InvalidOperation) as exc:
                abort(400, description=str(exc) if isinstance(exc, ValueError) and not str(exc).startswith('invalid literal') else 'Check numeric fields and event time.')
            try:
                result = ingest_simulation(actor_id(), source_key=key,
                    server_id=ids[0], source_ip_id=ids[1], attack_type_id=ids[2],
                    event_at=event_at, protocol=protocol, packet_count=counts[0],
                    bytes_in=counts[1], bytes_out=counts[2], severity_score=score, details=details)
                if result.incident_id is not None:
                    flash(f'Simulated event #{result.event_id}, threshold alert #{result.alert_id} and incident #{result.incident_id} saved or retrieved from Oracle. Repeated source keys reuse the same incident.', 'success')
                    return redirect(url_for('incident_detail', incident_id=result.incident_id))
                flash(f'Simulated event #{result.event_id} saved in Oracle. Score was below the configured threshold; no alert or incident created.', 'success')
                return redirect(url_for('event_detail',event_id=result.event_id))
            except Exception as exc:
                app.logger.exception('Oracle event ingestion failed')
                workflow_error(exc,'Oracle could not complete simulator ingestion and incident creation. The transaction was rolled back; no new event, alert or incident was confirmed.')
        return render_template('event_form.html',
            servers=safe_read(f"SELECT server_id,hostname FROM {obj('server')} WHERE is_active=1 ORDER BY hostname"),
            ips=safe_read(f"SELECT ip_id,ip_text FROM {obj('ip_address')} ORDER BY ip_text"),
            attack_types=safe_read(f"SELECT attack_type_id,name FROM {obj('attack_type')} ORDER BY name"),
            policy=safe_one(f"SELECT number_value FROM {obj('soc_policy')} WHERE policy_key='alert_threshold'"),
            source_key='ui-'+secrets.token_hex(16),event_at=datetime.now(timezone.utc).isoformat(timespec='microseconds'))

    @app.post('/assignments/<int:assignment_id>/end')
    @roles_required('ADMIN','MANAGER')
    def end_assignment(assignment_id):
        reason = request.form.get('reason','').strip()
        if not reason or len(reason)>1000: abort(400,description='An ending reason of at most 1000 characters is required.')
        try:
            call_proc('sp_end_assignment',[actor_id(),assignment_id,reason],actor_id())
            flash('Assignment ended in Oracle.','success')
        except Exception as exc:
            workflow_error(exc,'Oracle rejected ending this assignment.')
        return redirect(url_for('assignments'))

    @app.post('/evidence/<int:evidence_id>/analysis')
    @roles_required('ADMIN','ANALYST')
    def add_analysis(evidence_id):
        evidence = safe_one(f"SELECT incident_id FROM {obj('evidence')} WHERE evidence_id=:evidence_id",{'evidence_id':evidence_id})
        if not evidence: abort(404)
        require_case(evidence['incident_id'],write=True)
        technique = request.form.get('technique','').strip()
        findings = request.form.get('findings','').strip()
        try:
            confidence = Decimal(request.form.get('confidence',''))
            if not confidence.is_finite() or not 0 <= confidence <= 100 or confidence != confidence.quantize(Decimal('.01')): raise ValueError
            if not technique or len(technique)>120 or not findings: raise ValueError
        except (InvalidOperation,ValueError):
            abort(400,description='Technique, findings and confidence from 0 to 100 (up to two decimals) are required.')
        try:
            call_proc('sp_add_analysis',[actor_id(),evidence_id,None,technique,findings,request.form.get('indicators','').strip() or None,confidence,None],actor_id(),(7,))
            flash('Forensic analysis saved in Oracle.','success')
        except Exception as exc:
            workflow_error(exc,'Oracle rejected analysis. An active investigator profile is required.')
        return redirect(url_for('evidence_detail',evidence_id=evidence_id))
