import csv
import hashlib
import io
import os
import secrets
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from werkzeug.security import check_password_hash
from flask import has_request_context
from flask import (
    Flask, abort, flash, redirect, render_template, request, send_file,
    session, url_for, Response
)
import oracledb
from dotenv import load_dotenv
from db import get_connection, close_pool

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(BASE_DIR / "uploads"))).resolve()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "")
if not app.secret_key:
    app.secret_key = secrets.token_hex(32)
    app.logger.warning("FLASK_SECRET_KEY is unset. Set a persistent secret before deployment.")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
)

ROLES = {"ADMIN", "MANAGER", "ANALYST", "AUDITOR"}
OWNER = os.getenv("ORACLE_SCHEMA", "CS_OWNER").upper()
if OWNER != "CS_OWNER":
    raise RuntimeError("CyberShield must use the existing CS_OWNER Oracle schema.")
def obj(name):
    if not name.replace("_", "").isalnum():
        raise ValueError("Invalid Oracle object")
    return f"{OWNER}.{name.upper()}"

def row_dicts(cursor, rows):
    names = [d[0].lower() for d in (cursor.description or [])]
    result = []
    for row in rows:
        item = {}
        for key, value in zip(names, row):
            if hasattr(value, "read"):
                value = value.read()
            item[key] = value
        result.append(item)
    return result

def query_all(sql, params=None):
    con = get_connection()
    cur = None
    try:
        con.client_identifier = str(actor_id()) if actor_id() is not None else None
        cur = con.cursor()
        cur.execute(sql, params or {})
        return row_dicts(cur, cur.fetchall())
    finally:
        if cur is not None:
            cur.close()
        try:
            con.client_identifier = None
        finally:
            con.close()

def query_one(sql, params=None):
    rows = query_all(sql, params)
    return rows[0] if rows else None

def call_proc(name, params, actor=None, out_positions=()):
    if not name.replace("_", "").isalnum():
        raise ValueError("Invalid procedure")
    if actor is None:
        raise PermissionError("Authenticated actor required")
    con = get_connection()
    cur = None
    try:
        if actor is not None:
            con.client_identifier = str(actor)
        cur = con.cursor()
        for pos, value in enumerate(params):
            if isinstance(value, datetime) and value.tzinfo is not None:
                timestamp = cur.var(oracledb.DB_TYPE_TIMESTAMP_TZ)
                timestamp.setvalue(0, value)
                params[pos] = timestamp
        for pos in out_positions:
            params[pos] = cur.var(oracledb.NUMBER)
        cur.callproc(obj(name), params)
        result = {pos: params[pos].getvalue() for pos in out_positions}
        con.commit()
        return result
    except Exception:
        con.rollback()
        raise
    finally:
        if cur is not None:
            cur.close()
        try:
            con.client_identifier = None
        finally:
            con.close()

def current_user():
    return session.get("me") if has_request_context() else None

def actor_id():
    user = current_user()
    return user.get("user_id") if user else None

def role():
    user = current_user()
    return user.get("role_code", "").upper() if user else None

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped

def roles_required(*allowed):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not current_user():
                return redirect(url_for("login", next=request.path))
            if role() not in set(allowed):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorate

@app.before_request
def csrf_guard():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        token = session.get("_csrf")
        submitted = request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
        if not token or not submitted or not secrets.compare_digest(token, submitted):
            abort(400, description="Invalid or missing CSRF token.")

@app.before_request
def refresh_actor():
    if current_user():
        user = safe_one(f"SELECT user_id,full_name,email,role_code,is_active FROM {obj('app_user')} WHERE user_id=:target_user_id", {"target_user_id": actor_id()})
        if not user or user['is_active'] != 1 or user['role_code'] not in ROLES:
            session.clear()
            abort(403)
        session['me'] = dict(user, user_id=int(user['user_id']), role=user['role_code'].lower())

@app.context_processor
def template_context():
    return {"me": current_user() or {}, "csrf_token": session.get("_csrf", ""), "page_url": page_url}

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You are not allowed to perform this action."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="The requested record was not found."), 404

@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message=getattr(e, "description", "Invalid request.")), 400

@app.errorhandler(413)
def too_large(_):
    return render_template("error.html", code=413, message="Uploads must be 10 MiB or smaller."), 413

@app.errorhandler(Exception)
def unexpected(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return render_template("error.html", code=e.code or 500, message=e.description), e.code or 500
    app.logger.exception("Unhandled application error")
    return render_template("error.html", code=500, message="An unexpected error occurred. Check server logs."), 500

def safe_read(sql, params=None):
    try:
        return query_all(sql, params)
    except Exception:
        app.logger.exception("Oracle read failed")
        abort(503, description="Oracle data is temporarily unavailable. Verify the database connection, grants and installed schema.")

def safe_one(sql, params=None):
    rows = safe_read(sql, params)
    return rows[0] if rows else None

def page_url(page):
    args = request.args.to_dict()
    args["page"] = page
    return url_for(request.endpoint, **args)

def filter_context():
    return {"q": request.args.get("q", "").strip(), "status": request.args.get("status", "").strip(), "severity": request.args.get("severity", "").strip()}

def paged(items):
    page = max(1, request.args.get("page", default=1, type=int))
    size = 25
    total = len(items)
    pages = max(1, (total + size - 1) // size)
    return items[(page-1)*size:page*size], {"page": page, "pages": pages, "total": total}


def case_scope(column, write=False):
    if role() != 'ANALYST':
        return '1=1', {}
    active = 'AND c.ended_at IS NULL AND a.ended_at IS NULL' if write else ''
    return f"""EXISTS (SELECT 1 FROM {obj('incident_assignment')} a
        JOIN {obj('investigation_cycle')} c ON c.cycle_id=a.cycle_id
        JOIN {obj('investigator')} inv ON inv.investigator_id=a.investigator_id
        WHERE c.incident_id={column} AND inv.user_id=:scope_actor
        AND inv.availability <> 'INACTIVE' {active})""", {'scope_actor': actor_id()}

def require_case(incident_id, write=False):
    if write and role() not in {'ADMIN','ANALYST'}:
        abort(403)
    scope, binds = case_scope('i.incident_id', write)
    binds['case_id'] = incident_id
    if not safe_one(f"SELECT i.incident_id FROM {obj('incident')} i WHERE i.incident_id=:case_id AND {scope}", binds):
        abort(403 if role() == 'ANALYST' else 404)

def filtered_read(sql, search=(), status=None, severity=None, date=None, scope=None):
    clauses, binds = ['1=1'], {}
    if ':scope_actor' in sql:
        binds['scope_actor'] = actor_id()
    if scope:
        clause, values = case_scope(scope)
        clauses.append(clause)
        binds.update(values)
    q = request.args.get('q','').strip()
    if q and search:
        clauses.append('(' + ' OR '.join(f"LOWER({col}) LIKE :search_text ESCAPE '\\'" for col in search) + ')')
        binds['search_text'] = '%' + q.lower().replace('\\','\\\\').replace('%','\\%').replace('_','\\_') + '%'
    for param, column in [('status',status),('severity',severity)]:
        value = request.args.get(param,'').strip().upper()
        if value and column:
            clauses.append(f'{column}=:{param}_filter')
            binds[param+'_filter'] = value
    if request.args.get('from') and request.args.get('to') and request.args['from'] > request.args['to']:
        abort(400, description='From date must precede To date.')
    if date:
        date = f'SYS_EXTRACT_UTC({date})'
        for param, op in [('from','>='),('to','<')]:
            value = request.args.get(param,'').strip()
            if value:
                try:
                    parsed = datetime.strptime(value,'%Y-%m-%d')
                except ValueError:
                    abort(400, description='Dates must use YYYY-MM-DD.')
                clauses.append(f"{date} {op} :date_{param}" + (" + INTERVAL '1' DAY" if param == 'to' else ''))
                binds['date_'+param] = parsed
    if request.endpoint == 'events':
        for field, op in [('min_score','>='),('max_score','<=')]:
            value = request.args.get(field,'').strip()
            if value:
                try:
                    score = Decimal(value)
                    if not score.is_finite() or not 0 <= score <= 100: raise ValueError
                except (ValueError, InvalidOperation):
                    abort(400,description='Score filters must be from 0 to 100.')
                clauses.append(f'severity_score {op} :{field}')
                binds[field] = score
    return safe_read(f"SELECT * FROM ({sql}) records WHERE " + ' AND '.join(clauses), binds)


def alert_scope(alias='a'):
    if role() != 'ANALYST': return '1=1'
    scope, _ = case_scope('ia.incident_id')
    return f"EXISTS (SELECT 1 FROM {obj('incident_alert')} ia WHERE ia.alert_id={alias}.alert_id AND {scope})"

def event_scope():
    if role() != 'ANALYST': return '1=1'
    return f"EXISTS (SELECT 1 FROM {obj('alert')} scoped_alert WHERE scoped_alert.event_id=e.event_id AND {alert_scope('scoped_alert')})"

def workflow_error(exc, fallback):
    # Expose only reviewed application-error messages, never raw driver/SQL details.
    code = getattr(exc.args[0], 'code', None) if exc.args else None
    messages = {20001:'The requested Oracle record was not found.',
        20002:'An active eligible investigator profile is required.',
        20003:'Custody changed. Refresh before retrying.',
        20004:'This operation is not valid at the current lifecycle stage. Follow OPEN -> TRIAGED -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED.',
        20005:'This investigation cycle already has a resolution.',
        20006:'Record a response action before resolving the incident.',
        20007:'Oracle denied permission for this operation.',
        20009:'This source key or alert has already been used. Refresh the existing record.',
        20010:'Oracle rejected the fields. Check required values, lengths and assignment eligibility.',
        20011:'This incident already has an active lead investigator.'}
    abort(409, description=messages.get(code, fallback))


@app.get("/")
def home():
    if not current_user():
        return redirect(url_for("login"))
    return dashboard()

@app.route("/login", methods=["GET", "POST"])
def login():
    session.setdefault("_csrf", secrets.token_urlsafe(32))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        try:
            user = query_one(
                f"SELECT user_id, email, password_hash, full_name, role_code, is_active FROM {obj('app_user')} WHERE LOWER(email)=:email",
                {"email": email},
            )
        except Exception:
            app.logger.exception("Oracle login lookup failed")
            abort(503, description="Cannot access the Oracle user table. Check the runtime account and schema grants.")
        if not user or int(user.get("is_active") or 0) != 1 or not check_password_hash(str(user["password_hash"]), password):
            flash("Email or password is incorrect.", "error")
            return render_template("login.html"), 401
        role_code = str(user["role_code"]).upper()
        if role_code not in ROLES:
            flash("This account has an unsupported role.", "error")
            return render_template("login.html"), 403
        session.clear()
        session["_csrf"] = secrets.token_urlsafe(32)
        session["me"] = {
            "user_id": int(user["user_id"]), "email": user["email"],
            "full_name": user["full_name"], "role_code": role_code,
            "role": role_code.lower()
        }
        try:
            con = get_connection()
            try:
                con.client_identifier = str(user["user_id"])
                con.commit()
            finally:
                con.client_identifier = None
                con.close()
        except Exception:
            app.logger.warning("Could not initialize database session actor context after login", exc_info=True)
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/health")
def health():
    try:
        row = query_one("SELECT 1 AS ok FROM dual")
        return {"status": "ok", "oracle": bool(row and row.get("ok") == 1)}
    except Exception:
        app.logger.exception("Oracle health check failed")
        return {"status": "unavailable", "oracle": False}, 503

@app.get("/dashboard")
@login_required
def dashboard():
    if role() == 'ANALYST':
        scope, binds = case_scope('i.incident_id')
        rows = safe_read(f"SELECT i.* FROM {obj('incident')} i WHERE {scope} ORDER BY opened_at DESC",binds)
        return render_template('analyst_dashboard.html',items=rows)
    summary = safe_one(f"SELECT * FROM {obj('vw_dashboard_summary')}")
    recent = safe_read(
        f"""SELECT e.event_id, e.event_at, s.hostname, ip.ip_text AS source_ip,
                   at.name AS attack_type, e.severity_score, e.is_simulated
            FROM {obj('security_event')} e
            JOIN {obj('server')} s ON s.server_id=e.server_id
            JOIN {obj('ip_address')} ip ON ip.ip_id=e.source_ip_id
            JOIN {obj('attack_type')} at ON at.attack_type_id=e.attack_type_id
            ORDER BY e.event_at DESC FETCH FIRST 8 ROWS ONLY"""
    )
    incidents = safe_read(f"SELECT * FROM {obj('vw_open_incidents')} ORDER BY opened_at DESC FETCH FIRST 8 ROWS ONLY")
    return render_template("dashboard.html", summary=summary or {}, recent_events=recent, recent_incidents=incidents)

@app.get("/servers")
@roles_required("ADMIN", "MANAGER", "AUDITOR")
def servers():
    items = filtered_read(f"SELECT server_id, hostname, os_name, department, criticality, is_active FROM {obj('server')} ORDER BY hostname", search=('hostname','os_name','department'), status=None, severity='criticality', date=None, scope=None)
    items, pagination = paged(items)
    return render_template("servers.html", items=items, pagination=pagination, filters=filter_context())

@app.get("/events")
@login_required
def events():
    items = filtered_read(f"""SELECT e.event_id,e.event_at,s.hostname,ip.ip_text AS source_ip,
        at.name AS attack_type,e.severity_score,e.is_simulated,e.protocol,e.packet_count,e.bytes_in,e.bytes_out
        FROM {obj('security_event')} e JOIN {obj('server')} s ON s.server_id=e.server_id
        JOIN {obj('ip_address')} ip ON ip.ip_id=e.source_ip_id
        JOIN {obj('attack_type')} at ON at.attack_type_id=e.attack_type_id WHERE {event_scope()} ORDER BY e.event_at DESC""", search=('hostname','source_ip','attack_type','TO_CHAR(event_id)'), status=None, severity=None, date='event_at', scope=None)
    items, pagination = paged(items)
    return render_template("events.html", items=items, pagination=pagination, filters=filter_context())

@app.get("/events/<int:event_id>")
@login_required
def event_detail(event_id):
    event = safe_one(f"""SELECT e.*,s.hostname,ip.ip_text AS source_ip,at.name AS attack_type_name
        FROM {obj('security_event')} e JOIN {obj('server')} s ON s.server_id=e.server_id
        JOIN {obj('ip_address')} ip ON ip.ip_id=e.source_ip_id JOIN {obj('attack_type')} at ON at.attack_type_id=e.attack_type_id
        WHERE e.event_id=:id""", {"id": event_id})
    if not event: abort(404)
    if role() == 'ANALYST':
        scoped = safe_one(f"SELECT e.event_id FROM {obj('security_event')} e WHERE e.event_id=:event_id AND {event_scope()}", {'event_id':event_id,'scope_actor':actor_id()})
        if not scoped: abort(403)
    alert = safe_one(f"SELECT * FROM {obj('alert')} WHERE event_id=:id", {"id": event_id})
    linked_case = safe_one(f"SELECT incident_id FROM {obj('incident_alert')} WHERE alert_id=:alert_id", {'alert_id':alert['alert_id']}) if alert else None
    return render_template('event_detail.html',event=event,alert=alert,linked_case=linked_case)

@app.get("/alerts")
@login_required
def alerts():
    items = filtered_read(f"""SELECT a.alert_id,a.event_id,s.hostname,a.severity,a.status,a.created_at,a.acknowledged_at,a.triage_note,
        (SELECT MAX(ia.incident_id) FROM {obj('incident_alert')} ia WHERE ia.alert_id=a.alert_id) AS incident_id
        FROM {obj('alert')} a JOIN {obj('security_event')} e ON e.event_id=a.event_id
        JOIN {obj('server')} s ON s.server_id=e.server_id WHERE {alert_scope()} ORDER BY a.created_at DESC""", search=('hostname','TO_CHAR(alert_id)','TO_CHAR(event_id)'), status='status', severity='severity', date='created_at', scope=None)
    items, pagination = paged(items)
    return render_template("alerts.html", items=items, pagination=pagination, filters=filter_context())

@app.post("/alerts/<int:alert_id>/triage")
@roles_required("ADMIN", "ANALYST")
def triage_alert(alert_id):
    if role() == 'ANALYST':
        linked = safe_read(f"SELECT incident_id FROM {obj('incident_alert')} WHERE alert_id=:alert_id", {'alert_id':alert_id})
        if not linked: abort(403)
        for case in linked: require_case(case['incident_id'], write=True)
    status = request.form.get("status", "ACKNOWLEDGED").upper()
    note = request.form.get("note", "").strip()
    if status not in {"ACKNOWLEDGED", "ESCALATED", "DISMISSED"} or not note or len(note)>1000:
        abort(400, description="Invalid alert status.")
    try:
        call_proc("sp_triage_alert", [actor_id(), alert_id, status, note], actor_id())
        flash("Alert triage saved.", "success")
    except Exception as exc:
        app.logger.exception("Alert triage procedure failed")
        workflow_error(exc, "Oracle rejected the triage operation or the procedure is unavailable.")
    return redirect(url_for("alerts"))

@app.get("/incidents")
@login_required
def incidents():
    items = filtered_read(f"""SELECT i.*,u.full_name AS lead_name FROM {obj('incident')} i
        LEFT JOIN {obj('investigation_cycle')} c ON c.incident_id=i.incident_id AND c.ended_at IS NULL
        LEFT JOIN {obj('incident_assignment')} a ON a.cycle_id=c.cycle_id AND a.ended_at IS NULL AND a.assignment_role='LEAD'
        LEFT JOIN {obj('investigator')} inv ON inv.investigator_id=a.investigator_id
        LEFT JOIN {obj('app_user')} u ON u.user_id=inv.user_id ORDER BY i.opened_at DESC""",
        search=('title','TO_CHAR(incident_id)','lead_name'),status='status',severity='severity',date='opened_at',scope='records.incident_id')
    items, pagination = paged(items)
    return render_template('incidents.html',items=items,pagination=pagination,filters=filter_context())

@app.route("/incidents/new", methods=["GET", "POST"])
@roles_required("ADMIN")
def new_incident():
    if request.method == "POST":
        alert_id = request.form.get("alert_id", type=int)
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "").upper()
        campaign_id = request.form.get("campaign_id", type=int)
        if not alert_id or not title or len(title)>200 or not description or severity not in {"LOW","MEDIUM","HIGH","CRITICAL"}:
            flash("Alert, title, description and valid severity are required.", "error")
            return redirect(url_for("new_incident"))
        params = [actor_id(), alert_id, title, description, severity, campaign_id, None]
        try:
            result = call_proc("sp_create_incident", params, actor_id(), out_positions=(6,))
            flash(f"Incident #{result[6]} created.", "success")
            return redirect(url_for('incident_detail',incident_id=int(result[6])))
        except Exception as exc:
            app.logger.exception('Incident creation procedure failed')
            workflow_error(exc,'Oracle rejected incident creation. Check alert eligibility and procedure grants.')
    alerts_data = safe_read(f"SELECT alert_id,severity,status FROM {obj('alert')} a WHERE status <> 'DISMISSED' AND NOT EXISTS (SELECT 1 FROM {obj('incident_alert')} ia WHERE ia.alert_id=a.alert_id) ORDER BY created_at DESC")
    campaigns = safe_read(f"SELECT campaign_id,name FROM {obj('attack_campaign')} ORDER BY name")
    return render_template("incident_form.html", alerts=alerts_data, campaigns=campaigns)

@app.get("/incidents/<int:incident_id>")
@login_required
def incident_detail(incident_id):
    require_case(incident_id, write=False)
    incident = safe_one(f"""SELECT i.*, u.full_name AS creator_name, c.cycle_id,c.cycle_no
        FROM {obj('incident')} i JOIN {obj('app_user')} u ON u.user_id=i.created_by
        LEFT JOIN {obj('investigation_cycle')} c ON c.incident_id=i.incident_id AND c.ended_at IS NULL
        WHERE i.incident_id=:id""", {"id": incident_id})
    if not incident: abort(404)
    actions = safe_read(f"""SELECT ra.*,u.full_name AS performer_name FROM {obj('response_action')} ra
        JOIN {obj('app_user')} u ON u.user_id=ra.performed_by
        LEFT JOIN {obj('investigation_cycle')} c ON c.cycle_id=ra.cycle_id
        WHERE c.incident_id=:id ORDER BY ra.performed_at DESC""", {"id": incident_id})
    linked_events = safe_read(f"""SELECT a.alert_id,a.status AS alert_status,e.event_id,e.event_at,e.details,s.hostname,ip.ip_text,at.name AS attack_type
        FROM {obj('incident_alert')} ia JOIN {obj('alert')} a ON a.alert_id=ia.alert_id
        JOIN {obj('security_event')} e ON e.event_id=a.event_id JOIN {obj('server')} s ON s.server_id=e.server_id
        JOIN {obj('ip_address')} ip ON ip.ip_id=e.source_ip_id JOIN {obj('attack_type')} at ON at.attack_type_id=e.attack_type_id
        WHERE ia.incident_id=:id ORDER BY e.event_at DESC""", {'id':incident_id})
    history = safe_read(f"""SELECT h.*,u.full_name FROM {obj('incident_status_history')} h
        JOIN {obj('investigation_cycle')} c ON c.cycle_id=h.cycle_id JOIN {obj('app_user')} u ON u.user_id=h.changed_by
        WHERE c.incident_id=:id ORDER BY h.changed_at,h.history_id""", {'id':incident_id})
    assigned = safe_read(f"""SELECT a.*,u.full_name FROM {obj('incident_assignment')} a
        JOIN {obj('investigation_cycle')} c ON c.cycle_id=a.cycle_id JOIN {obj('investigator')} inv ON inv.investigator_id=a.investigator_id
        JOIN {obj('app_user')} u ON u.user_id=inv.user_id WHERE c.incident_id=:id AND c.ended_at IS NULL AND a.ended_at IS NULL""", {'id':incident_id})
    case_evidence = safe_read(f"SELECT * FROM {obj('evidence')} WHERE incident_id=:id ORDER BY collected_at DESC", {'id':incident_id})
    analyses = safe_read(f"SELECT f.* FROM {obj('forensic_analysis')} f JOIN {obj('evidence')} e ON e.evidence_id=f.evidence_id WHERE e.incident_id=:id ORDER BY f.created_at DESC", {'id':incident_id})
    resolutions = safe_read(f"SELECT r.* FROM {obj('resolution')} r JOIN {obj('investigation_cycle')} c ON c.cycle_id=r.cycle_id WHERE c.incident_id=:id ORDER BY r.resolved_at DESC", {'id':incident_id})
    write_scope, write_binds = case_scope('i.incident_id', True)
    write_binds['id'] = incident_id
    can_write = role() in {'ADMIN','ANALYST'} and bool(safe_one(f"SELECT 1 AS ok FROM {obj('incident')} i WHERE i.incident_id=:id AND {write_scope}",write_binds))
    next_status = {'OPEN':'TRIAGED','TRIAGED':'INVESTIGATING','INVESTIGATING':'CONTAINED','RESOLVED':'CLOSED'}.get(incident['status'])
    messages = []
    incident = dict(incident)
    incident["summary"] = incident.get("title")
    incident["details"] = incident.get("description")
    incident["customer_name"] = incident.get("creator_name")
    return render_template("incident_detail.html", incident=incident, actions=actions, messages=messages, linked_events=linked_events, history=history, assigned=assigned, case_evidence=case_evidence, analyses=analyses, resolutions=resolutions, can_write=can_write, next_status=next_status)

@app.post("/incidents/<int:incident_id>/status")
@roles_required("ADMIN", "ANALYST")
def change_incident_status(incident_id):
    require_case(incident_id, write=True)
    to_status = request.form.get("status", "").upper()
    reason = request.form.get("reason", "").strip()
    if to_status not in {"TRIAGED", "INVESTIGATING", "CONTAINED", "CLOSED"} or not reason or len(reason)>1000:
        abort(400, description="A valid target status and reason of up to 1000 characters are required.")
    try:
        call_proc("sp_change_status", [actor_id(), incident_id, to_status, reason], actor_id())
        flash("Incident status updated.", "success")
    except Exception as exc:
        app.logger.exception("Status change failed")
        workflow_error(exc, "Oracle rejected the status transition.")
    return redirect(url_for("incident_detail", incident_id=incident_id))

@app.post("/incidents/<int:incident_id>/action")
@roles_required("ADMIN", "ANALYST")
def add_action(incident_id):
    require_case(incident_id, write=True)
    action_type = request.form.get("action_type", "").strip()
    description = request.form.get("description", "").strip()
    outcome = request.form.get("outcome", "").strip() or "Recorded"
    if not action_type or len(action_type)>80 or not description or len(outcome)>1000:
        abort(400, description="Action type and description are required.")
    try:
        call_proc("sp_record_action", [actor_id(), incident_id, action_type, description, outcome, None], actor_id(), (5,))
        flash("Response action recorded.", "success")
    except Exception as exc:
        app.logger.exception("Response action failed")
        workflow_error(exc, "Oracle rejected the response action. Check incident status and access.")
    return redirect(url_for("incident_detail", incident_id=incident_id))

@app.post("/incidents/<int:incident_id>/resolve")
@roles_required("ADMIN", "ANALYST")
def resolve_incident(incident_id):
    require_case(incident_id, write=True)
    summary = request.form.get("summary", "").strip()
    root_cause = request.form.get("root_cause", "").strip()
    lessons = request.form.get("lessons_learned", "").strip() or None
    loss = request.form.get("financial_loss", default="0").strip()
    try:
        loss = Decimal(loss)
        if not summary or not root_cause or not loss.is_finite() or loss < 0 or loss >= Decimal("1e12") or loss != loss.quantize(Decimal("0.01")):
            raise ValueError
        call_proc("sp_resolve_incident", [actor_id(), incident_id, summary, root_cause, lessons, loss, None], actor_id(), (6,))
        flash("Incident resolution recorded.", "success")
    except (ValueError, InvalidOperation):
        abort(400, description="Summary, root cause and a non-negative financial loss with at most two decimal places are required.")
    except Exception as exc:
        app.logger.exception("Incident resolution failed")
        workflow_error(exc, "Oracle rejected resolution. The incident may need containment and a response action first.")
    return redirect(url_for("incident_detail", incident_id=incident_id))

@app.post("/incidents/<int:incident_id>/reopen")
@roles_required("ADMIN", "MANAGER")
def reopen_incident(incident_id):
    reason = request.form.get("reason", "").strip()
    if not reason:
        abort(400, description="A reopening reason is required.")
    try:
        call_proc("sp_reopen_incident", [actor_id(), incident_id, reason, None], actor_id(), (3,))
        flash("Incident reopened into a new investigation cycle.", "success")
    except Exception as exc:
        app.logger.exception("Incident reopening failed")
        workflow_error(exc, "Oracle rejected reopening.")
    return redirect(url_for("incident_detail", incident_id=incident_id))

@app.get("/assignments")
@roles_required("ADMIN", "MANAGER", "AUDITOR")
def assignments():
    items = filtered_read(f"SELECT * FROM {obj('vw_investigator_workload')} ORDER BY full_name",search=('full_name','TO_CHAR(investigator_id)'),status='availability')
    queue = safe_read(f"SELECT * FROM {obj('vw_open_incidents')} ORDER BY opened_at DESC")
    investigators = safe_read(f"""SELECT inv.investigator_id,u.full_name FROM {obj('investigator')} inv
        JOIN {obj('app_user')} u ON u.user_id=inv.user_id WHERE inv.availability <> 'INACTIVE' AND u.is_active=1
        AND u.role_code IN ('ADMIN','ANALYST') ORDER BY u.full_name""")
    return render_template('assignments.html',items=items,filters=filter_context(),queue=queue,investigators=investigators)

@app.post("/assignments")
@roles_required("ADMIN", "MANAGER")
def create_assignment():
    incident_id = request.form.get("incident_id", type=int)
    investigator_id = request.form.get("investigator_id", type=int)
    assignment_role = request.form.get("assignment_role", "LEAD").upper()
    if not incident_id or not investigator_id or assignment_role not in {"LEAD", "SUPPORT"}:
        abort(400, description="Incident, investigator and assignment role are required.")
    try:
        call_proc("sp_assign_investigator", [actor_id(), incident_id, investigator_id, assignment_role, None], actor_id(), (4,))
        flash("Investigator assigned.", "success")
    except Exception as exc:
        app.logger.exception("Assignment procedure failed")
        workflow_error(exc, "Oracle rejected the assignment.")
    return redirect(url_for("assignments"))

@app.get("/evidence")
@login_required
def evidence_list():
    items = filtered_read(f"""SELECT e.evidence_id,e.incident_id,e.evidence_type,e.original_name,e.sha256,e.sensitivity,
        e.file_size AS size_bytes,e.collected_at,u.full_name AS collector_name,e.current_custodian_id
        FROM {obj('evidence')} e JOIN {obj('investigator')} collector ON collector.investigator_id=e.collected_by JOIN {obj('app_user')} u ON u.user_id=collector.user_id ORDER BY e.collected_at DESC""", search=('original_name','evidence_type','collector_name','TO_CHAR(incident_id)'), status=None, severity=None, date='collected_at', scope='records.incident_id')
    return render_template("evidence.html", items=items, filters=filter_context())

@app.route("/evidence/upload", methods=["GET", "POST"])
@roles_required("ADMIN", "ANALYST")
def upload_evidence():
    if request.method == "POST":
        file = request.files.get("file")
        incident_id = request.form.get("incident_id", type=int)
        evidence_type = request.form.get("evidence_type", "LOG").strip().upper()
        sensitivity = request.form.get("sensitivity", "INTERNAL").strip().upper()
        if not file or not file.filename or not incident_id:
            abort(400, description="Incident and file are required.")
        allowed_sensitivity = {"INTERNAL","RESTRICTED"}
        if sensitivity not in allowed_sensitivity:
            abort(400, description="Invalid sensitivity.")
        require_case(incident_id, write=True)
        raw = file.read()
        if not raw or len(raw) > 10 * 1024 * 1024:
            abort(400, description="File must be non-empty and no larger than 10 MiB.")
        storage_key = secrets.token_hex(24)
        path = (UPLOAD_DIR / storage_key).resolve()
        if UPLOAD_DIR not in path.parents:
            abort(400)
        sha = hashlib.sha256(raw).hexdigest()
        try:
            path.write_bytes(raw)
            now = datetime.now(timezone.utc)
            call_proc("sp_register_evidence", [actor_id(), incident_id, evidence_type, storage_key, file.filename[:255], now, sha, len(raw), sensitivity, None], actor_id(), (9,))
            flash("Evidence registered.", "success")
            return redirect(url_for("evidence_list"))
        except Exception:
            path.unlink(missing_ok=True)
            app.logger.exception("Evidence registration failed")
            abort(409, description="Oracle rejected evidence registration. No evidence record was confirmed.")
    scope, binds = case_scope('i.incident_id', True)
    incidents_data = safe_read(f"SELECT incident_id,title,status FROM {obj('incident')} i WHERE status NOT IN ('RESOLVED','CLOSED') AND {scope} ORDER BY opened_at DESC", binds)
    return render_template("form.html", title="Register evidence", fields=[], submit_label="Register evidence", incidents=incidents_data, upload=True)

@app.get("/evidence/<int:evidence_id>")
@login_required
def evidence_detail(evidence_id):
    evidence = safe_one(f"""SELECT e.*,u.full_name AS collector_name,
        (SELECT u2.full_name FROM {obj('investigator')} inv JOIN {obj('app_user')} u2 ON u2.user_id=inv.user_id
         WHERE inv.investigator_id=e.current_custodian_id) AS current_custodian_name
        FROM {obj('evidence')} e JOIN {obj('investigator')} collector ON collector.investigator_id=e.collected_by JOIN {obj('app_user')} u ON u.user_id=collector.user_id WHERE e.evidence_id=:id""", {"id": evidence_id})
    if not evidence: abort(404)
    require_case(evidence["incident_id"])
    custody = safe_read(f"""SELECT * FROM {obj('vw_custody_history')} WHERE evidence_id=:id ORDER BY transferred_at DESC""", {"id": evidence_id})
    analyses = safe_read(f"SELECT * FROM {obj('forensic_analysis')} WHERE evidence_id=:id ORDER BY created_at DESC", {"id": evidence_id})
    scope, binds = case_scope('i.incident_id', True)
    binds['case_id'] = evidence['incident_id']
    can_write = role() in {'ADMIN','ANALYST'} and bool(safe_one(f"SELECT 1 AS ok FROM {obj('incident')} i WHERE i.incident_id=:case_id AND i.status NOT IN ('RESOLVED','CLOSED') AND {scope}", binds))
    return render_template('evidence_detail.html', evidence=evidence, custody=custody, analyses=analyses, can_write=can_write)

@app.get("/evidence/<int:evidence_id>/download")
@login_required
def download_evidence(evidence_id):
    if role() not in {"ADMIN", "ANALYST"}:
        abort(403)
    evidence = safe_one(f"SELECT evidence_id,incident_id,storage_key,original_name FROM {obj('evidence')} WHERE evidence_id=:id", {"id": evidence_id})
    if not evidence: abort(404)
    require_case(evidence["incident_id"])
    if role() == "ANALYST":
        assigned = safe_one(f"""SELECT 1 AS ok FROM {obj('incident_assignment')} a
            JOIN {obj('investigator')} inv ON inv.investigator_id=a.investigator_id
            JOIN {obj('investigation_cycle')} c ON c.cycle_id=a.cycle_id
            WHERE c.incident_id=:iid AND c.ended_at IS NULL AND a.ended_at IS NULL AND inv.user_id=:target_user_id""",
            {"iid": evidence["incident_id"], "target_user_id": actor_id()})
        if not assigned: abort(403)
    path = (UPLOAD_DIR / str(evidence["storage_key"])).resolve()
    if UPLOAD_DIR not in path.parents or not path.is_file(): abort(404)
    return send_file(path, as_attachment=True, download_name=Path(evidence["original_name"]).name)

@app.get("/response")
@login_required
def response():
    items = filtered_read(f"""SELECT a.action_id,c.incident_id,a.action_type,a.performed_at,a.outcome
        FROM {obj('response_action')} a JOIN {obj('investigation_cycle')} c ON c.cycle_id=a.cycle_id
        ORDER BY a.performed_at DESC""", search=('action_type','outcome','TO_CHAR(incident_id)'), status=None, severity=None, date='performed_at', scope='records.incident_id')
    return render_template("response.html", items=items, filters=filter_context())

@app.get("/sla")
@login_required
def sla():
    items = filtered_read(f"SELECT * FROM {obj('vw_sla_status')} ORDER BY response_due_at", search=('TO_CHAR(incident_id)',), status=None, severity=None, date='response_due_at', scope='records.incident_id')
    return render_template("sla.html", items=items, filters=filter_context())

@app.post("/sla/<int:incident_id>/escalate")
@roles_required("ADMIN", "MANAGER")
def escalate_sla(incident_id):
    reason = request.form.get("reason", "").strip()
    if not reason: abort(400, description="Escalation reason is required.")
    try:
        call_proc("sp_escalate_sla", [actor_id(), incident_id, reason], actor_id())
        flash("SLA escalation recorded.", "success")
    except Exception as exc:
        app.logger.exception("SLA escalation failed")
        workflow_error(exc, "Oracle rejected the SLA escalation.")
    return redirect(url_for("sla"))

def report_data():
    items = filtered_read(f"""SELECT i.incident_id,i.title,i.severity,i.status,i.opened_at,c.cycle_no,
        ROUND((CAST(SYS_EXTRACT_UTC(s.acknowledged_at) AS DATE)-CAST(SYS_EXTRACT_UTC(c.started_at) AS DATE))*1440,2) AS mtta_minutes,
        ROUND((CAST(SYS_EXTRACT_UTC(r.resolved_at) AS DATE)-CAST(SYS_EXTRACT_UTC(c.started_at) AS DATE))*1440,2) AS mttr_minutes
        FROM {obj('incident')} i JOIN {obj('investigation_cycle')} c ON c.incident_id=i.incident_id
        LEFT JOIN {obj('sla')} s ON s.cycle_id=c.cycle_id
        LEFT JOIN {obj('resolution')} r ON r.cycle_id=c.cycle_id ORDER BY i.opened_at DESC,c.cycle_no""",date='opened_at')
    def mean(field):
        values=[row[field] for row in items if row[field] is not None]
        return round(sum(values)/len(values),2) if values else None
    cases={row['incident_id']:row['status'] for row in items}
    return items, {'mtta_minutes':mean('mtta_minutes'),'mttr_minutes':mean('mttr_minutes'),
        'closure_rate':round(100*sum(status=='CLOSED' for status in cases.values())/len(cases),2) if cases else None}

@app.get("/reports")
@roles_required("ADMIN", "MANAGER", "AUDITOR")
def reports():
    items, metrics = report_data()
    return render_template('reports.html',items=items,metrics=metrics,filters={'from':request.args.get('from',''),'to':request.args.get('to','')})

@app.get("/reports/export")
@roles_required("ADMIN", "MANAGER", "AUDITOR")
def reports_export():
    items, _ = report_data()
    output = io.StringIO()
    if items:
        writer = csv.DictWriter(output, fieldnames=list(items[0].keys()))
        writer.writeheader()
        writer.writerows(items)
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=cybershield-report.csv"})

@app.get("/audit")
@roles_required("ADMIN", "AUDITOR")
def audit():
    items = filtered_read(f"""SELECT a.audit_id,u.full_name AS actor_name,a.action,a.entity_name AS entity_type,
        a.entity_id,a.occurred_at AS action_time FROM {obj('audit_log')} a
        LEFT JOIN {obj('app_user')} u ON u.user_id=a.actor_user_id ORDER BY a.occurred_at DESC""", search=('actor_name','action','entity_type','TO_CHAR(entity_id)'), status=None, severity=None, date='action_time', scope=None)
    return render_template("audit.html", items=items, filters=filter_context())

@app.get("/threat-intel")
@login_required
def threat_intel():
    actors = safe_read(f"SELECT name,attribution_status,description FROM {obj('threat_actor')} ORDER BY name")
    intelligence = safe_read(f"""SELECT h.title,t.name AS actor_name,a.name AS attack_type_name,h.observed_at,h.confidence
        FROM {obj('historical_threat_intelligence')} h LEFT JOIN {obj('threat_actor')} t ON t.actor_id=h.actor_id
        JOIN {obj('attack_type')} a ON a.attack_type_id=h.attack_type_id ORDER BY h.observed_at DESC""")
    campaigns = safe_read(f"""SELECT c.name,t.name AS actor_name,c.started_at,c.ended_at,c.description
        FROM {obj('attack_campaign')} c LEFT JOIN {obj('threat_actor')} t ON t.actor_id=c.actor_id ORDER BY c.started_at DESC""")
    return render_template("threat_intel.html", actors=actors, intelligence=intelligence, campaigns=campaigns)

@app.get("/settings")
@roles_required("ADMIN")
def settings():
    users = safe_read(f"SELECT user_id,full_name,email,role_code,is_active FROM {obj('app_user')} ORDER BY full_name")
    attack_types = safe_read(f"SELECT name,description FROM {obj('attack_type')} ORDER BY name")
    policies = safe_read(f"SELECT policy_key,number_value,description FROM {obj('soc_policy')} ORDER BY policy_key")
    return render_template("settings.html", users=users, attack_types=attack_types, policies=policies)

@app.get("/admin/users")
@roles_required("ADMIN")
def admin_users():
    users = safe_read(f"SELECT user_id,full_name,email,role_code,is_active FROM {obj('app_user')} ORDER BY full_name")
    return render_template("users.html", users=users, investigators=[])

@app.get("/tables")
@roles_required("ADMIN")
def table_index():
    tables = safe_read("SELECT table_name FROM all_tables WHERE owner=:owner ORDER BY table_name", {"owner": OWNER})
    return render_template("tables.html", tables=[r["table_name"] for r in tables])

@app.get("/table/<table>")
@roles_required("ADMIN")
def list_records(table):
    allowed = {r["table_name"].lower() for r in safe_read("SELECT table_name FROM all_tables WHERE owner=:owner", {"owner": OWNER})}
    if table.lower() not in allowed: abort(404)
    columns = safe_read("SELECT column_name FROM all_tab_columns WHERE owner=:owner AND table_name=:table_name ORDER BY column_id", {'owner':OWNER,'table_name':table.upper()})
    selected = ','.join(r['column_name'] for r in columns if r['column_name'] != 'PASSWORD_HASH')
    records = safe_read(f"SELECT {selected} FROM {obj(table)} FETCH FIRST 100 ROWS ONLY")
    return render_template("list.html", table=table, records=records, columns=list(records[0].keys()) if records else [])

@app.get("/register")
def register():
    abort(403, description="Account self-registration is disabled. Accounts must be provisioned by an authorized administrator.")

@app.get("/health/details")
@roles_required("ADMIN")
def health_details():
    return {"oracle_schema": OWNER, "health_url": url_for("health"), "upload_dir_configured": bool(UPLOAD_DIR)}

from workflow_routes import register_workflows
register_workflows(app, globals())
from asset_routes import register_assets
register_assets(app, globals())

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG", "0") == "1")
