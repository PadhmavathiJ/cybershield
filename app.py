import csv
import hashlib
import io
import os
import secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from werkzeug.security import check_password_hash, generate_password_hash
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
if not OWNER.replace("_", "").isalnum():
    raise RuntimeError("Invalid ORACLE_SCHEMA")
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
        cur = con.cursor()
        cur.execute(sql, params or {})
        return row_dicts(cur, cur.fetchall())
    finally:
        if cur is not None:
            cur.close()
        con.close()

def query_one(sql, params=None):
    rows = query_all(sql, params)
    return rows[0] if rows else None

def call_proc(name, params, actor=None, out_positions=()):
    if not name.replace("_", "").isalnum():
        raise ValueError("Invalid procedure")
    con = get_connection()
    cur = None
    try:
        if actor is not None:
            con.client_identifier = str(actor)
        cur = con.cursor()
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
            con.client_identifier = ""
        finally:
            con.close()

def current_user():
    return session.get("me")

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

@app.context_processor
def template_context():
    return {"me": current_user() or {}, "csrf_token": session.get("_csrf", "")}

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

def filter_context():
    return {"q": request.args.get("q", "").strip(), "status": request.args.get("status", "").strip(), "severity": request.args.get("severity", "").strip()}

def paged(items):
    page = max(1, request.args.get("page", default=1, type=int))
    size = 25
    total = len(items)
    pages = max(1, (total + size - 1) // size)
    return items[(page-1)*size:page*size], {"page": page, "pages": pages, "total": total}

@app.get("/")
def home():
    return redirect(url_for("login"))

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
                con.client_identifier = ""
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

@app.route("/servers", methods=["GET", "POST"])
@roles_required("ADMIN")
def servers():
    if request.method == "POST":
        hostname = request.form.get("hostname", "").strip()
        os_name = request.form.get("os_name", "").strip()
        department = request.form.get("department", "").strip()
        criticality = request.form.get("criticality", "").strip().upper()

        if not hostname:
            flash("Hostname is required.", "error")
            return redirect(url_for("servers"))

        if criticality not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            flash("Select a valid criticality.", "error")
            return redirect(url_for("servers"))

        con = get_connection()
        cur = None
        try:
            cur = con.cursor()
            cur.execute(
                f"SELECT COUNT(*) FROM {obj('server')} WHERE UPPER(hostname)=UPPER(:hostname)",
                {"hostname": hostname}
            )

            if cur.fetchone()[0]:
                flash("A server with this hostname already exists.", "error")
                return redirect(url_for("servers"))

            cur.execute(
                f"""INSERT INTO {obj('server')}
                (hostname, os_name, department, criticality, is_active)
                VALUES (:hostname, :os_name, :department, :criticality, 1)""",
                {
                    "hostname": hostname,
                    "os_name": os_name or None,
                    "department": department or None,
                    "criticality": criticality
                }
            )
            con.commit()
            flash("Server registered successfully in Oracle.", "success")
        except Exception:
            con.rollback()
            app.logger.exception("Server registration failed")
            flash("Server registration failed. Check the Flask terminal for details.", "error")
        finally:
            if cur is not None:
                cur.close()
            con.close()

        return redirect(url_for("servers"))

    items = safe_read(
        f"SELECT server_id, hostname, os_name, department, criticality, is_active "
        f"FROM {obj('server')} ORDER BY hostname"
    )
    items, pagination = paged(items)
    return render_template(
        "servers.html",
        items=items,
        pagination=pagination,
        filters=filter_context()
    )

@app.get("/events")
@login_required
def events():
    items = safe_read(f"""SELECT e.event_id,e.event_at,s.hostname,ip.ip_text AS source_ip,
        at.name AS attack_type,e.severity_score,e.is_simulated,e.protocol,e.packet_count,e.bytes_in,e.bytes_out
        FROM {obj('security_event')} e JOIN {obj('server')} s ON s.server_id=e.server_id
        JOIN {obj('ip_address')} ip ON ip.ip_id=e.source_ip_id
        JOIN {obj('attack_type')} at ON at.attack_type_id=e.attack_type_id ORDER BY e.event_at DESC""")
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
    alert = safe_one(f"SELECT * FROM {obj('alert')} WHERE event_id=:id", {"id": event_id})
    return render_template("event_detail.html", event=event, alert=alert)

@app.get("/alerts")
@login_required
def alerts():
    items = safe_read(f"""SELECT a.alert_id,a.event_id,s.hostname,a.severity,a.status,a.created_at,a.acknowledged_at,a.triage_note
        FROM {obj('alert')} a JOIN {obj('security_event')} e ON e.event_id=a.event_id
        JOIN {obj('server')} s ON s.server_id=e.server_id ORDER BY a.created_at DESC""")
    items, pagination = paged(items)
    return render_template("alerts.html", items=items, pagination=pagination, filters=filter_context())

@app.post("/alerts/<int:alert_id>/triage")
@roles_required("ADMIN", "ANALYST")
def triage_alert(alert_id):
    status = request.form.get("status", "ACKNOWLEDGED").upper()
    note = request.form.get("note", "").strip()
    if status not in {"ACKNOWLEDGED", "ESCALATED", "DISMISSED"}:
        abort(400, description="Invalid alert status.")
    try:
        call_proc("sp_triage_alert", [actor_id(), alert_id, status, note], actor_id())
        flash("Alert triage saved.", "success")
    except Exception:
        app.logger.exception("Alert triage procedure failed")
        abort(409, description="Oracle rejected the triage operation or the procedure is unavailable.")
    return redirect(url_for("alerts"))

@app.get("/incidents")
@login_required
def incidents():
    items = safe_read(f"SELECT * FROM {obj('vw_open_incidents')} ORDER BY opened_at DESC")
    items, pagination = paged(items)
    return render_template("incidents.html", items=items, pagination=pagination, filters=filter_context())

@app.route("/incidents/new", methods=["GET", "POST"])
@roles_required("ADMIN", "MANAGER", "ANALYST")
def new_incident():
    if request.method == "POST":
        alert_id = request.form.get("alert_id", type=int)
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "").upper()
        campaign_id = request.form.get("campaign_id", type=int)
        if not alert_id or not title or not description or severity not in {"LOW","MEDIUM","HIGH","CRITICAL"}:
            flash("Alert, title, description and valid severity are required.", "error")
            return redirect(url_for("new_incident"))
        params = [actor_id(), alert_id, title, description, severity, campaign_id, None]
        try:
            result = call_proc("sp_create_incident", params, actor_id(), out_positions=(6,))
            flash(f"Incident #{result[6]} created.", "success")
            return redirect(url_for("incidents"))
        except Exception:
            app.logger.exception("Incident creation procedure failed")
            abort(409, description="Oracle rejected incident creation. Check alert eligibility, role permissions and procedure grants.")
    alerts_data = safe_read(f"SELECT alert_id,severity,status FROM {obj('alert')} WHERE status <> 'DISMISSED' ORDER BY created_at DESC")
    campaigns = safe_read(f"SELECT campaign_id,name FROM {obj('attack_campaign')} ORDER BY name")
    return render_template("incident_form.html", alerts=alerts_data, campaigns=campaigns)

@app.get("/incidents/<int:incident_id>")
@login_required
def incident_detail(incident_id):
    incident = safe_one(f"""SELECT i.*, u.full_name AS creator_name, c.cycle_id,c.cycle_no
        FROM {obj('incident')} i JOIN {obj('app_user')} u ON u.user_id=i.created_by
        LEFT JOIN {obj('investigation_cycle')} c ON c.incident_id=i.incident_id AND c.ended_at IS NULL
        WHERE i.incident_id=:id""", {"id": incident_id})
    if not incident: abort(404)
    actions = safe_read(f"""SELECT ra.*,u.full_name AS performer_name FROM {obj('response_action')} ra
        JOIN {obj('app_user')} u ON u.user_id=ra.performed_by
        LEFT JOIN {obj('investigation_cycle')} c ON c.cycle_id=ra.cycle_id
        WHERE c.incident_id=:id ORDER BY ra.performed_at DESC""", {"id": incident_id})
    messages = []
    incident = dict(incident)
    incident["summary"] = incident.get("title")
    incident["details"] = incident.get("description")
    incident["customer_name"] = incident.get("creator_name")
    return render_template("incident_detail.html", incident=incident, actions=actions, messages=messages)

@app.post("/incidents/<int:incident_id>/status")
@roles_required("ADMIN", "MANAGER", "ANALYST")
def change_incident_status(incident_id):
    to_status = request.form.get("status", "").upper()
    reason = request.form.get("reason", "").strip()
    if to_status not in {"TRIAGED", "INVESTIGATING", "CONTAINED", "CLOSED"} or not reason:
        abort(400, description="A valid target status and reason are required.")
    try:
        call_proc("sp_change_status", [actor_id(), incident_id, to_status, reason], actor_id())
        flash("Incident status updated.", "success")
    except Exception:
        app.logger.exception("Status change failed")
        abort(409, description="Oracle rejected the status transition.")
    return redirect(url_for("incident_detail", incident_id=incident_id))

@app.post("/incidents/<int:incident_id>/action")
@roles_required("ADMIN", "ANALYST")
def add_action(incident_id):
    action_type = request.form.get("action_type", "").strip()
    description = request.form.get("description", "").strip()
    outcome = request.form.get("outcome", "").strip() or "Recorded"
    if not action_type or not description:
        abort(400, description="Action type and description are required.")
    try:
        call_proc("sp_record_action", [actor_id(), incident_id, action_type, description, outcome, None], actor_id(), (5,))
        flash("Response action recorded.", "success")
    except Exception:
        app.logger.exception("Response action failed")
        abort(409, description="Oracle rejected the response action. Check incident status and access.")
    return redirect(url_for("incident_detail", incident_id=incident_id))

@app.post("/incidents/<int:incident_id>/resolve")
@roles_required("ADMIN", "ANALYST")
def resolve_incident(incident_id):
    summary = request.form.get("summary", "").strip() or "Incident resolved"
    root_cause = request.form.get("root_cause", "").strip()
    lessons = request.form.get("lessons_learned", "").strip() or None
    loss = request.form.get("financial_loss", default="0").strip()
    try:
        loss = float(loss)
        if not root_cause or loss < 0:
            raise ValueError
        call_proc("sp_resolve_incident", [actor_id(), incident_id, summary, root_cause, lessons, loss, None], actor_id(), (6,))
        flash("Incident resolution recorded.", "success")
    except ValueError:
        abort(400, description="Root cause and a non-negative financial loss are required.")
    except Exception:
        app.logger.exception("Incident resolution failed")
        abort(409, description="Oracle rejected resolution. The incident may need containment and a response action first.")
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
    except Exception:
        app.logger.exception("Incident reopening failed")
        abort(409, description="Oracle rejected reopening.")
    return redirect(url_for("incident_detail", incident_id=incident_id))

@app.get("/assignments")
@login_required
def assignments():
    items = safe_read(f"""SELECT inv.investigator_id,u.full_name,inv.availability,
        SUM(CASE WHEN a.ended_at IS NULL THEN 1 ELSE 0 END) AS active_cases,
        SUM(CASE WHEN a.ended_at IS NULL AND a.assignment_role='LEAD' THEN 1 ELSE 0 END) AS lead_cases
        FROM {obj('investigator')} inv JOIN {obj('app_user')} u ON u.user_id=inv.user_id
        LEFT JOIN {obj('incident_assignment')} a ON a.investigator_id=inv.investigator_id
        GROUP BY inv.investigator_id,u.full_name,inv.availability ORDER BY u.full_name""")
    return render_template("assignments.html", items=items, filters=filter_context())

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
    except Exception:
        app.logger.exception("Assignment procedure failed")
        abort(409, description="Oracle rejected the assignment.")
    return redirect(url_for("assignments"))

@app.get("/evidence")
@login_required
def evidence_list():
    items = safe_read(f"""SELECT e.evidence_id,e.incident_id,e.evidence_type,e.original_name,e.sha256,e.sensitivity,
        e.file_size AS size_bytes,e.collected_at,u.full_name AS collector_name,e.current_custodian_id
        FROM {obj('evidence')} e JOIN {obj('app_user')} u ON u.user_id=e.collected_by ORDER BY e.collected_at DESC""")
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
        allowed_sensitivity = {"PUBLIC","INTERNAL","CONFIDENTIAL","RESTRICTED"}
        if sensitivity not in allowed_sensitivity:
            abort(400, description="Invalid sensitivity.")
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
    incidents_data = safe_read(f"SELECT incident_id,title,status FROM {obj('incident')} WHERE status NOT IN ('RESOLVED','CLOSED') ORDER BY opened_at DESC")
    return render_template("form.html", title="Register evidence", fields=[], submit_label="Register evidence", incidents=incidents_data, upload=True)

@app.get("/evidence/<int:evidence_id>")
@login_required
def evidence_detail(evidence_id):
    evidence = safe_one(f"""SELECT e.*,u.full_name AS collector_name,
        (SELECT u2.full_name FROM {obj('investigator')} inv JOIN {obj('app_user')} u2 ON u2.user_id=inv.user_id
         WHERE inv.investigator_id=e.current_custodian_id) AS current_custodian_name
        FROM {obj('evidence')} e JOIN {obj('app_user')} u ON u.user_id=e.collected_by WHERE e.evidence_id=:id""", {"id": evidence_id})
    if not evidence: abort(404)
    custody = safe_read(f"""SELECT * FROM {obj('vw_custody_history')} WHERE evidence_id=:id ORDER BY transferred_at DESC""", {"id": evidence_id})
    analyses = safe_read(f"SELECT * FROM {obj('forensic_analysis')} WHERE evidence_id=:id ORDER BY created_at DESC", {"id": evidence_id})
    return render_template("evidence_detail.html", evidence=evidence, custody=custody, analyses=analyses)

@app.get("/evidence/<int:evidence_id>/download")
@login_required
def download_evidence(evidence_id):
    if role() not in {"ADMIN", "ANALYST"}:
        abort(403)
    evidence = safe_one(f"SELECT evidence_id,incident_id,storage_key,original_name FROM {obj('evidence')} WHERE evidence_id=:id", {"id": evidence_id})
    if not evidence: abort(404)
    if role() == "ANALYST":
        assigned = safe_one(f"""SELECT 1 AS ok FROM {obj('incident_assignment')} a
            JOIN {obj('investigator')} inv ON inv.investigator_id=a.investigator_id
            JOIN {obj('investigation_cycle')} c ON c.cycle_id=a.cycle_id
            WHERE c.incident_id=:iid AND c.ended_at IS NULL AND a.ended_at IS NULL AND inv.user_id=:uid""",
            {"iid": evidence["incident_id"], "uid": actor_id()})
        if not assigned: abort(403)
    path = (UPLOAD_DIR / str(evidence["storage_key"])).resolve()
    if UPLOAD_DIR not in path.parents or not path.is_file(): abort(404)
    return send_file(path, as_attachment=True, download_name=Path(evidence["original_name"]).name)

@app.get("/response")
@login_required
def response():
    items = safe_read(f"""SELECT a.action_id,c.incident_id,a.action_type,a.performed_at,a.outcome
        FROM {obj('response_action')} a JOIN {obj('investigation_cycle')} c ON c.cycle_id=a.cycle_id
        ORDER BY a.performed_at DESC""")
    return render_template("response.html", items=items, filters=filter_context())

@app.get("/sla")
@login_required
def sla():
    items = safe_read(f"SELECT * FROM {obj('vw_sla_status')} ORDER BY response_due_at")
    return render_template("sla.html", items=items, filters=filter_context())

@app.post("/sla/<int:incident_id>/escalate")
@roles_required("ADMIN", "MANAGER", "ANALYST")
def escalate_sla(incident_id):
    reason = request.form.get("reason", "").strip()
    if not reason: abort(400, description="Escalation reason is required.")
    try:
        call_proc("sp_escalate_sla", [actor_id(), incident_id, reason], actor_id())
        flash("SLA escalation recorded.", "success")
    except Exception:
        app.logger.exception("SLA escalation failed")
        abort(409, description="Oracle rejected the SLA escalation.")
    return redirect(url_for("sla"))

@app.get("/reports")
@login_required
def reports():
    items = safe_read(f"SELECT * FROM {obj('vw_dashboard_summary')}")
    metrics = {"mtta_minutes": None, "mttr_minutes": None, "closure_rate": None}
    return render_template("reports.html", items=items, metrics=metrics, filters={"from": request.args.get("from",""), "to": request.args.get("to","")})

@app.get("/reports/export")
@login_required
def reports_export():
    items = safe_read(f"SELECT * FROM {obj('vw_dashboard_summary')}")
    output = io.StringIO()
    if items:
        writer = csv.DictWriter(output, fieldnames=list(items[0].keys()))
        writer.writeheader()
        writer.writerows(items)
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=cybershield-report.csv"})

@app.get("/audit")
@roles_required("ADMIN", "AUDITOR")
def audit():
    items = safe_read(f"""SELECT a.audit_id,u.full_name AS actor_name,a.action,a.entity_name AS entity_type,
        a.entity_id,a.occurred_at AS action_time FROM {obj('audit_log')} a
        LEFT JOIN {obj('app_user')} u ON u.user_id=a.actor_user_id ORDER BY a.occurred_at DESC FETCH FIRST 500 ROWS ONLY""")
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
@roles_required("ADMIN", "MANAGER", "AUDITOR")
def settings():
    users = safe_read(f"SELECT user_id,full_name,email,role_code,is_active FROM {obj('app_user')} ORDER BY full_name")
    attack_types = safe_read(f"SELECT name,description FROM {obj('attack_type')} ORDER BY name")
    policies = safe_read(f"SELECT policy_key,number_value,description FROM {obj('soc_policy')} ORDER BY policy_key")
    return render_template("settings.html", users=users, attack_types=attack_types, policies=policies)

@app.route("/admin/users", methods=["GET", "POST"])
@roles_required("ADMIN")
def admin_users():
    if request.method == "POST":
        action = request.form.get("action", "").strip().lower()

        if action == "create":
            name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            role_code = request.form.get("role_code", "").strip().upper()

            if not name or not email or not password:
                flash("Name, email and password are required.", "error")
            elif len(name) > 200 or len(email) > 320:
                flash("Name or email is too long.", "error")
            elif len(password) < 8:
                flash("Password must contain at least 8 characters.", "error")
            elif role_code not in ROLES:
                flash("Select a valid role.", "error")
            else:
                con = get_connection()
                cur = None
                try:
                    cur = con.cursor()
                    cur.execute(
                        f"SELECT COUNT(*) FROM {obj('app_user')} WHERE LOWER(email)=:email",
                        {"email": email.lower()}
                    )
                    if cur.fetchone()[0]:
                        flash("An account with that email already exists.", "error")
                    else:
                        cur.execute(
                            f"""INSERT INTO {obj('app_user')}
                            (email, password_hash, full_name, role_code, is_active)
                            VALUES (:email, :password_hash, :full_name, :role_code, 1)""",
                            {
                                "email": email,
                                "password_hash": generate_password_hash(password),
                                "full_name": name,
                                "role_code": role_code
                            }
                        )
                        con.commit()
                        flash("User account created successfully.", "success")
                except Exception:
                    con.rollback()
                    app.logger.exception("Could not create user account")
                    flash("Could not create account. Check the application log.", "error")
                finally:
                    if cur is not None:
                        cur.close()
                    con.close()

        elif action == "update":
            user_id = request.form.get("user_id", "").strip()
            role_code = request.form.get("role_code", "").strip().upper()
            is_active = request.form.get("is_active", "").strip()

            if not user_id.isdigit() or role_code not in ROLES or is_active not in {"0", "1"}:
                flash("Invalid user update details.", "error")
            elif int(user_id) == int(actor_id()) and (role_code != "ADMIN" or is_active != "1"):
                flash("You cannot remove your own administrator access or deactivate yourself.", "error")
            else:
                con = get_connection()
                cur = None
                try:
                    cur = con.cursor()
                    cur.execute(
                        f"""UPDATE {obj('app_user')}
                        SET role_code=:role_code, is_active=:is_active
                        WHERE user_id=:user_id""",
                        {
                            "role_code": role_code,
                            "is_active": int(is_active),
                            "user_id": int(user_id)
                        }
                    )
                    if cur.rowcount:
                        con.commit()
                        flash("User account updated.", "success")
                    else:
                        con.rollback()
                        flash("User account was not found.", "error")
                except Exception:
                    con.rollback()
                    app.logger.exception("Could not update user account")
                    flash("Could not update account. Check the application log.", "error")
                finally:
                    if cur is not None:
                        cur.close()
                    con.close()
        else:
            flash("Invalid user-management action.", "error")

        return redirect(url_for("admin_users"))

    users = safe_read(
        f"""SELECT user_id, full_name, email, role_code, is_active, created_at
        FROM {obj('app_user')} ORDER BY full_name"""
    )
    return render_template("users.html", users=users)


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
    records = safe_read(f"SELECT * FROM {obj(table)} FETCH FIRST 100 ROWS ONLY")
    return render_template("list.html", table=table, records=records, columns=list(records[0].keys()) if records else [])

@app.route("/incidents/<int:incident_id>/message", methods=["POST"])
@login_required
def send_incident_message(incident_id):
    abort(501, description="Incident messaging is not included in Person 1's Oracle schema. No message was stored.")

@app.get("/register")
def register():
    abort(403, description="Account self-registration is disabled. Accounts must be provisioned by an authorized administrator.")

@app.get("/health/details")
@roles_required("ADMIN")
def health_details():
    return {"oracle_schema": OWNER, "health_url": url_for("health"), "upload_dir_configured": bool(UPLOAD_DIR)}

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG", "0") == "1")
