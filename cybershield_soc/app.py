from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from pathlib import Path
from db import get_connection, close_pool
import sqlite3, json, secrets, os

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'cybershield.db'
app = Flask(__name__)
app.secret_key = os.environ.get('CYBERSHIELD_SECRET', 'dev-only-change-this-secret-before-deployment')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
TABLES = ['ip_address','server','attack_type','security_event','alert','evidence','chain_of_custody','forensic_analysis','threat_actor','historical_threat_intelligence','attack_campaign','campaign_event','incident','sla','investigator','incident_assignment','response_action','resolution','audit_log']
LABELS = {t: t.replace('_',' ').title() for t in TABLES}


def connect_db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys = ON')
    con.execute('PRAGMA busy_timeout = 10000')
    return con


def init_db():
    con = connect_db()
    con.executescript((BASE_DIR/'schema.sql').read_text(encoding='utf-8'))
    user_cols={r['name'] for r in con.execute('PRAGMA table_info(users)').fetchall()}
    if 'specialization' not in user_cols: con.execute("ALTER TABLE users ADD COLUMN specialization TEXT NOT NULL DEFAULT 'General Security'")
    if 'max_severity' not in user_cols: con.execute("ALTER TABLE users ADD COLUMN max_severity TEXT NOT NULL DEFAULT 'critical'")
    incident_cols={r['name'] for r in con.execute('PRAGMA table_info(incident)').fetchall()}
    if 'details' not in incident_cols: con.execute('ALTER TABLE incident ADD COLUMN details TEXT')
    con.commit()
    # Seed demo identities only when absent. Passwords are hashed and never displayed in the app.
    demos = [
        ('CyberShield Administrator','admin@cybershield.local','Admin@123','admin'),
        ('Security Engineer','engineer@cybershield.local','Engineer@123','engineer'),
        ('Demo Complainer','customer@cybershield.local','Customer@123','complainer')]
    for name,email,pw,role in demos:
        if not con.execute('SELECT 1 FROM users WHERE email=?',(email,)).fetchone():
            con.execute('INSERT INTO users(full_name,email,password_hash,role) VALUES(?,?,?,?)',(name,email,generate_password_hash(pw),role))
    # Enforce one administrator account and keep investigator profiles synchronized for engineers.
    admin_id=con.execute("SELECT user_id FROM users WHERE email='admin@cybershield.local'").fetchone()
    if admin_id:
        con.execute("UPDATE users SET role='complainer' WHERE role='admin' AND user_id<>?",(admin_id['user_id'],))
    for u in con.execute("SELECT full_name,email FROM users WHERE role='engineer'").fetchall():
        con.execute('INSERT OR IGNORE INTO investigator(name,email,specialization) VALUES(?,?,?)',(u['full_name'],u['email'],'General Security'))
    con.commit(); con.close()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please sign in to continue.','warning')
            return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get('user_id'):
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def current_user():
    return {'user_id':session.get('user_id'),'full_name':session.get('full_name'),'email':session.get('email'),'role':session.get('role')}


def log_action(con, action, table, record_id=None, old_values=None, new_values=None):
    con.execute('INSERT INTO audit_log(user_id,action,table_name,record_id,old_values,new_values,ip_address,session_id) VALUES(?,?,?,?,?,?,?,?)',
        (str(session.get('user_id','system')),action,table,record_id,json.dumps(old_values,default=str) if old_values is not None else None,json.dumps(new_values,default=str) if new_values is not None else None,request.remote_addr,session.get('_id')))


def get_table_info(con, table):
    return [dict(r) for r in con.execute(f'PRAGMA table_info("{table}")').fetchall()]


def get_fks(con, table):
    return [dict(r) for r in con.execute(f'PRAGMA foreign_key_list("{table}")').fetchall()]


def columns_for_form(con, table):
    cols=get_table_info(con,table); fks={f['from']:f for f in get_fks(con,table)}; out=[]
    for c in cols:
        if c['pk'] and table!='campaign_event': continue
        name=c['name']; fk=fks.get(name); options=[]
        if fk:
            rt=fk['table']; rc=get_table_info(con,rt); rpk=next((x['name'] for x in rc if x['pk']),rc[0]['name'])
            candidates=[x['name'] for x in rc if x['name'] not in ('id',rpk) and x['type'].upper().startswith('TEXT')]
            label=candidates[0] if candidates else rpk
            options=[{'value':r[rpk],'label':f"{r[rpk]} — {r[label] or ''}"} for r in con.execute(f'SELECT * FROM "{rt}" ORDER BY "{rpk}" DESC LIMIT 300').fetchall()]
        out.append({**c,'fk':fk,'options':options,'required':bool(c['notnull']) and c['dflt_value'] is None})
    return out


@app.before_request
def setup():
    if not DB_PATH.exists(): init_db()
    if '_id' not in session: session['_id']=secrets.token_hex(12)
    if request.method=='POST':
        token=request.form.get('_csrf','')
        if not token or token != session.get('_csrf'):
            abort(400, 'Invalid form token. Refresh the page and try again.')

@app.context_processor
def globals_for_templates():
    return {'tables':TABLES,'labels':LABELS,'me':current_user(),'csrf_token':session.setdefault('_csrf',secrets.token_urlsafe(24))}

@app.route('/')
def home():
    if not session.get('user_id'): return redirect(url_for('login'))
    role=session['role']
    con=connect_db()
    if role=='admin':
        counts={t:con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in TABLES}
        recent=con.execute('SELECT audit_id,action,table_name,record_id,action_time,user_id FROM audit_log ORDER BY audit_id DESC LIMIT 8').fetchall()
        incidents=con.execute('SELECT i.*,u.full_name AS customer_name FROM incident i LEFT JOIN users u ON u.user_id=i.created_by_user_id ORDER BY i.incident_id DESC LIMIT 8').fetchall()
        users=con.execute('SELECT user_id,full_name,email,role,is_active,created_at FROM users ORDER BY user_id DESC LIMIT 8').fetchall()
        con.close(); return render_template('dashboard.html',role=role,counts=counts,recent=recent,incidents=incidents,users=users)
    if role=='complainer':
        incidents=con.execute('SELECT i.* FROM incident i WHERE i.created_by_user_id=? ORDER BY i.incident_id DESC',(session['user_id'],)).fetchall()
        requests=con.execute('SELECT ar.*,i.summary,e.full_name AS engineer_name FROM access_request ar JOIN incident i ON i.incident_id=ar.incident_id JOIN users e ON e.user_id=ar.engineer_user_id WHERE ar.complainer_user_id=? ORDER BY ar.request_id DESC',(session['user_id'],)).fetchall()
        con.close(); return render_template('dashboard.html',role=role,incidents=incidents,requests=requests)
    engineer=con.execute('SELECT max_severity FROM users WHERE user_id=?',(session['user_id'],)).fetchone()
    levels={'low':1,'medium':2,'high':3,'critical':4}; max_level=levels.get(engineer['max_severity'] if engineer else 'critical',4)
    available=con.execute("SELECT i.incident_id,i.severity,i.status,i.summary,i.created_by_user_id,i.opened_at FROM incident i WHERE i.status IN ('open','investigating','assigned') AND i.incident_id NOT IN (SELECT incident_id FROM access_request WHERE engineer_user_id=? AND status IN ('approved','pending')) ORDER BY i.incident_id DESC",(session['user_id'],)).fetchall()
    available=[i for i in available if levels.get(i['severity'],2)<=max_level]
    my_requests=con.execute('SELECT ar.*,i.summary,i.status AS incident_status,u.full_name AS customer_name FROM access_request ar JOIN incident i ON i.incident_id=ar.incident_id JOIN users u ON u.user_id=ar.complainer_user_id WHERE ar.engineer_user_id=? ORDER BY ar.request_id DESC',(session['user_id'],)).fetchall()
    active=con.execute("SELECT i.*,u.full_name AS customer_name FROM incident i JOIN access_request ar ON ar.incident_id=i.incident_id AND ar.status='approved' LEFT JOIN users u ON u.user_id=i.created_by_user_id WHERE ar.engineer_user_id=? AND i.status!='resolved' ORDER BY i.incident_id DESC",(session['user_id'],)).fetchall()
    con.close(); return render_template('dashboard.html',role=role,available=available,my_requests=my_requests,active=active)

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower(); password=request.form.get('password','')
        con=connect_db(); u=con.execute('SELECT * FROM users WHERE email=? AND is_active=1',(email,)).fetchone(); con.close()
        if u and check_password_hash(u['password_hash'],password):
            session.clear(); session.update({'user_id':u['user_id'],'full_name':u['full_name'],'email':u['email'],'role':u['role'],'_id':secrets.token_hex(12),'_csrf':secrets.token_urlsafe(24)})
            log_con=connect_db(); log_action(log_con,'LOGIN','users',u['user_id']); log_con.commit(); log_con.close()
            return redirect(url_for('home'))
        flash('Email or password is incorrect, or the account is disabled.','error')
    return render_template('login.html')

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        name=request.form.get('full_name','').strip(); email=request.form.get('email','').strip().lower(); pw=request.form.get('password',''); confirm=request.form.get('confirm_password',''); chosen_role=request.form.get('role','complainer')
        chosen_role='complainer'
        if len(name)<2 or '@' not in email or len(pw)<8 or pw!=confirm:
            flash('Enter a valid name/email, use at least 8 characters for the password, and make both passwords match.','error')
        else:
            con=connect_db()
            try:
                cur=con.execute("INSERT INTO users(full_name,email,password_hash,role) VALUES(?,?,?,?)",(name,email,generate_password_hash(pw),chosen_role))
                if chosen_role=='engineer':
                    con.execute('INSERT OR IGNORE INTO investigator(name,email,specialization) VALUES(?,?,?)',(name,email,'General Security'))
                log_action(con,'REGISTER','users',cur.lastrowid,new_values={'email':email,'role':chosen_role}); con.commit()
                flash('Account created. You can now sign in.','success'); con.close(); return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                con.rollback(); con.close(); flash('An account with that email already exists.','error')
    return render_template('register.html')

@app.route('/logout',methods=['POST'])
@login_required
def logout():
    con=connect_db(); log_action(con,'LOGOUT','users',session.get('user_id')); con.commit(); con.close(); session.clear(); return redirect(url_for('login'))

@app.route('/incidents/new',methods=['GET','POST'])
@roles_required('complainer')
def new_incident():
    if request.method=='POST':
        summary=request.form.get('summary','').strip(); details=request.form.get('details','').strip(); severity=request.form.get('severity','medium')
        if len(summary)<5 or len(details)<10 or severity not in ('low','medium','high','critical'):
            flash('Please provide a clear summary, at least 10 characters of detail, and a valid severity.','error')
        else:
            con=connect_db()
            # Create reusable reference records, then link each report to a security event and alert.
            con.execute("INSERT OR IGNORE INTO server(host_name,critically_level,owner_dept,os_type) VALUES('customer-reported-system','medium','Security Operations','Unknown')")
            server_id=con.execute("SELECT server_id FROM server WHERE host_name='customer-reported-system'").fetchone()['server_id']
            con.execute("INSERT OR IGNORE INTO attack_type(name,category,description) VALUES('Customer Report','Reported activity','User-submitted security concern; requires investigation')")
            attack_type_id=con.execute("SELECT attack_type_id FROM attack_type WHERE name='Customer Report'").fetchone()['attack_type_id']
            score={'low':2,'medium':5,'high':8,'critical':10}[severity]
            ev=con.execute('INSERT INTO security_event(server_id,attack_type_id,severity_score,is_flagged,protocol) VALUES(?,?,?,?,?)',(server_id,attack_type_id,score,1,'reported')).lastrowid
            alert_id=con.execute('INSERT INTO alert(event_id,risk_score,severity,status) VALUES(?,?,?,?)',(ev,score*10,severity,'open')).lastrowid
            cur=con.execute('INSERT INTO incident(event_id,alert_id,severity,status,summary,created_by_user_id,details) VALUES(?,?,?,?,?,?,?)',(ev,alert_id,severity,'open',summary,session['user_id'],details))
            iid=cur.lastrowid
            log_action(con,'CREATE','incident',iid,new_values={'summary':summary,'severity':severity,'created_by_user_id':session['user_id'],'event_id':ev,'alert_id':alert_id})
            con.commit(); con.close()
            flash(f'Incident #{iid} submitted. Engineers must request access and you decide whether to approve it.','success'); return redirect(url_for('home'))
    return render_template('incident_form.html')

@app.route('/incidents/<int:iid>')
@login_required
def incident_detail(iid):
    con=connect_db(); inc=con.execute('SELECT i.*,u.full_name AS customer_name FROM incident i LEFT JOIN users u ON u.user_id=i.created_by_user_id WHERE i.incident_id=?',(iid,)).fetchone()
    if not inc: con.close(); abort(404)
    role=session['role']; allowed=role=='admin' or (role=='complainer' and inc['created_by_user_id']==session['user_id'])
    if role=='engineer': allowed=bool(con.execute("SELECT 1 FROM access_request WHERE incident_id=? AND engineer_user_id=? AND status='approved'",(iid,session['user_id'])).fetchone())
    if not allowed: con.close(); abort(403)
    actions=con.execute('SELECT ra.*,inv.name AS engineer_name FROM response_action ra LEFT JOIN investigator inv ON inv.investigator_id=ra.investigator_id WHERE ra.incident_id=? ORDER BY ra.action_id DESC',(iid,)).fetchall()
    resolution=con.execute('SELECT * FROM resolution WHERE incident_id=?',(iid,)).fetchone(); evidence=con.execute('SELECT * FROM evidence WHERE incident_id=? ORDER BY evidence_id DESC',(iid,)).fetchall()
    messages=con.execute('SELECT m.*,u.full_name AS sender_name,u.role AS sender_role FROM incident_message m JOIN users u ON u.user_id=m.sender_user_id WHERE m.incident_id=? ORDER BY m.message_id',(iid,)).fetchall()
    con.close()
    return render_template('incident_detail.html',incident=inc,actions=actions,resolution=resolution,evidence=evidence,messages=messages)

@app.route('/incidents/<int:iid>/messages',methods=['POST'])
@login_required
def send_incident_message(iid):
    body=request.form.get('body','').strip()
    if not body or len(body)>4000:
        flash('Message must contain 1–4000 characters.','error'); return redirect(url_for('incident_detail',iid=iid))
    con=connect_db(); inc=con.execute('SELECT * FROM incident WHERE incident_id=?',(iid,)).fetchone()
    if not inc: con.close(); abort(404)
    role=session['role']; allowed=role=='admin' or (role=='complainer' and inc['created_by_user_id']==session['user_id'])
    if role=='engineer': allowed=bool(con.execute("SELECT 1 FROM access_request WHERE incident_id=? AND engineer_user_id=? AND status='approved'",(iid,session['user_id'])).fetchone())
    if not allowed: con.close(); abort(403)
    cur=con.execute('INSERT INTO incident_message(incident_id,sender_user_id,body) VALUES(?,?,?)',(iid,session['user_id'],body))
    log_action(con,'MESSAGE','incident_message',cur.lastrowid,new_values={'incident_id':iid})
    con.commit(); con.close(); flash('Message saved to the incident conversation.','success'); return redirect(url_for('incident_detail',iid=iid))

@app.route('/incidents/<int:iid>/request-access',methods=['POST'])
@roles_required('engineer')
def request_access(iid):
    message=request.form.get('message','').strip()
    if len(message)<10: flash('Explain why you need access (at least 10 characters).','error'); return redirect(url_for('home'))
    con=connect_db(); inc=con.execute('SELECT * FROM incident WHERE incident_id=?',(iid,)).fetchone()
    if not inc or not inc['created_by_user_id']:
        con.close(); flash('This incident has no customer account to approve access. Ask an admin to assign it.','error'); return redirect(url_for('home'))
    try:
        cur=con.execute('INSERT INTO access_request(incident_id,engineer_user_id,complainer_user_id,message) VALUES(?,?,?,?)',(iid,session['user_id'],inc['created_by_user_id'],message))
        log_action(con,'REQUEST_ACCESS','access_request',cur.lastrowid,new_values={'incident_id':iid,'engineer_user_id':session['user_id']}); con.commit(); flash('Access request sent to the customer. You cannot work on the incident until approved.','success')
    except sqlite3.IntegrityError:
        con.rollback(); flash('You have already requested access to this incident.','warning')
    con.close(); return redirect(url_for('home'))

@app.route('/access-requests/<int:rid>/decision',methods=['POST'])
@roles_required('complainer','admin')
def decide_access(rid):
    decision=request.form.get('decision'); note=request.form.get('decision_note','').strip()
    if decision not in ('approved','rejected'): abort(400)
    con=connect_db(); ar=con.execute('SELECT * FROM access_request WHERE request_id=?',(rid,)).fetchone()
    if not ar: con.close(); abort(404)
    if session['role']=='complainer' and ar['complainer_user_id']!=session['user_id']: con.close(); abort(403)
    con.execute('UPDATE access_request SET status=?,decided_at=CURRENT_TIMESTAMP,decision_note=? WHERE request_id=?',(decision,note,rid))
    if decision=='approved': con.execute("UPDATE incident SET status='assigned' WHERE incident_id=? AND status='open'",(ar['incident_id'],))
    log_action(con,'ACCESS_'+decision.upper(),'access_request',rid,old_values={'status':ar['status']},new_values={'status':decision,'decision_note':note}); con.commit(); con.close()
    flash('Access approved. The engineer can now open the case.' if decision=='approved' else 'Access request rejected. The engineer cannot open or work on the case.','success'); return redirect(url_for('home'))

@app.route('/incidents/<int:iid>/action',methods=['POST'])
@roles_required('engineer','admin')
def add_action(iid):
    action_type=request.form.get('action_type','').strip(); description=request.form.get('description','').strip(); outcome=request.form.get('outcome','').strip()
    con=connect_db(); inc=con.execute('SELECT * FROM incident WHERE incident_id=?',(iid,)).fetchone()
    if not inc: con.close(); abort(404)
    if session['role']=='engineer' and not con.execute("SELECT 1 FROM access_request WHERE incident_id=? AND engineer_user_id=? AND status='approved'",(iid,session['user_id'])).fetchone(): con.close(); abort(403)
    if not action_type or not description: con.close(); flash('Action type and description are required.','error'); return redirect(url_for('incident_detail',iid=iid))
    inv=con.execute('SELECT investigator_id FROM investigator WHERE email=?',(session.get('email'),)).fetchone()
    cur=con.execute('INSERT INTO response_action(incident_id,investigator_id,action_type,description,outcome) VALUES(?,?,?,?,?)',(iid,inv['investigator_id'] if inv else None,action_type,description,outcome))
    con.execute("UPDATE incident SET status='investigating' WHERE incident_id=? AND status IN ('open','assigned')",(iid,))
    log_action(con,'CREATE','response_action',cur.lastrowid,new_values={'incident_id':iid,'action_type':action_type}); con.commit(); con.close(); flash('Response action recorded.','success'); return redirect(url_for('incident_detail',iid=iid))

@app.route('/incidents/<int:iid>/resolve',methods=['POST'])
@roles_required('engineer','admin')
def resolve_incident(iid):
    final_status=request.form.get('final_status','resolved'); root=request.form.get('root_cause','').strip(); lessons=request.form.get('lessons_learned','').strip()
    if final_status not in ('resolved','false_positive','closed') or len(root)<5: flash('Choose a valid final status and enter a root cause.','error'); return redirect(url_for('incident_detail',iid=iid))
    con=connect_db(); inc=con.execute('SELECT * FROM incident WHERE incident_id=?',(iid,)).fetchone()
    if not inc: con.close(); abort(404)
    if session['role']=='engineer' and not con.execute("SELECT 1 FROM access_request WHERE incident_id=? AND engineer_user_id=? AND status='approved'",(iid,session['user_id'])).fetchone(): con.close(); abort(403)
    inv=con.execute('SELECT investigator_id FROM investigator WHERE email=?',(session.get('email'),)).fetchone()
    con.execute('INSERT INTO resolution(incident_id,investigator_id,closed_at,final_status,root_cause,lessons_learned) VALUES(?,?,CURRENT_TIMESTAMP,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET investigator_id=excluded.investigator_id,closed_at=CURRENT_TIMESTAMP,final_status=excluded.final_status,root_cause=excluded.root_cause,lessons_learned=excluded.lessons_learned',(iid,inv['investigator_id'] if inv else None,final_status,root,lessons))
    con.execute('UPDATE incident SET status=?,closed_at=CURRENT_TIMESTAMP WHERE incident_id=?',('resolved' if final_status=='resolved' else 'closed',iid))
    log_action(con,'RESOLVE','incident',iid,old_values={'status':inc['status']},new_values={'status':final_status,'root_cause':root}); con.commit(); con.close(); flash('Resolution saved and incident status updated.','success'); return redirect(url_for('home'))

@app.route('/tables')
@roles_required('admin')
def table_index(): return render_template('tables.html')

@app.route('/table/<table>')
@roles_required('admin')
def list_records(table):
    if table not in TABLES: abort(404)
    con=connect_db(); cols=get_table_info(con,table); pkcols=[c['name'] for c in cols if c['pk']]
    order=pkcols[0] if pkcols else cols[0]['name']; rows=con.execute(f'SELECT * FROM "{table}" ORDER BY "{order}" DESC LIMIT 250').fetchall(); con.close()
    # Audit log is intentionally read-only; password hashes are never part of this generic table interface.
    return render_template('list.html',table=table,title=LABELS[table],cols=cols,pk=order,rows=rows,readonly=(table=='audit_log'))

@app.route('/table/<table>/new',methods=['GET','POST'])
@roles_required('admin')
def create_record(table):
    if table not in TABLES or table=='audit_log': abort(404)
    con=connect_db(); fields=columns_for_form(con,table)
    if request.method=='POST':
        names=[]; vals=[]
        for f in fields:
            v=request.form.get(f['name'],'').strip()
            if v=='':
                if f['required']:
                    flash(f"{f['name']} is required.",'error'); con.close(); return render_template('form.html',table=table,title=LABELS[table],fields=fields,record=request.form,mode='Create')
                continue
            names.append(f['name']); vals.append(v)
        try:
            cur=con.execute(f'INSERT INTO "{table}" ({", ".join(chr(34)+n+chr(34) for n in names)}) VALUES ({", ".join("?" for _ in names)})',vals) if names else con.execute(f'INSERT INTO "{table}" DEFAULT VALUES')
            rid=cur.lastrowid; log_action(con,'CREATE',table,rid,new_values=dict(zip(names,vals))); con.commit(); con.close(); flash('Record created successfully.','success'); return redirect(url_for('list_records',table=table))
        except sqlite3.Error as e: con.rollback(); flash(f'Database rejected the record: {e}','error')
    con.close(); return render_template('form.html',table=table,title=LABELS[table],fields=fields,record={},mode='Create')

@app.route('/table/campaign_event/<int:cid>/<int:eid>/edit',methods=['GET','POST'])
@roles_required('admin')
def edit_campaign_event(cid,eid):
    table='campaign_event'; con=connect_db(); old=con.execute('SELECT * FROM campaign_event WHERE campaign_id=? AND event_id=?',(cid,eid)).fetchone()
    if old is None: con.close(); abort(404)
    old_dict=dict(old); fields=columns_for_form(con,table)
    if request.method=='POST':
        new={}; vals=[]
        for f in fields:
            name=f['name']; v=request.form.get(name,'').strip(); new[name]=v
            if v=='': con.close(); flash(f'{name} is required.','error'); return redirect(url_for('edit_campaign_event',cid=cid,eid=eid))
            vals.append(v)
        try:
            con.execute('DELETE FROM campaign_event WHERE campaign_id=? AND event_id=?',(cid,eid))
            con.execute('INSERT INTO campaign_event(campaign_id,event_id,linked_at) VALUES(?,?,?)',(int(new['campaign_id']),int(new['event_id']),new.get('linked_at') or old_dict.get('linked_at')))
            log_action(con,'UPDATE',table,f'{cid}:{eid}',old_values=old_dict,new_values=new); con.commit(); con.close(); flash('Campaign event link updated.','success'); return redirect(url_for('list_records',table=table))
        except (sqlite3.Error,ValueError) as e: con.rollback(); flash(f'Database rejected the update: {e}','error')
    con.close(); return render_template('form.html',table=table,title=LABELS[table],fields=fields,record=old_dict,mode='Edit')

@app.route('/table/campaign_event/<int:cid>/<int:eid>/delete',methods=['POST'])
@roles_required('admin')
def delete_campaign_event(cid,eid):
    con=connect_db(); old=con.execute('SELECT * FROM campaign_event WHERE campaign_id=? AND event_id=?',(cid,eid)).fetchone()
    if old:
        log_action(con,'DELETE','campaign_event',f'{cid}:{eid}',old_values=dict(old)); con.execute('DELETE FROM campaign_event WHERE campaign_id=? AND event_id=?',(cid,eid)); con.commit(); flash('Campaign event link deleted.','success')
    con.close(); return redirect(url_for('list_records',table='campaign_event'))

@app.route('/table/<table>/<int:rid>/edit',methods=['GET','POST'])
@roles_required('admin')
def edit_record(table,rid):
    if table not in TABLES or table=='audit_log': abort(404)
    con=connect_db(); cols=get_table_info(con,table); pk=next(c['name'] for c in cols if c['pk']); old=con.execute(f'SELECT * FROM "{table}" WHERE "{pk}"=?',(rid,)).fetchone()
    if old is None: con.close(); abort(404)
    old_dict=dict(old); fields=columns_for_form(con,table)
    if request.method=='POST':
        sets=[]; vals=[]; new={}
        for f in fields:
            name=f['name']; v=request.form.get(name,'').strip(); new[name]=v
            if v=='' and not f['required']: v=None
            elif v=='' and f['required']:
                flash(f'{name} is required.','error'); con.close(); return render_template('form.html',table=table,title=LABELS[table],fields=fields,record=request.form,mode='Edit',rid=rid)
            sets.append(f'"{name}"=?'); vals.append(v)
        try:
            con.execute(f'UPDATE "{table}" SET {", ".join(sets)} WHERE "{pk}"=?',vals+[rid]); log_action(con,'UPDATE',table,rid,old_values=old_dict,new_values=new); con.commit(); con.close(); flash('Record updated successfully.','success'); return redirect(url_for('list_records',table=table))
        except sqlite3.Error as e: con.rollback(); flash(f'Database rejected the update: {e}','error')
    con.close(); return render_template('form.html',table=table,title=LABELS[table],fields=fields,record=old_dict,mode='Edit',rid=rid)

@app.route('/table/<table>/<int:rid>/delete',methods=['POST'])
@roles_required('admin')
def delete_record(table,rid):
    if table not in TABLES or table=='audit_log': abort(404)
    con=connect_db(); cols=get_table_info(con,table); pk=next(c['name'] for c in cols if c['pk']); old=con.execute(f'SELECT * FROM "{table}" WHERE "{pk}"=?',(rid,)).fetchone()
    if old:
        try: log_action(con,'DELETE',table,rid,old_values=dict(old)); con.execute(f'DELETE FROM "{table}" WHERE "{pk}"=?',(rid,)); con.commit(); flash('Record deleted.','success')
        except sqlite3.Error as e: con.rollback(); flash(f'Cannot delete this record because related records depend on it: {e}','error')
    con.close(); return redirect(url_for('list_records',table=table))

@app.route('/admin/users',methods=['GET','POST'])
@roles_required('admin')
def admin_users():
    con=connect_db()
    if request.method=='POST':
        action=request.form.get('action','update')
        if action=='create_engineer':
            name=request.form.get('full_name','').strip(); email=request.form.get('email','').strip().lower(); password=request.form.get('password',''); specialization=request.form.get('specialization','General Security').strip(); max_severity=request.form.get('max_severity','medium')
            if len(name)<2 or '@' not in email or len(password)<8 or max_severity not in ('low','medium','high','critical'):
                flash('Enter a valid name/email, password of at least 8 characters, and valid severity capability.','error')
            else:
                try:
                    cur=con.execute("INSERT INTO users(full_name,email,password_hash,role,specialization,max_severity) VALUES(?,?,?,'engineer',?,?)",(name,email,generate_password_hash(password),specialization,max_severity))
                    con.execute('INSERT OR IGNORE INTO investigator(name,email,specialization,experience_years,is_active) VALUES(?,?,?,?,1)',(name,email,specialization,0))
                    log_action(con,'CREATE_ENGINEER','users',cur.lastrowid,new_values={'email':email,'specialization':specialization,'max_severity':max_severity})
                    con.commit(); flash('Engineer account created. Share the password securely; it cannot be viewed again in the dashboard.','success')
                except sqlite3.IntegrityError:
                    con.rollback(); flash('An account with that email already exists.','error')
        else:
            uid=request.form.get('user_id',type=int); active=request.form.get('is_active')=='1'; role=request.form.get('role'); specialization=request.form.get('specialization','General Security').strip(); max_severity=request.form.get('max_severity','critical')
            if role not in ('admin','complainer','engineer') or max_severity not in ('low','medium','high','critical'): abort(400)
            target=con.execute('SELECT role FROM users WHERE user_id=?',(uid,)).fetchone()
            if role=='admin' and (not target or target['role']!='admin'):
                flash('Only the existing administrator account may hold the Admin role.','error')
            elif uid==session['user_id'] and (not active or role!='admin'):
                flash('You cannot disable or change the role of your own administrator account.','error')
            else:
                con.execute('UPDATE users SET is_active=?,role=?,specialization=?,max_severity=? WHERE user_id=?',(1 if active else 0,role,specialization,max_severity,uid))
                if role=='engineer':
                    u=con.execute('SELECT full_name,email FROM users WHERE user_id=?',(uid,)).fetchone()
                    con.execute('INSERT OR IGNORE INTO investigator(name,email,specialization) VALUES(?,?,?)',(u['full_name'],u['email'],specialization))
                    con.execute('UPDATE investigator SET specialization=? WHERE email=?',(specialization,u['email']))
                log_action(con,'USER_ACCESS_UPDATE','users',uid,new_values={'is_active':active,'role':role,'specialization':specialization,'max_severity':max_severity}); con.commit(); flash('Account access updated. Passwords are never displayed.','success')
    users=con.execute('SELECT user_id,full_name,email,role,is_active,created_at,specialization,max_severity FROM users ORDER BY user_id DESC').fetchall()
    con.close(); return render_template('users.html',users=users)

@app.route('/health/oracle')
def oracle_health():
    con = None
    cur = None

    try:
        con = get_connection()
        cur = con.cursor()
        cur.execute("SELECT 1 FROM dual")
        result = cur.fetchone()

        if result and result[0] == 1:
            return {'status': 'ok', 'database': 'oracle'}, 200

        return {'status': 'unavailable'}, 503

    except Exception:
        app.logger.exception("Oracle health check failed")
        return {'status': 'unavailable'}, 503

    finally:
        if cur is not None:
            cur.close()

        if con is not None:
            con.close()

@app.errorhandler(403)
def forbidden(e): return render_template('error.html',code=403,message='You do not have permission to view or change this resource.'),403
@app.errorhandler(404)
def not_found(e): return render_template('error.html',code=404,message='The requested page or record was not found.'),404

@app.route('/evidence/<int:evidence_id>/download', methods=['GET'])
@login_required
def download_evidence(evidence_id):
    con = None
    cur = None

    try:
        con = get_connection()
        cur = con.cursor()

        cur.execute(
            """
            SELECT evidence_id, incident_id, storage_key, original_name
            FROM cs_owner.evidence
            WHERE evidence_id = :evidence_id
            """,
            {"evidence_id": evidence_id}
        )

        ev = cur.fetchone()

        if ev is None:
            return {"error": "Evidence not found"}, 404

        role = str(session.get("role", "")).upper()
        user_id = session.get("user_id")

        if role == "ADMIN":
            allowed = True
        elif role == "ANALYST":
            cur.execute(
                """
                SELECT 1
                FROM cs_owner.investigator iv
                JOIN cs_owner.incident_assignment ia
                  ON ia.investigator_id = iv.investigator_id
                JOIN cs_owner.investigation_cycle ic
                  ON ic.cycle_id = ia.cycle_id
                WHERE iv.user_id = :user_id
                  AND ic.incident_id = :incident_id
                  AND ic.ended_at IS NULL
                  AND ia.ended_at IS NULL
                FETCH FIRST 1 ROWS ONLY
                """,
                {
                    "user_id": user_id,
                    "incident_id": ev[1]
                }
            )
            allowed = cur.fetchone() is not None
        else:
            allowed = False

        if not allowed:
            return {"error": "Forbidden"}, 403

        upload_dir = os.getenv("UPLOAD_DIR")

        if not upload_dir:
            app.logger.error("UPLOAD_DIR is not configured")
            return {"error": "Evidence storage unavailable"}, 503

        root = Path(upload_dir).expanduser().resolve()
        storage_key = ev[2]
        original_name = ev[3]

        if not storage_key or not original_name:
            return {"error": "Evidence file not found"}, 404

        file_path = (root / storage_key).resolve()

        if not file_path.is_relative_to(root):
            return {"error": "Evidence file not found"}, 404

        if not file_path.is_file():
            return {"error": "Evidence file not found"}, 404

        download_name = Path(str(original_name)).name

        return send_file(
            file_path,
            as_attachment=True,
            download_name=download_name
        )

    except Exception:
        app.logger.exception("Evidence download failed")
        return {"error": "Evidence service unavailable"}, 503

    finally:
        if cur is not None:
            cur.close()

        if con is not None:
            con.close()

if __name__=='__main__':
    init_db()
    app.run(debug=os.environ.get('FLASK_DEBUG')=='1',host='127.0.0.1',port=5000)
