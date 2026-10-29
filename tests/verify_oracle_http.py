"""Opt-in real HTTP/Oracle verification. Creates a NEW labelled simulation only.
Run from the repository root with .venv/Scripts/python tests/verify_oracle_http.py.
Uses signed test sessions for existing users; does not test password entry or alter users.
"""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import io
import json
import secrets
import threading
from datetime import datetime,timezone
from html.parser import HTMLParser
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from urllib.parse import urlencode
from werkzeug.serving import make_server, WSGIRequestHandler
import app as root

class QuietHandler(WSGIRequestHandler):
    def log_request(self,*args,**kwargs): pass

class Fields(HTMLParser):
    def __init__(self,html):
        super().__init__();self.fields={};self.select=None;self.feed(html)
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='input' and 'name' in a:self.fields[a['name']]=a.get('value','')
        if tag=='select':self.select=a.get('name')
        if tag=='option' and self.select and self.select not in self.fields and 'value' in a:self.fields[self.select]=a['value']
    def handle_endtag(self,tag):
        if tag=='select':self.select=None


def main():
    checks=[];ids={}
    def passed(name):
        checks.append(name);print('PASS:',name,flush=True)
    users=root.query_all("SELECT u.user_id,u.role_code,inv.investigator_id FROM cs_owner.app_user u LEFT JOIN cs_owner.investigator inv ON inv.user_id=u.user_id AND inv.availability <> 'INACTIVE' WHERE u.is_active=1 ORDER BY u.user_id")
    selected={role:next(u for u in users if u['role_code']==role) for role in ['ADMIN','MANAGER','AUDITOR']}
    analysts=[u for u in users if u['role_code']=='ANALYST' and u['investigator_id'] is not None]
    assert len(analysts)>=2,'Need two existing active analyst investigator profiles.'
    selected['ANALYST']=analysts[0];selected['OTHER']=analysts[1]
    server=make_server('127.0.0.1',0,root.app,request_handler=QuietHandler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    base=f'http://127.0.0.1:{server.server_port}'
    print('Running ROOT website:',base,flush=True)
    serializer=root.app.session_interface.get_signing_serializer(root.app)
    csrf=secrets.token_hex(24)
    def http(role,path,data=None,raw=None,content_type=None):
        user=selected[role]
        cookie=serializer.dumps({'me':{'user_id':int(user['user_id']),'role_code':user['role_code']},'_csrf':csrf})
        headers={'Cookie':root.app.config['SESSION_COOKIE_NAME']+'='+cookie}
        if data is not None:
            data=dict(data,_csrf=csrf);raw=urlencode(data).encode();content_type='application/x-www-form-urlencoded'
        if content_type:headers['Content-Type']=content_type
        req=Request(base+path,data=raw,headers=headers)
        try:
            with urlopen(req,timeout=20) as response:return response.status,response.read().decode('utf-8',errors='replace')
        except HTTPError as response:return response.code,response.read().decode('utf-8',errors='replace')
    try:
        assert http('ADMIN','/health')[0]==200
        con=root.get_connection()
        with con.cursor() as cur:
            cur.execute('select user from dual');assert cur.fetchone()[0]=='CS_APP'
            cur.execute("select privilege from user_sys_privs where privilege in ('CREATE TABLE','INSERT ANY TABLE','UPDATE ANY TABLE','DELETE ANY TABLE')");assert not cur.fetchall()
            cur.execute("select privilege from user_tab_privs where grantee='CS_APP' and owner='CS_OWNER' and privilege in ('INSERT','UPDATE','DELETE')");assert not cur.fetchall()
        con.close();passed('Oracle CS_APP connection; no direct table-write or broad write privileges')
        for role in ['ADMIN','MANAGER','ANALYST','AUDITOR']:
            for path in ['/dashboard','/incidents','/events','/alerts','/evidence','/response','/sla']:
                assert http(role,path)[0]==200,(role,path)
        passed('Live HTTP dashboards and permitted list pages render for all four roles')
        status,html=http('ADMIN','/events/new');assert status==200
        data=Fields(html).fields
        data.update(severity_score='99',details='SIMULATED: CyberShield Oracle HTTP workflow verification '+secrets.token_hex(8),packet_count='12',bytes_in='100',bytes_out='50')
        key=data['source_event_key'];ids['source_event_key']=key
        assert http('ADMIN','/events/new',data)[0]==200
        row=root.query_one('SELECT event_id,is_simulated FROM cs_owner.security_event WHERE source_event_key=:source_key',{'source_key':key});assert row and row['is_simulated']==1
        event_id=int(row['event_id']);ids['event_id']=event_id
        alert=root.query_one('SELECT alert_id,severity FROM cs_owner.alert WHERE event_id=:event_id',{'event_id':event_id});assert alert and alert['severity']=='CRITICAL'
        alert_id=int(alert['alert_id']);ids['alert_id']=alert_id
        assert http('ADMIN','/events/new',data)[0]==200
        assert root.query_one('SELECT COUNT(*) AS n FROM cs_owner.security_event WHERE source_event_key=:source_key',{'source_key':key})['n']==1
        passed('Frontend ingestion committed a simulated event and threshold alert; identical retry deduplicated')
        incident=root.query_one('SELECT i.incident_id,i.status,i.title FROM cs_owner.incident i JOIN cs_owner.incident_alert ia ON ia.incident_id=i.incident_id WHERE ia.alert_id=:alert_id',{'alert_id':alert_id})
        assert incident and incident['status']=='OPEN'
        case_id=int(incident['incident_id']);ids['incident_id']=case_id
        case_path=f'/incidents/{case_id}'
        assert http('ADMIN',case_path)[0]==200
        passed('Frontend simulator automatically committed incident, cycle, SLA and initial OPEN history')
        assert http('MANAGER','/assignments',{'incident_id':case_id,'investigator_id':selected['ANALYST']['investigator_id'],'assignment_role':'LEAD'})[0]==200
        assert http('ANALYST',case_path)[0]==200
        passed('Manager assignment committed; assigned Analyst can open the investigation')
        for path in [case_path,f'/events/{event_id}']:
            assert http('OTHER',path)[0]==403
        assert http('OTHER',case_path+'/status',{'status':'TRIAGED','reason':'must be denied'})[0]==403
        assert http('MANAGER',case_path+'/status',{'status':'TRIAGED','reason':'must be denied'})[0]==403
        for suffix,payload in [('status',{'status':'TRIAGED','reason':'deny'}),('action',{'action_type':'note','description':'deny'}),('resolve',{'summary':'deny'}),('reopen',{'reason':'deny'})]:
            assert http('AUDITOR',case_path+'/'+suffix,payload)[0]==403
        for path,payload in [('/events/new',data),('/incidents/new',{'alert_id':alert_id}),('/assignments',{'incident_id':case_id}),('/evidence/upload',{}),(f'/alerts/{alert_id}/triage',{'note':'deny'}),(f'/sla/{case_id}/escalate',{'reason':'deny'})]:
            assert http('AUDITOR',path,payload)[0]==403,(path,'auditor mutation')
        passed('Unassigned Analyst reads/writes denied; Manager operational writes and Auditor direct POSTs denied')
        assert http('ANALYST',case_path+'/status',{'status':'CONTAINED','reason':'invalid transition'})[0]==409
        assert root.query_one('SELECT status FROM cs_owner.incident WHERE incident_id=:case_id',{'case_id':case_id})['status']=='OPEN'
        passed('Oracle invalid lifecycle transition rolled back and returned a useful 409')
        for next_status in ['TRIAGED','INVESTIGATING']:
            assert http('ANALYST',case_path+'/status',{'status':next_status,'reason':'SIMULATED HTTP verification '+next_status})[0]==200
        assert http('ANALYST',f'/alerts/{alert_id}/triage',{'status':'ACKNOWLEDGED','note':'SIMULATED: assigned analyst reviewed threshold alert'})[0]==200
        assert http('ANALYST',case_path+'/action',{'action_type':'SIMULATED INVESTIGATION NOTE','description':'Reviewed linked simulated traffic and isolated the test asset.','outcome':'Simulation contained; no production changes.'})[0]==200
        # Register a new labelled evidence file through the real multipart frontend.
        boundary='cs-'+secrets.token_hex(12)
        fields={'_csrf':csrf,'incident_id':str(case_id),'evidence_type':'LOG','sensitivity':'INTERNAL'}
        parts=[]
        for name,value in fields.items():parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="simulated-http-evidence.txt"\r\nContent-Type: text/plain\r\n\r\nSIMULATED Oracle workflow verification {key}\r\n--{boundary}--\r\n'.encode())
        assert http('ANALYST','/evidence/upload',raw=b''.join(parts),content_type='multipart/form-data; boundary='+boundary)[0]==200
        evidence=root.query_one('SELECT evidence_id,storage_key FROM cs_owner.evidence WHERE incident_id=:case_id',{'case_id':case_id});assert evidence
        evidence_id=int(evidence['evidence_id']);ids['evidence_id']=evidence_id
        assert http('ANALYST',f'/evidence/{evidence_id}')[0]==200
        assert http('ANALYST',f'/evidence/{evidence_id}/download')[0]==200
        assert http('OTHER',f'/evidence/{evidence_id}')[0]==403
        assert http('OTHER',f'/evidence/{evidence_id}/download')[0]==403
        assert http('ANALYST',f'/evidence/{evidence_id}/analysis',{'technique':'SIMULATED log review','findings':'Simulation evidence agrees with the linked event.','indicators':key,'confidence':'99'})[0]==200
        assert root.query_one('SELECT COUNT(*) AS n FROM cs_owner.chain_of_custody WHERE evidence_id=:evidence_id',{'evidence_id':evidence_id})['n']==1
        assert root.query_one('SELECT COUNT(*) AS n FROM cs_owner.forensic_analysis WHERE evidence_id=:evidence_id',{'evidence_id':evidence_id})['n']==1
        passed('Frontend response note, evidence upload, initial custody, analysis and scoped download committed/verified')
        assert http('ANALYST',case_path+'/status',{'status':'CONTAINED','reason':'SIMULATED test isolation verified'})[0]==200
        assert http('ANALYST',case_path+'/resolve',{'summary':'SIMULATED workflow verification complete','root_cause':'Labelled synthetic threshold event','lessons_learned':'Oracle frontend round trip verified','financial_loss':'0.00'})[0]==200
        assert http('ANALYST',case_path+'/status',{'status':'CLOSED','reason':'SIMULATED case closed after verification'})[0]==200
        state=root.query_one('SELECT status FROM cs_owner.incident WHERE incident_id=:case_id',{'case_id':case_id});assert state['status']=='CLOSED'
        history=root.query_all('SELECT h.to_status FROM cs_owner.incident_status_history h JOIN cs_owner.investigation_cycle c ON c.cycle_id=h.cycle_id WHERE c.incident_id=:case_id ORDER BY h.history_id',{'case_id':case_id})
        assert [h['to_status'] for h in history]==['OPEN','TRIAGED','INVESTIGATING','CONTAINED','RESOLVED','CLOSED']
        resolution=root.query_one('SELECT COUNT(*) AS n FROM cs_owner.resolution r JOIN cs_owner.investigation_cycle c ON c.cycle_id=r.cycle_id WHERE c.incident_id=:case_id',{'case_id':case_id});assert resolution['n']==1
        passed('Entire frontend lifecycle committed through CLOSED; exact six-stage status history and resolution verified')
        # Verify real query predicates with unique and impossible matches.
        for path in ['/incidents','/alerts','/events','/assignments','/evidence','/audit']:
            status,html=http('ADMIN',path+'?q=impossible-'+key);assert status==200 and ('No ' in html or 'no ' in html)
        for path in ['/incidents','/alerts','/events','/evidence','/audit','/reports']:
            status,html=http('ADMIN',path+'?from=2099-01-01&to=2099-01-02');assert status==200
        assert http('ADMIN','/events?min_score=99&max_score=100')[0]==200
        assert http('ADMIN','/incidents?status=CLOSED&severity=CRITICAL&q='+key)[0]==200
        assert http('ADMIN','/events?min_score=NaN')[0]==400
        assert http('ADMIN','/events?from=invalid')[0]==400
        passed('Search, status, severity, numeric score and date filters execute against Oracle; invalid filters rejected')
        assert http('AUDITOR',case_path)[0]==200
        assert http('AUDITOR','/audit')[0]==200
        assert http('AUDITOR','/reports')[0]==200
        audit=root.query_all("SELECT entity_name,action,actor_user_id FROM cs_owner.audit_log WHERE (UPPER(entity_name)='SECURITY_EVENT' AND entity_id=:event_id) OR (UPPER(entity_name)='INCIDENT' AND entity_id=:case_id) OR (UPPER(entity_name)='EVIDENCE' AND entity_id=:evidence_id)",{'event_id':event_id,'case_id':case_id,'evidence_id':evidence_id})
        assert audit and all(a['actor_user_id'] is not None for a in audit)
        assert {'SECURITY_EVENT','INCIDENT','EVIDENCE'} <= {a['entity_name'].upper() for a in audit}
        ids['audit_rows_checked']=len(audit)
        passed('Auditor sees committed case/history/reports; Oracle audit triggers recorded authenticated actors')
        con=root.get_connection()
        with con.cursor() as cur:
            cur.execute("SELECT SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') FROM dual");assert cur.fetchone()[0] is None
        con.close();passed('Pooled Oracle session actor context cleared before reuse')
        report={'transport':'Real HTTP to ROOT Flask app; python-oracledb to CS_APP/CS_OWNER','authentication':'Signed test sessions for existing users; password login not tested','ids':ids,'checks':checks,'verified_at':datetime.now(timezone.utc).isoformat()}
        Path('ORACLE_VERIFICATION.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(ids,indent=2),flush=True)
    finally:
        server.shutdown();server.server_close();root.close_pool()

if __name__=='__main__':main()
