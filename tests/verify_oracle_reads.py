"""Read-only follow-up against the running root website and existing verified simulation."""
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from html.parser import HTMLParser
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from urllib.parse import urlencode
import app as root

class Rows(HTMLParser):
    def __init__(self,html):
        super().__init__();self.in_body=False;self.current=None;self.rows=[];self.empty=False;self.feed(html)
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='tbody':self.in_body=True
        if tag=='tr' and self.in_body:self.current=[];self.empty=False
        if tag=='td' and 'empty' in attrs.get('class',''):self.empty=True
    def handle_endtag(self,tag):
        if tag=='tr' and self.current is not None:
            if not self.empty:self.rows.append(' '.join(self.current))
            self.current=None
        if tag=='tbody':self.in_body=False
    def handle_data(self,data):
        if self.current is not None and data.strip():self.current.append(data.strip())

def main():
    report_path=Path(sys.argv[2]) if len(sys.argv)>2 else Path('ORACLE_VERIFICATION.json')
    report=json.loads(report_path.read_text())
    ids=report['ids'];case_id=ids['incident_id'];event_id=ids['event_id'];evidence_id=ids['evidence_id']
    base=sys.argv[1] if len(sys.argv)>1 else 'http://127.0.0.1:5000'
    admin=root.query_one("SELECT user_id FROM cs_owner.app_user WHERE role_code='ADMIN' AND is_active=1")
    serializer=root.app.session_interface.get_signing_serializer(root.app)
    cookie=serializer.dumps({'me':{'user_id':int(admin['user_id']),'role_code':'ADMIN'},'_csrf':'read-only-verifier'})
    def get(path):
        try:
            with urlopen(Request(base+path,headers={'Cookie':'session='+cookie}),timeout=15) as r:return r.status,r.read().decode()
        except HTTPError as r:return r.code,r.read().decode()
    checks=[]
    def passed(message):checks.append(message);print('PASS:',message,flush=True)
    paths=['/dashboard','/events/new','/incidents/new','/assignments','/evidence/upload','/admin/assets','/admin/users','/settings','/reports','/reports/export',f'/incidents/{case_id}',f'/events/{event_id}',f'/evidence/{evidence_id}']
    for path in paths:assert get(path)[0]==200,path
    for page in ['incidents','alerts','events','assignments','evidence','audit','response','sla','servers']:
        code,html=get('/'+page+'?'+urlencode({'q':'impossible-'+ids['source_event_key']}))
        assert code==200 and not Rows(html).rows,page
    passed('All root page/action destinations render; nine search filters return genuine empty table bodies')
    case=root.query_one('SELECT title,status,severity FROM cs_owner.incident WHERE incident_id=:case_id',{'case_id':case_id})
    code,html=get('/incidents?'+urlencode({'q':case['title'],'status':'CLOSED','severity':'CRITICAL'}));rows=Rows(html).rows
    assert code==200 and len(rows)==1 and case['title'] in rows[0]
    assert not Rows(get('/incidents?'+urlencode({'q':case['title'],'status':'OPEN'}))[1]).rows
    assert not Rows(get('/incidents?'+urlencode({'q':case['title'],'severity':'LOW'}))[1]).rows
    assert not Rows(get('/events?min_score=0&max_score=0')[1]).rows or all(' 0 ' in r for r in Rows(get('/events?min_score=0&max_score=0')[1]).rows)
    for page in ['incidents','alerts','events','evidence','audit','reports','response','sla']:
        code,html=get('/'+page+'?from=2099-01-01&to=2099-01-02');assert code==200 and not Rows(html).rows,page
    assert get('/incidents?from=2026-10-29&to=2026-10-01')[0]==400
    assert get('/events?min_score=NaN')[0]==400
    passed('Status/severity filters include/exclude the verified case; date filters affect actual rows; invalid filters rejected')
    mapping={
        'security_event':('SELECT event_id AS id FROM cs_owner.security_event WHERE event_id=:event_id',{'event_id':event_id}),
        'alert':('SELECT alert_id AS id FROM cs_owner.alert WHERE event_id=:event_id',{'event_id':event_id}),
        'incident':('SELECT incident_id AS id FROM cs_owner.incident WHERE incident_id=:case_id',{'case_id':case_id}),
        'incident_alert':('SELECT incident_id AS id FROM cs_owner.incident_alert WHERE incident_id=:case_id',{'case_id':case_id}),
        'investigation_cycle':('SELECT cycle_id AS id FROM cs_owner.investigation_cycle WHERE incident_id=:case_id',{'case_id':case_id}),
        'incident_assignment':('SELECT a.assignment_id AS id FROM cs_owner.incident_assignment a JOIN cs_owner.investigation_cycle c ON c.cycle_id=a.cycle_id WHERE c.incident_id=:case_id',{'case_id':case_id}),
        'sla':('SELECT s.sla_id AS id FROM cs_owner.sla s JOIN cs_owner.investigation_cycle c ON c.cycle_id=s.cycle_id WHERE c.incident_id=:case_id',{'case_id':case_id}),
        'incident_status_history':('SELECT h.history_id AS id FROM cs_owner.incident_status_history h JOIN cs_owner.investigation_cycle c ON c.cycle_id=h.cycle_id WHERE c.incident_id=:case_id',{'case_id':case_id}),
        'evidence':('SELECT evidence_id AS id FROM cs_owner.evidence WHERE evidence_id=:evidence_id',{'evidence_id':evidence_id}),
        'chain_of_custody':('SELECT custody_id AS id FROM cs_owner.chain_of_custody WHERE evidence_id=:evidence_id',{'evidence_id':evidence_id}),
        'forensic_analysis':('SELECT analysis_id AS id FROM cs_owner.forensic_analysis WHERE evidence_id=:evidence_id',{'evidence_id':evidence_id}),
        'response_action':('SELECT a.action_id AS id FROM cs_owner.response_action a JOIN cs_owner.investigation_cycle c ON c.cycle_id=a.cycle_id WHERE c.incident_id=:case_id',{'case_id':case_id}),
        'resolution':('SELECT r.resolution_id AS id FROM cs_owner.resolution r JOIN cs_owner.investigation_cycle c ON c.cycle_id=r.cycle_id WHERE c.incident_id=:case_id',{'case_id':case_id})}
    counts={}
    for entity,(sql,binds) in mapping.items():
        objects=root.query_all(sql,binds);assert objects,entity
        total=0
        for item in objects:
            audits=root.query_all('SELECT actor_user_id,action FROM cs_owner.audit_log WHERE entity_name=:entity AND entity_id=:object_id',{'entity':entity,'object_id':item['id']})
            assert audits and all(a['actor_user_id'] is not None for a in audits),entity
            total+=len(audits)
        counts[entity]=total
    passed('Authenticated Oracle audit records verified for all 13 workflow entity types')
    assert root.query_one('SELECT status FROM cs_owner.incident WHERE incident_id=:case_id',{'case_id':case_id})['status']=='CLOSED'
    assert root.query_one('SELECT COUNT(*) AS n FROM cs_owner.incident_assignment a JOIN cs_owner.investigation_cycle c ON c.cycle_id=a.cycle_id WHERE c.incident_id=:case_id AND a.ended_at IS NULL',{'case_id':case_id})['n']==0
    assert root.query_one('SELECT COUNT(*) AS n FROM cs_owner.investigation_cycle WHERE incident_id=:case_id AND ended_at IS NULL',{'case_id':case_id})['n']==0
    passed('Closed incident persisted; cycle and assignment ended as required by Oracle procedures')
    report['follow_up_checks']=checks;report['audit_counts_by_entity']=counts;report['running_url']=base
    report_path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('Audit rows across entity types:',sum(counts.values()),flush=True)
    root.close_pool()

if __name__=='__main__':main()
