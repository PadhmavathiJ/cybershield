"""Opt-in real Oracle race tests. Adds two labelled simulations and closes them.
No migrations, passwords, grants, existing cases or policies are changed.
"""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import json
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import app as root
from simulator import ingest_simulation


def main():
    actor=int(root.query_one("SELECT user_id FROM cs_owner.app_user WHERE role_code='ADMIN' AND is_active=1")['user_id'])
    server=int(root.query_one('SELECT server_id FROM cs_owner.server WHERE is_active=1 ORDER BY server_id FETCH FIRST 1 ROW ONLY')['server_id'])
    ip=int(root.query_one('SELECT ip_id FROM cs_owner.ip_address WHERE is_simulated=1 ORDER BY ip_id FETCH FIRST 1 ROW ONLY')['ip_id'])
    attack=int(root.query_one('SELECT attack_type_id FROM cs_owner.attack_type ORDER BY attack_type_id FETCH FIRST 1 ROW ONLY')['attack_type_id'])
    report={'checks':[],'records':[],'before':root.query_one('SELECT * FROM cs_owner.vw_dashboard_summary')}
    for mode in ['concurrent-first-ingestion','concurrent-existing-unlinked-alert']:
        key='sim-race-'+secrets.token_hex(12)
        payload=dict(source_key=key,server_id=server,source_ip_id=ip,attack_type_id=attack,event_at=datetime.now(timezone.utc),protocol='TCP',packet_count=1,bytes_in=1,bytes_out=1,severity_score=99,details='SIMULATED Oracle concurrency verification: '+mode)
        if mode.endswith('unlinked-alert'):
            root.call_proc('sp_ingest_event',[actor,key,server,ip,attack,payload['event_at'],'TCP',1,1,1,99,payload['details'],None,None],actor,(12,13))
        start=threading.Barrier(4)
        def submit(_):start.wait();return ingest_simulation(actor,**payload)
        with ThreadPoolExecutor(max_workers=4) as executor:results=list(executor.map(submit,range(4)))
        assert len(set(results))==1
        result=results[0]
        assert root.query_one('SELECT COUNT(*) AS n FROM cs_owner.security_event WHERE source_event_key=:key',{'key':key})['n']==1
        assert root.query_one('SELECT COUNT(*) AS n FROM cs_owner.alert WHERE event_id=:event_id',{'event_id':result.event_id})['n']==1
        assert root.query_one('SELECT COUNT(*) AS n FROM cs_owner.incident_alert WHERE alert_id=:alert_id',{'alert_id':result.alert_id})['n']==1
        before=root.query_one("SELECT COUNT(*) AS n FROM cs_owner.audit_log WHERE entity_name='incident' AND entity_id=:case_id",{'case_id':result.incident_id})['n']
        assert before==1
        changed=dict(payload,details='SIMULATED conflicting retry payload')
        try:ingest_simulation(actor,**changed);raise AssertionError('Conflicting source-key reuse was accepted')
        except root.oracledb.DatabaseError as exc:assert exc.args[0].code==20009
        assert root.query_one("SELECT COUNT(*) AS n FROM cs_owner.audit_log WHERE entity_name='incident' AND entity_id=:case_id",{'case_id':result.incident_id})['n']==before
        for status in ['TRIAGED','INVESTIGATING']:
            root.call_proc('sp_change_status',[actor,result.incident_id,status,'SIMULATED concurrency verification '+status],actor)
        root.call_proc('sp_record_action',[actor,result.incident_id,'SIMULATED race verification','Verified four concurrent requests reuse one event, alert and incident.','Simulation only; no production changes.',None],actor,(5,))
        root.call_proc('sp_change_status',[actor,result.incident_id,'CONTAINED','SIMULATED verification complete'],actor)
        root.call_proc('sp_resolve_incident',[actor,result.incident_id,'SIMULATED concurrency verification complete','Synthetic concurrent requests','Existing Oracle procedure lock prevented duplicate incidents',0,None],actor,(6,))
        root.call_proc('sp_change_status',[actor,result.incident_id,'CLOSED','SIMULATED verification closed'],actor)
        report['records'].append({'mode':mode,'source_key':key,'event_id':result.event_id,'alert_id':result.alert_id,'incident_id':result.incident_id,'status':'CLOSED'})
        message=mode+': four concurrent CS_APP calls produced one event/alert/incident; changed retry rejected; test case closed'
        report['checks'].append(message);print('PASS:',message,flush=True)
    report['after']=root.query_one('SELECT * FROM cs_owner.vw_dashboard_summary')
    assert report['after']['total_events']==report['before']['total_events']+2
    assert report['after']['open_incidents']==report['before']['open_incidents']
    report['status']='passed';report['verified_at']=datetime.now(timezone.utc).isoformat()
    Path('SIMULATOR_CONCURRENCY_VERIFICATION.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    root.close_pool()

if __name__=='__main__':main()
