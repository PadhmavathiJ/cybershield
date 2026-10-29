"""Opt-in CS_APP/frontend verification. Creates only labelled new test assets."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import json
import secrets
from datetime import datetime,timezone
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from urllib.parse import urlencode
import app as root


def main():
    base='http://127.0.0.1:5000'
    users={role:root.query_one('SELECT user_id,role_code FROM cs_owner.app_user WHERE role_code=:role AND is_active=1 ORDER BY user_id FETCH FIRST 1 ROW ONLY',{'role':role}) for role in ['ADMIN','MANAGER','ANALYST','AUDITOR']}
    csrf=secrets.token_hex(24)
    serializer=root.app.session_interface.get_signing_serializer(root.app)
    def http(role,path,data=None):
        user=users[role]
        cookie=serializer.dumps({'me':{'user_id':int(user['user_id']),'role_code':role},'_csrf':csrf})
        headers={'Cookie':'session='+cookie}
        raw=None
        if data is not None:
            raw=urlencode(dict(data,_csrf=csrf)).encode();headers['Content-Type']='application/x-www-form-urlencoded'
        try:
            with urlopen(Request(base+path,data=raw,headers=headers),timeout=20) as response:return response.status,response.read().decode()
        except HTTPError as response:return response.code,response.read().decode()
    report_path=Path('ASSET_MIGRATION_VERIFICATION.json')
    report=json.loads(report_path.read_text());checks=[]
    def passed(message):checks.append(message);print('PASS:',message,flush=True)
    con=root.get_connection()
    with con.cursor() as cur:
        cur.execute('SELECT user FROM dual');assert cur.fetchone()[0]=='CS_APP'
        cur.execute("SELECT privilege FROM user_sys_privs");privileges=[r[0] for r in cur.fetchall()];assert set(privileges)=={'CREATE SESSION'}
    con.close()
    grants=root.query_all("SELECT table_name,privilege FROM all_tab_privs WHERE table_schema='CS_OWNER' AND grantee='CS_APP' AND table_name IN ('SP_SAVE_SERVER','SP_SAVE_IP') ORDER BY table_name")
    assert grants==[{'table_name':'SP_SAVE_IP','privilege':'EXECUTE'},{'table_name':'SP_SAVE_SERVER','privilege':'EXECUTE'}]
    assert not root.query_all("SELECT table_name,privilege FROM user_tab_privs WHERE owner='CS_OWNER' AND grantee='CS_APP' AND privilege IN ('INSERT','UPDATE','DELETE')")
    passed('CS_APP runtime identity, CREATE SESSION only, EXECUTE grants and absence of direct table DML verified')
    code,html=http('ADMIN','/admin/assets');assert code==200 and 'Save server in Oracle' in html and 'Save IP in Oracle' in html
    for role in ['MANAGER','ANALYST','AUDITOR']:
        assert http(role,'/admin/assets')[0]==403
        assert http(role,'/admin/assets',{'kind':'server'})[0]==403
    passed('Asset forms enabled after owner migration; non-Admin GET/POST denied')
    key=secrets.token_hex(6);hostname='sim-asset-check-'+key
    server={'kind':'server','target_id':'','hostname':hostname,'os_name':'SIMULATED verification OS','department':'SIMULATED asset verification','criticality':'LOW','is_active':'1'}
    code,html=http('ADMIN','/admin/assets',server);assert code==200,(code,'server create failed')
    record=root.query_one('SELECT server_id,hostname,department,is_active FROM cs_owner.server WHERE hostname=:hostname',{'hostname':hostname});assert record and record['is_active']==1
    server_id=int(record['server_id'])
    server.update(target_id=server_id,department='SIMULATED verification complete',is_active='0')
    assert http('ADMIN','/admin/assets',server)[0]==200
    updated=root.query_one('SELECT department,is_active FROM cs_owner.server WHERE server_id=:server_id',{'server_id':server_id});assert updated=={'department':'SIMULATED verification complete','is_active':0}
    passed('Frontend server create/update persisted through CS_APP; new simulation server left inactive')
    existing={row['ip_text'] for row in root.query_all('SELECT ip_text FROM cs_owner.ip_address')}
    ip=next('192.0.2.'+str(i) for i in range(254,0,-1) if '192.0.2.'+str(i) not in existing)
    address={'kind':'ip','target_id':'','ip_text':ip,'country_code':'','is_simulated':'1'}
    assert http('ADMIN','/admin/assets',address)[0]==200
    record=root.query_one('SELECT ip_id,country_code,is_simulated FROM cs_owner.ip_address WHERE ip_text=:ip_text',{'ip_text':ip});assert record and record['is_simulated']==1
    ip_id=int(record['ip_id'])
    address.update(target_id=ip_id,country_code='ZZ')
    assert http('ADMIN','/admin/assets',address)[0]==200
    updated=root.query_one('SELECT country_code,is_simulated FROM cs_owner.ip_address WHERE ip_id=:ip_id',{'ip_id':ip_id});assert updated=={'country_code':'ZZ','is_simulated':1}
    passed('Frontend IP create/update persisted through CS_APP using a simulated documentation-range address')
    # Verify database authorization independently of frontend decorators.
    for role in ['MANAGER','ANALYST','AUDITOR']:
        actor=int(users[role]['user_id'])
        try:
            root.call_proc('sp_save_server',[actor,None,'must-not-save-'+key,'OS','Denied','LOW',1,None],actor,(7,))
            raise AssertionError('Non-Admin procedure call was accepted')
        except root.oracledb.DatabaseError as exc:assert exc.args[0].code==20007
    assert not root.query_all('SELECT server_id FROM cs_owner.server WHERE hostname=:hostname',{'hostname':'must-not-save-'+key})
    # Duplicate asset rejection must preserve the prior record and avoid phantom audits.
    before=root.query_one("SELECT COUNT(*) AS n FROM cs_owner.audit_log WHERE entity_name='server' AND entity_id=:entity_id",{'entity_id':server_id})['n']
    duplicate=dict(server,target_id='')
    assert http('ADMIN','/admin/assets',duplicate)[0]==409
    after=root.query_one("SELECT COUNT(*) AS n FROM cs_owner.audit_log WHERE entity_name='server' AND entity_id=:entity_id",{'entity_id':server_id})['n']
    assert before==after==2
    passed('Database ADMIN guard rejected Manager/Analyst/Auditor calls; duplicate save rolled back without extra audit')
    audit_counts={}
    for entity,entity_id in [('server',server_id),('ip_address',ip_id)]:
        rows=root.query_all('SELECT action,actor_user_id,before_data,after_data FROM cs_owner.audit_log WHERE entity_name=:entity AND entity_id=:entity_id ORDER BY audit_id',{'entity':entity,'entity_id':entity_id})
        assert [r['action'] for r in rows]==['INSERT','UPDATE']
        assert all(int(r['actor_user_id'])==int(users['ADMIN']['user_id']) for r in rows)
        assert all(json.loads(r['after_data'])=={'fields':'redacted','workflow':'asset_admin'} for r in rows)
        audit_counts[entity]=len(rows)
    passed('Four authenticated, redacted Oracle audit records verified for server/IP create/update')
    con=root.get_connection()
    with con.cursor() as cur:
        cur.execute("SELECT SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') FROM dual");assert cur.fetchone()[0] is None
    con.close();passed('CS_APP pooled actor context cleared after successful and rejected asset writes')
    report.update(asset_checks=checks,test_server_id=server_id,test_server_hostname=hostname,test_server_active=False,test_ip_id=ip_id,test_ip=ip,audit_counts=audit_counts,asset_verified_at=datetime.now(timezone.utc).isoformat())
    report_path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('Verified new test assets:',server_id,ip_id,flush=True)
    root.close_pool()

if __name__=='__main__':main()
