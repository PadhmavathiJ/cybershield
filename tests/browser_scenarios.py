"""Resumable acceptance scenarios used only by verify_oracle_browser.py."""
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from playwright.sync_api import expect
from simulator import ingest_simulation


def form(page,selector):
    return page.locator('form').filter(has=page.locator(selector))

def oracle(s,sql,binds=None):return s['root'].query_one(sql,binds)

def case(s):return oracle(s,'SELECT status FROM cs_owner.incident WHERE incident_id=:id',{'id':s['report']['ids']['incident_id']})['status']

def dashboard(s,page,values):
    page.goto(s['base']+'/dashboard')
    actual=page.locator('.soc-metrics article strong').all_text_contents()
    keys=['active_servers','total_events','critical_alerts','open_incidents','active_investigators','sla_breaches']
    assert [int(v.strip()) for v in actual]==[int(values[k]) for k in keys]


def navigation(s):
    pages=s['pages'];base=s['base']
    nav={role:[v.strip() for v in page.locator('nav.primary-nav a').all_text_contents()] for role,page in pages.items()}
    s['report']['navigation']=nav
    assert 'Asset administration' in nav['ADMIN'] and 'User access' in nav['ADMIN']
    assert 'Assignments' in nav['MANAGER'] and 'Audit trail' not in nav['MANAGER']
    assert 'My investigations' in nav['ANALYST'] and 'Assignments' not in nav['ANALYST'] and 'Settings' not in nav['ANALYST']
    assert 'Audit trail' in nav['AUDITOR'] and 'Asset administration' not in nav['AUDITOR']
    for role,page in pages.items():
        links=page.locator('nav.primary-nav a').evaluate_all('(links)=>links.map(a=>a.getAttribute("href"))')
        for href in links:assert page.goto(base+href).status==200
        if role!='ADMIN':assert page.goto(base+'/admin/assets').status==403
        if role=='ANALYST':assert page.goto(base+'/audit').status==403
        page.goto(base+'/dashboard')
    s['baseline']=oracle(s,'SELECT * FROM cs_owner.vw_dashboard_summary')
    s['report']['dashboard_before']=s['baseline'];dashboard(s,pages['ADMIN'],s['baseline'])
    s['passed']('Distinct role navigation links render; forbidden administration/audit routes return 403')


def assets(s):
    page=s['pages']['ADMIN'];base=s['base'];ids=s['report']['ids'];hostname='sim-browser-'+s['key']
    page.goto(base+'/admin/assets')
    record=oracle(s,'SELECT server_id FROM cs_owner.server WHERE hostname=:hostname',{'hostname':hostname})
    if not record:
        f=form(page,'input[name=kind][value=server]')
        for label,value in [('Hostname',hostname),('Operating system','SIMULATED browser OS'),('Department','SIMULATED browser acceptance')]:
            f.get_by_label(label,exact=True).fill(value)
        f.locator('select[name=criticality]').select_option('HIGH')
        f.get_by_role('button',name='Save server in Oracle',exact=True).click()
        record=oracle(s,'SELECT server_id FROM cs_owner.server WHERE hostname=:hostname',{'hostname':hostname})
    assert record;ids['server_id']=int(record['server_id'])
    page.locator(f'a[href="/admin/assets?server_id={ids["server_id"]}"]').click()
    f=form(page,'input[name=kind][value=server]');f.get_by_label('Department',exact=True).fill('SIMULATED browser verified')
    f.get_by_role('button',name='Save server in Oracle',exact=True).click()
    assert oracle(s,'SELECT department FROM cs_owner.server WHERE server_id=:id',{'id':ids['server_id']})['department']=='SIMULATED browser verified'
    if 'ip_text' not in s:
        existing={r['ip_text'] for r in s['root'].query_all('SELECT ip_text FROM cs_owner.ip_address')}
        s['ip_text']=next('198.51.100.'+str(i) for i in range(254,0,-1) if '198.51.100.'+str(i) not in existing)
    record=oracle(s,'SELECT ip_id FROM cs_owner.ip_address WHERE ip_text=:ip',{'ip':s['ip_text']})
    if not record:
        f=form(page,'input[name=kind][value=ip]');f.get_by_label('IPv4 or IPv6',exact=True).fill(s['ip_text'])
        f.get_by_role('button',name='Save IP in Oracle',exact=True).click()
        record=oracle(s,'SELECT ip_id FROM cs_owner.ip_address WHERE ip_text=:ip',{'ip':s['ip_text']})
    assert record;ids['ip_id']=int(record['ip_id'])
    page.locator(f'a[href="/admin/assets?ip_id={ids["ip_id"]}"]').click()
    f=form(page,'input[name=kind][value=ip]');f.get_by_label('Country code (optional)',exact=True).fill('ZZ')
    f.get_by_role('button',name='Save IP in Oracle',exact=True).click()
    assert oracle(s,'SELECT country_code FROM cs_owner.ip_address WHERE ip_id=:id',{'id':ids['ip_id']})['country_code']=='ZZ'
    s['passed']('Admin browser server/IP creation and updates persisted independently in Oracle')


def simulation(s):
    page=s['pages']['ADMIN'];ids=s['report']['ids'];base=s['base']
    page.goto(base+'/events');page.get_by_role('link',name='Submit simulated event',exact=True).click()
    policy=oracle(s,"SELECT number_value FROM cs_owner.soc_policy WHERE policy_key='alert_threshold'")['number_value'];s['threshold']=policy
    s['report']['detection_rule']={'field':'severity_score','comparison':'>=','policy':'SOC_POLICY.alert_threshold','value':policy,'scope':'labelled simulator','retry':'identical source key, time and payload reuse event/alert/incident'}
    if 'payload' not in s:
        page.locator('select[name=server_id]').select_option(str(ids['server_id']))
        page.locator('select[name=source_ip_id]').select_option(str(ids['ip_id']))
        page.get_by_label('Severity score',exact=True).fill('99')
        page.get_by_label('Simulation details',exact=True).fill('SIMULATED browser lifecycle '+s['key'])
        s['payload']=page.locator('form.soc-form').evaluate('(f)=>Object.fromEntries(new FormData(f))')
        ids['source_event_key']=s['payload']['source_event_key']
    def restore():
        for name,value in s['payload'].items():
            if name=='_csrf':continue
            control=page.locator(f'form.soc-form [name="{name}"]')
            if control.evaluate('(el)=>el.tagName')=='SELECT':control.select_option(value)
            else:control.fill(value)
    restore();page.get_by_role('button',name='Save simulated event to Oracle',exact=True).click()
    page.wait_for_url('**/incidents/*');ids['incident_id']=int(page.url.rsplit('/',1)[1])
    record=oracle(s,'SELECT e.event_id,a.alert_id FROM cs_owner.security_event e JOIN cs_owner.alert a ON a.event_id=e.event_id WHERE e.source_event_key=:key',{'key':ids['source_event_key']})
    assert record;ids['event_id']=int(record['event_id']);ids['alert_id']=int(record['alert_id'])
    page.goto(base+'/events/new');restore()
    page.get_by_role('button',name='Save simulated event to Oracle',exact=True).click()
    page.wait_for_url('**/incidents/'+str(ids['incident_id']))
    assert oracle(s,'SELECT COUNT(*) AS n FROM cs_owner.incident_alert WHERE alert_id=:id',{'id':ids['alert_id']})['n']==1
    values=oracle(s,'SELECT * FROM cs_owner.vw_dashboard_summary');baseline=s['baseline']
    assert values['active_servers']==baseline['active_servers']+1
    assert values['total_events']==baseline['total_events']+1
    assert values['open_incidents']==baseline['open_incidents']+1
    s['report']['dashboard_after_ingestion']=values;dashboard(s,page,values)
    s['passed']('Browser simulator automatically created event/alert/incident; browser retry reused it; dashboard counts increased correctly')


def assignment(s):
    ids=s['report']['ids'];base=s['base'];manager=s['pages']['MANAGER'];analyst=s['pages']['ANALYST'];case_path='/incidents/'+str(ids['incident_id'])
    if not oracle(s,'SELECT a.assignment_id FROM cs_owner.incident_assignment a JOIN cs_owner.investigation_cycle c ON c.cycle_id=a.cycle_id WHERE c.incident_id=:id AND a.ended_at IS NULL',{'id':ids['incident_id']}):
        manager.goto(base+'/assignments');f=form(manager,'select[name=investigator_id]')
        f.locator('select[name=incident_id]').select_option(str(ids['incident_id']))
        f.locator('select[name=investigator_id]').select_option(str(s['users']['ANALYST']['investigator_id']))
        f.locator('select[name=assignment_role]').select_option('LEAD');f.get_by_role('button',name='Assign in Oracle',exact=True).click()
    row=oracle(s,'SELECT a.assignment_id FROM cs_owner.incident_assignment a JOIN cs_owner.investigation_cycle c ON c.cycle_id=a.cycle_id WHERE c.incident_id=:id AND a.ended_at IS NULL',{'id':ids['incident_id']});assert row
    ids['assignment_id']=int(row['assignment_id'])
    for role in ['MANAGER','AUDITOR']:
        page=s['pages'][role];page.goto(base+case_path)
        assert page.get_by_role('button',name='Update status',exact=True).count()==0
        csrf=page.locator('form[action="/logout"] input[name=_csrf]').input_value()
        status=page.evaluate("""async ({path,csrf})=>{const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({_csrf:csrf,status:'TRIAGED',reason:'deny browser check'})});return r.status;}""",{'path':case_path+'/status','csrf':csrf})
        assert status==403
    analyst.goto(base+'/dashboard')
    analyst.get_by_role('link',name=f'#{ids["incident_id"]} SIMULATED threshold event {ids["source_event_key"]}',exact=True).click()
    s['passed']('Manager browser assignment persisted; assigned Analyst opened My investigations; Manager/Auditor lifecycle POSTs denied')


def investigation(s):
    page=s['pages']['ANALYST'];ids=s['report']['ids'];base=s['base'];case_path='/incidents/'+str(ids['incident_id'])
    page.goto(base+case_path)
    def transition(target):
        f=form(page,'select[name=status]');f.locator('select[name=status]').select_option(target)
        f.get_by_label('Reason',exact=True).fill('SIMULATED browser '+target)
        f.get_by_role('button',name='Update status',exact=True).click();assert case(s)==target
    if case(s)=='OPEN':transition('TRIAGED')
    if case(s)=='TRIAGED':transition('INVESTIGATING')
    if case(s)=='INVESTIGATING':
        actions=oracle(s,'SELECT COUNT(*) AS n FROM cs_owner.response_action a JOIN cs_owner.investigation_cycle c ON c.cycle_id=a.cycle_id WHERE c.incident_id=:id',{'id':ids['incident_id']})['n']
        if not actions:
            f=form(page,'input[name=action_type]')
            f.get_by_label('Action type',exact=True).fill('SIMULATED browser investigation')
            f.get_by_label('Description',exact=True).fill('Reviewed linked synthetic traffic and planned test isolation.')
            f.get_by_label('Outcome',exact=True).fill('Simulation only; no production changes.')
            f.get_by_role('button',name='Record action',exact=True).click()
        evidence=oracle(s,'SELECT evidence_id FROM cs_owner.evidence WHERE incident_id=:id',{'id':ids['incident_id']})
        if not evidence:
            page.get_by_role('link',name='Register evidence',exact=True).click()
            page.locator('select[name=incident_id]').select_option(str(ids['incident_id']))
            page.locator('select[name=evidence_type]').select_option('LOG')
            page.locator('select[name=sensitivity]').select_option('INTERNAL')
            page.get_by_label('File',exact=True).set_input_files({'name':'simulated-browser-evidence.txt','mimeType':'text/plain','buffer':('SIMULATED browser evidence '+ids['source_event_key']).encode()})
            page.get_by_role('button',name='Upload and register evidence',exact=True).click()
            evidence=oracle(s,'SELECT evidence_id FROM cs_owner.evidence WHERE incident_id=:id',{'id':ids['incident_id']})
        assert evidence;ids['evidence_id']=int(evidence['evidence_id'])
        page.goto(base+'/evidence/'+str(ids['evidence_id']))
        if not oracle(s,'SELECT COUNT(*) AS n FROM cs_owner.forensic_analysis WHERE evidence_id=:id',{'id':ids['evidence_id']})['n']:
            for label,value in [('Technique','SIMULATED browser log analysis'),('Findings','Evidence agrees with the labelled simulated event.'),('Indicators',ids['source_event_key']),('Confidence','98')]:page.get_by_label(label,exact=True).fill(value)
            page.get_by_role('button',name='Save analysis in Oracle',exact=True).click()
        with page.expect_download() as download:page.get_by_role('link',name='Download evidence',exact=True).click()
        assert download.value.suggested_filename=='simulated-browser-evidence.txt'
        assert oracle(s,'SELECT COUNT(*) AS n FROM cs_owner.chain_of_custody WHERE evidence_id=:id',{'id':ids['evidence_id']})['n']==1
        assert oracle(s,'SELECT COUNT(*) AS n FROM cs_owner.forensic_analysis WHERE evidence_id=:id',{'id':ids['evidence_id']})['n']==1
        page.goto(base+case_path);transition('CONTAINED')
    if case(s)=='CONTAINED':
        f=form(page,'textarea[name=root_cause]')
        for label,value in [('Summary','SIMULATED browser lifecycle verified'),('Root cause','Labelled synthetic severity threshold event'),('Lessons learned','Browser actions and Oracle records agree'),('Financial loss','0.00')]:f.get_by_label(label,exact=True).fill(value)
        f.get_by_role('button',name='Resolve incident',exact=True).click();assert case(s)=='RESOLVED'
    if case(s)=='RESOLVED':transition('CLOSED')
    history=s['root'].query_all('SELECT h.to_status FROM cs_owner.incident_status_history h JOIN cs_owner.investigation_cycle c ON c.cycle_id=h.cycle_id WHERE c.incident_id=:id ORDER BY h.history_id',{'id':ids['incident_id']})
    assert [r['to_status'] for r in history]==['OPEN','TRIAGED','INVESTIGATING','CONTAINED','RESOLVED','CLOSED']
    s['passed']('Assigned Analyst browser lifecycle, response, evidence upload/download, custody, analysis, resolution and six-stage history persisted')


def filters(s):
    auditor=s['pages']['AUDITOR'];admin=s['pages']['ADMIN'];base=s['base'];ids=s['report']['ids']
    auditor.goto(base+'/incidents');auditor.get_by_label('Search',exact=True).fill(ids['source_event_key'])
    auditor.locator('select[name=status]').select_option('CLOSED');auditor.locator('select[name=severity]').select_option('CRITICAL')
    auditor.get_by_role('button',name='Apply filters',exact=True).click();expect(auditor.locator('tbody tr')).to_have_count(1)
    auditor.get_by_role('link',name=str(ids['incident_id']),exact=True).click()
    assert 'SIMULATED browser lifecycle verified' in auditor.locator('.page-content').inner_text()
    assert auditor.locator('.page-content form[method=post]').count()==0
    auditor.get_by_role('link',name='Audit trail',exact=True).click();auditor.get_by_label('Search',exact=True).fill(str(ids['incident_id']))
    auditor.get_by_role('button',name='Apply filters',exact=True).click();assert auditor.locator('tbody td.empty').count()==0
    auditor.get_by_role('link',name='Reports',exact=True).click()
    with auditor.expect_download() as csv:auditor.get_by_role('link',name='Export CSV',exact=True).click()
    assert csv.value.suggested_filename=='cybershield-report.csv'
    for name in ['incidents','alerts','events','assignments','evidence','audit','response','sla','servers']:
        s['phase']='filters: '+name
        admin.goto(base+'/'+name);admin.get_by_label('Search',exact=True).fill('no-match-'+s['key'])
        admin.get_by_role('button',name='Apply filters',exact=True).click();expect(admin.locator('tbody td.empty')).to_have_count(1)
        admin.get_by_role('link',name='Clear',exact=True).click();assert '?' not in admin.url
    admin.goto(base+'/events');admin.get_by_label('Minimum score',exact=True).fill('99');admin.get_by_label('Maximum score',exact=True).fill('100')
    admin.get_by_role('button',name='Apply filters',exact=True).click();assert admin.locator('tbody td.empty').count()==0
    admin.goto(base+'/incidents');admin.get_by_label('From (UTC)',exact=True).fill('2099-01-01');admin.get_by_label('To (UTC)',exact=True).fill('2099-01-02')
    admin.get_by_role('button',name='Apply filters',exact=True).click();expect(admin.locator('tbody td.empty')).to_have_count(1)
    s['passed']('Auditor browser history/audit/report CSV and all nine search/Clear forms; status, severity, dates and score filters verified')


def retries_and_audit(s):
    ids=s['report']['ids'];payload=s['payload'];actor=int(s['users']['ADMIN']['user_id']);admin=s['pages']['ADMIN'];base=s['base']
    kwargs=dict(source_key=ids['source_event_key'],server_id=ids['server_id'],source_ip_id=ids['ip_id'],attack_type_id=int(payload['attack_type_id']),event_at=datetime.fromisoformat(payload['event_at']),protocol=payload['protocol'],packet_count=int(payload['packet_count']),bytes_in=int(payload['bytes_in']),bytes_out=int(payload['bytes_out']),severity_score=99,details=payload['details'])
    with ThreadPoolExecutor(max_workers=4) as executor:results=list(executor.map(lambda _:ingest_simulation(actor,**kwargs),range(4)))
    assert all(r.incident_id==ids['incident_id'] and r.event_id==ids['event_id'] for r in results)
    if 'below_threshold_event_id' not in ids:
        admin.goto(base+'/events/new');ids['below_threshold_source_key']=admin.locator('[name=source_event_key]').input_value()
        admin.locator('select[name=server_id]').select_option(str(ids['server_id']));admin.locator('select[name=source_ip_id]').select_option(str(ids['ip_id']))
        admin.get_by_label('Severity score',exact=True).fill(str(float(s['threshold'])-.01))
        admin.get_by_label('Simulation details',exact=True).fill('SIMULATED below threshold browser check')
        admin.get_by_role('button',name='Save simulated event to Oracle',exact=True).click();assert '/events/' in admin.url
        record=oracle(s,'SELECT e.event_id,(SELECT COUNT(*) FROM cs_owner.alert a WHERE a.event_id=e.event_id) AS alerts FROM cs_owner.security_event e WHERE e.source_event_key=:key',{'key':ids['below_threshold_source_key']})
        assert record and record['alerts']==0;ids['below_threshold_event_id']=int(record['event_id'])
    for entity,id_name in [('server','server_id'),('ip_address','ip_id')]:
        audit=s['root'].query_all('SELECT action,actor_user_id FROM cs_owner.audit_log WHERE entity_name=:entity AND entity_id=:id ORDER BY audit_id',{'entity':entity,'id':ids[id_name]})
        assert [r['action'] for r in audit][:2]==['INSERT','UPDATE'] and all(r['actor_user_id']==actor for r in audit)
    for entity,id_name in [('security_event','event_id'),('alert','alert_id'),('incident','incident_id'),('evidence','evidence_id')]:
        audit=s['root'].query_all('SELECT actor_user_id FROM cs_owner.audit_log WHERE entity_name=:entity AND entity_id=:id',{'entity':entity,'id':ids[id_name]})
        assert audit and all(r['actor_user_id'] is not None for r in audit)
    assert oracle(s,'SELECT COUNT(*) AS n FROM cs_owner.incident_alert WHERE alert_id=:id',{'id':ids['alert_id']})['n']==1
    s['passed']('Four parallel Oracle retries reused the same closed incident; below-threshold browser event has no alert/incident; audit actors verified')


def finish(s):
    admin=s['pages']['ADMIN'];auditor=s['pages']['AUDITOR'];ids=s['report']['ids'];base=s['base']
    admin.goto(base+f'/admin/assets?server_id={ids["server_id"]}')
    f=form(admin,'input[name=kind][value=server]');f.locator('select[name=is_active]').select_option('0');f.get_by_role('button',name='Save server in Oracle',exact=True).click()
    values=oracle(s,'SELECT * FROM cs_owner.vw_dashboard_summary');s['report']['dashboard_final']=values
    assert values['active_servers']==s['baseline']['active_servers']
    assert values['total_events']==s['baseline']['total_events']+2
    assert values['open_incidents']==s['baseline']['open_incidents']
    dashboard(s,admin,values);dashboard(s,auditor,values)
    s['passed']('Final Admin/Auditor dashboard equals Oracle: events +2, open incidents and active servers back at baseline')
    auditor.goto(base+'/incidents/'+str(ids['incident_id']))
    folder=s['ROOT']/'verification-artifacts';folder.mkdir(exist_ok=True)
    screenshot=folder/'auditor-closed-simulated-case.png';auditor.screenshot(path=str(screenshot),full_page=True)
    s['report']['screenshots'].append(str(screenshot.relative_to(s['ROOT'])))
    admin.goto(base+'/admin/users');assert admin.locator('.page-content form').count()==0
    s['report']['user_provisioning']='Not implemented; read-only account inventory'
    for role,page in s['pages'].items():
        if page.url.endswith('/login'):continue
        page.reload()
        if role=='ANALYST':
            page.set_viewport_size({'width':390,'height':844});page.reload()
            expect(page.get_by_role('button',name='Sign out',exact=True)).to_be_visible()
        page.get_by_role('button',name='Sign out',exact=True).click();assert page.url.endswith('/login')
    s['passed']('All four browser logout buttons work, including Analyst at mobile size; User access remains accurately read-only')


def run(s):
    s['root'].app.jinja_env.cache.clear()
    for phase in [navigation,assets,simulation,assignment,investigation,filters,retries_and_audit,finish]:
        if phase.__name__ in s['done']:continue
        s['phase']=phase.__name__
        phase(s)
        s['done'].add(phase.__name__)
