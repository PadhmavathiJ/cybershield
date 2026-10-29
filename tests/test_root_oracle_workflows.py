"""Isolated tests: mocked Oracle boundary, never mock saved application data."""
from datetime import datetime, timezone
import pytest
import app as root

@pytest.fixture
def client(monkeypatch):
    def read_one(sql, params=None):
        if 'FROM CS_OWNER.APP_USER' in sql.upper():
            return {'user_id':7,'full_name':'Test','email':'test@example.invalid','role_code':root.role(),'is_active':1}
        return None
    monkeypatch.setattr(root,'safe_one',read_one)
    return root.app.test_client()

def signin(client,role):
    with client.session_transaction() as s:
        s['me']={'user_id':7,'role_code':role};s['_csrf']='unit-csrf'

@pytest.mark.parametrize('role,path',[
    ('AUDITOR','/events/new'),('AUDITOR','/incidents/new'),('AUDITOR','/assignments'),
    ('AUDITOR','/incidents/91/status'),('AUDITOR','/incidents/91/action'),('AUDITOR','/incidents/91/resolve'),
    ('AUDITOR','/incidents/91/reopen'),('AUDITOR','/evidence/upload'),('AUDITOR','/evidence/91/analysis'),
    ('AUDITOR','/alerts/91/triage'),('AUDITOR','/sla/91/escalate'),('AUDITOR','/assignments/91/end'),
    ('MANAGER','/incidents/91/status'),('MANAGER','/incidents/91/action'),('MANAGER','/incidents/91/resolve'),
    ('MANAGER','/evidence/upload'),('ANALYST','/assignments'),('ANALYST','/incidents/new')])
def test_forbidden_post_is_denied_before_database_write(client,monkeypatch,role,path):
    signin(client,role)
    def forbidden_call(*args,**kwargs):pytest.fail('Forbidden request reached a workflow procedure')
    monkeypatch.setattr(root,'call_proc',forbidden_call)
    assert client.post(path,data={'_csrf':'unit-csrf'}).status_code==403

@pytest.mark.parametrize('path',['/incidents/91','/evidence/91','/evidence/91/download'])
def test_unassigned_analyst_cannot_read_objects(client,path):
    signin(client,'ANALYST')
    assert client.get(path).status_code in (403,404)

def test_csrf_rejects_before_write(client):
    signin(client,'ADMIN')
    assert client.post('/events/new',data={}).status_code==400

def test_parameterized_filters_and_case_scope(monkeypatch):
    captured={}
    def read(sql,binds=None):captured.update(sql=sql,binds=binds);return []
    monkeypatch.setattr(root,'safe_read',read)
    with root.app.test_request_context('/incidents?q=a%25_b&status=CLOSED&severity=CRITICAL&from=2026-10-01&to=2026-10-29'):
        root.session['me']={'user_id':7,'role_code':'ANALYST'}
        root.filtered_read('SELECT * FROM CS_OWNER.INCIDENT',search=('title',),status='status',severity='severity',date='opened_at',scope='records.incident_id')
    assert 'a%_b' not in captured['sql']
    assert captured['binds']['search_text']=='%a\\%\\_b%'
    assert captured['binds']['scope_actor']==7
    assert captured['binds']['status_filter']=='CLOSED'
    assert 'SYS_EXTRACT_UTC(opened_at)' in captured['sql']
    assert 'inv.availability' in captured['sql']
    assert captured['binds']['date_from']==datetime(2026,10,1)

def test_scope_write_requires_current_assignment():
    with root.app.test_request_context('/'):
        root.session['me']={'user_id':7,'role_code':'ANALYST'}
        read,_=root.case_scope('i.incident_id')
        write,_=root.case_scope('i.incident_id',True)
        assert 'a.ended_at IS NULL' not in read
        assert 'a.ended_at IS NULL' in write and 'c.ended_at IS NULL' in write

class Var:
    def setvalue(self,pos,value):self.value=value
    def getvalue(self):return self.value
class Cursor:
    def __init__(self,con):self.con=con;self.closed=False
    def var(self,kind):v=Var();v.value=55;return v
    def callproc(self,name,params):
        assert self.con.client_identifier=='7'
        self.con.called=(name,params)
        if self.con.fail:raise RuntimeError('test procedure failure')
    def close(self):self.closed=True
class Connection:
    def __init__(self,fail=False):
        self.fail=fail;self.commits=0;self.rollbacks=0;self.closed=False;self.cur=Cursor(self)
    def cursor(self):return self.cur
    def commit(self):self.commits+=1
    def rollback(self):self.rollbacks+=1
    def close(self):self.closed=True

@pytest.mark.parametrize('fail',[False,True])
def test_procedure_transaction_actor_and_context_cleanup(monkeypatch,fail):
    con=Connection(fail)
    monkeypatch.setattr(root,'get_connection',lambda:con)
    params=[7,datetime.now(timezone.utc),None]
    if fail:
        with pytest.raises(RuntimeError):root.call_proc('sp_ingest_event',params,7,(2,))
        assert con.rollbacks==1 and con.commits==0
    else:
        assert root.call_proc('sp_ingest_event',params,7,(2,))=={2:55}
        assert con.commits==1 and con.rollbacks==0
        assert con.called[0]=='CS_OWNER.SP_INGEST_EVENT'
        assert isinstance(con.called[1][1],Var)
    assert con.client_identifier is None and con.closed and con.cur.closed

@pytest.mark.parametrize('role',['MANAGER','ANALYST','AUDITOR'])
def test_asset_admin_is_admin_only(client,role):
    signin(client,role)
    assert client.get('/admin/assets').status_code==403
    assert client.post('/admin/assets',data={'_csrf':'unit-csrf'}).status_code==403

def test_missing_owner_migration_is_explicit(client,monkeypatch):
    monkeypatch.setattr(root,'query_all',lambda *args,**kwargs:[])
    signin(client,'ADMIN')
    response=client.post('/admin/assets',data={'_csrf':'unit-csrf','kind':'server'})
    assert response.status_code==503
    assert b'V010_asset_admin.sql' in response.data

def test_user_access_page_has_only_oracle_roles(client,monkeypatch):
    signin(client,'ADMIN')
    monkeypatch.setattr(root,'safe_read',lambda *args,**kwargs:[])
    response=client.get('/admin/users')
    assert response.status_code==200
    assert b'Create engineer' not in response.data
    assert b'complainer' not in response.data

@pytest.mark.parametrize('template,query,context,expected',[
    ('form.html','/evidence/upload?incident_id=17',{'upload':True,'incidents':[{'incident_id':17,'title':'Assigned case'}]},'value="17" selected'),
    ('incident_form.html','/incidents/new?alert_id=23',{'alerts':[{'alert_id':23,'severity':'HIGH','status':'NEW'}],'campaigns':[]},'value="23" selected'),
])
def test_linked_form_preselection_renders_without_undefined_int(template,query,context,expected):
    from flask import render_template
    with root.app.test_request_context(query):
        root.session['me']={'user_id':7,'role_code':'ADMIN'}
        html=render_template(template,**context)
        assert expected in html
