"""Mocked transaction tests; runtime persistence remains exclusively Oracle."""
from datetime import datetime,timezone
from types import SimpleNamespace
import pytest
import oracledb
import simulator

class Var:
    def __init__(self):self.value=None
    def setvalue(self,pos,value):self.value=value
    def getvalue(self):return self.value
class Cursor:
    def __init__(self,con):self.con=con;self.calls=[];self.sql=[];self.reads=0;self.closed=False
    def var(self,*args):return Var()
    def callproc(self,name,params):
        assert self.con.client_identifier=='101';self.calls.append((name,params))
        if name.endswith('SP_INGEST_EVENT'):
            assert len(params)==14 and isinstance(params[5],Var)
            params[12].value=801;params[13].value=901 if self.con.qualifies else None
        elif name.endswith('SP_CREATE_INCIDENT'):
            assert len(params)==7 and params[0]==101 and params[1]==901
            assert params[2].startswith('SIMULATED') and params[5] is None
            if self.con.failure:raise oracledb.DatabaseError(SimpleNamespace(code=self.con.failure))
            params[6].value=1001
    def execute(self,sql,binds):
        self.sql.append((sql,binds));assert binds=={'alert_id':901}
        if 'INCIDENT_ALERT' in sql:self.reads+=1
    def fetchone(self):
        if 'SELECT severity' in self.sql[-1][0]:return ('CRITICAL',)
        if self.con.linked or (self.con.failure==20009 and self.reads==2 and self.con.race_committed):return (1001,)
        return None
    def close(self):self.closed=True
class Connection:
    def __init__(self,qualifies=True,linked=False,failure=None,race_committed=True):
        self.qualifies=qualifies;self.linked=linked;self.failure=failure;self.race_committed=race_committed
        self.commits=0;self.rollbacks=0;self.closed=False;self.cur=Cursor(self)
    def cursor(self):return self.cur
    def commit(self):self.commits+=1
    def rollback(self):self.rollbacks+=1
    def close(self):self.closed=True

@pytest.fixture
def payload():
    return dict(source_key='unit-simulation',server_id=1,source_ip_id=2,attack_type_id=3,event_at=datetime.now(timezone.utc),protocol='TCP',packet_count=1,bytes_in=2,bytes_out=3,severity_score=99,details='SIMULATED unit test')

@pytest.mark.parametrize('qualifies,linked',[(True,False),(True,True),(False,False)])
def test_threshold_ingestion_and_retry_commit_once(monkeypatch,payload,qualifies,linked):
    con=Connection(qualifies,linked);monkeypatch.setattr(simulator,'get_connection',lambda:con)
    result=simulator.ingest_simulation(101,**payload)
    assert result.event_id==801 and result.incident_id==(1001 if qualifies else None)
    assert len(con.cur.calls)==(2 if qualifies and not linked else 1)
    assert con.commits==1 and con.rollbacks==0
    assert con.client_identifier is None and con.closed and con.cur.closed

@pytest.mark.parametrize('failure,race_committed',[(20009,False),(20004,True),(1031,True)])
def test_incident_failure_rolls_back_ingestion_and_alert(monkeypatch,payload,failure,race_committed):
    con=Connection(failure=failure,race_committed=race_committed);monkeypatch.setattr(simulator,'get_connection',lambda:con)
    with pytest.raises(oracledb.DatabaseError):simulator.ingest_simulation(101,**payload)
    assert con.rollbacks==1 and con.commits==0
    assert con.client_identifier is None and con.closed and con.cur.closed

def test_concurrent_duplicate_uses_procedure_locked_link(monkeypatch,payload):
    con=Connection(failure=20009);monkeypatch.setattr(simulator,'get_connection',lambda:con)
    assert simulator.ingest_simulation(101,**payload).incident_id==1001
    assert con.commits==1 and con.cur.reads==2
    assert not any('INSERT ' in sql or 'UPDATE ' in sql for sql,binds in con.cur.sql)

def test_invalid_actor_and_timezone_fail_before_connection(monkeypatch,payload):
    monkeypatch.setattr(simulator,'get_connection',lambda:pytest.fail('Invalid request acquired a connection'))
    with pytest.raises(PermissionError):simulator.ingest_simulation(None,**payload)
    payload['event_at']=datetime.now()
    with pytest.raises(ValueError):simulator.ingest_simulation(101,**payload)
