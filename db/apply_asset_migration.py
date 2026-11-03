"""Apply the two reviewed asset scripts through a genuine CS_OWNER Python session.
Credentials are requested with a local masked dialog, never logged or persisted.
Only the SQL*Plus constructs used in these two scripts are supported; unknown ones fail.
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def sql_end(text):
    """Find a top-level terminator, respecting SQL quoted text and comments."""
    quote=None;line_comment=False;block_comment=False;i=0
    while i<len(text):
        char=text[i];pair=text[i:i+2]
        if line_comment:
            if char=='\n':line_comment=False
        elif block_comment:
            if pair=='*/':block_comment=False;i+=1
        elif quote:
            if char==quote:
                if i+1<len(text) and text[i+1]==quote:i+=1
                else:quote=None
        elif pair=='--':line_comment=True;i+=1
        elif pair=='/*':block_comment=True;i+=1
        elif char in ("'",'"'):quote=char
        elif char==';':return i
        i+=1
    return None


def parse_script(text):
    buffer=[];plsql=False
    for line in text.splitlines():
        stripped=line.strip()
        if not buffer:
            if not stripped or stripped.startswith('--'):continue
            upper=stripped.upper()
            if upper=='WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK':
                yield 'on_error_rollback',None;continue
            if upper=='SET DEFINE OFF':yield 'define_off',None;continue
            if upper.startswith('SHOW ERRORS PROCEDURE '):
                name=stripped.split()[-1].upper()
                if not re.fullmatch(r'SP_SAVE_(SERVER|IP)',name):raise ValueError('Unexpected SHOW ERRORS target')
                yield 'show_errors',name;continue
            if upper.startswith('PROMPT '):yield 'prompt',stripped[7:];continue
            if upper=='EXIT':yield 'exit',None;return
            if upper=='/':raise ValueError('Unexpected slash without a PL/SQL block')
            plsql=bool(re.match(r'^(BEGIN\b|DECLARE\b|CREATE\s+PROCEDURE\b)',upper))
            if not plsql and not re.match(r'^(INSERT\s+INTO\s+SCHEMA_MIGRATION\b|COMMIT\b|GRANT\s+EXECUTE\b)',upper):
                raise ValueError('Unsupported script statement/directive')
        if plsql and stripped=='/':
            yield 'plsql','\n'.join(buffer)
            buffer=[];plsql=False;continue
        buffer.append(line)
        if not plsql:
            statement='\n'.join(buffer);end=sql_end(statement)
            if end is not None:
                if statement[end+1:].strip():raise ValueError('Unexpected text following SQL terminator')
                yield 'sql',statement[:end]
                buffer=[]
    if buffer:raise ValueError('Unterminated SQL or missing standalone PL/SQL slash')


def run_script(con,path):
    operations=list(parse_script(path.read_text(encoding='utf-8')))
    print('Applying',path.name,'with',sum(kind in ('sql','plsql') for kind,_ in operations),'database statements',flush=True)
    with con.cursor() as cur:
        for kind,value in operations:
            if kind in ('on_error_rollback','define_off'):continue
            if kind=='exit':break
            if kind=='prompt':print(value,flush=True);continue
            if kind=='show_errors':
                cur.execute("SELECT line,position,text FROM user_errors WHERE name=:object_name AND type='PROCEDURE' AND attribute='ERROR' ORDER BY sequence",{'object_name':value})
                errors=cur.fetchall()
                if errors:
                    for error in errors:print('COMPILE ERROR',value,*error,flush=True)
                    raise RuntimeError('Procedure compilation failed')
                print(value,'compilation errors: none',flush=True)
                continue
            if value.strip().upper()=='COMMIT':con.commit()
            else:cur.execute(value)


def main():
    from dotenv import load_dotenv
    import oracledb
    load_dotenv(ROOT/'.env')
    paths=[ROOT/'db/V010_asset_admin.sql',ROOT/'db/grants_asset_admin.sql']
    for path in paths:
        operations=list(parse_script(path.read_text(encoding='utf-8')))
        assert operations[0][0]=='on_error_rollback'
        print('Reviewed',path.name,'SHA256',hashlib.sha256(path.read_bytes()).hexdigest(),flush=True)
    # Native GUI prevents terminal echo and keeps the secret out of tool inputs/results.
    import tkinter as tk
    from tkinter import simpledialog
    window=tk.Tk();window.withdraw();window.attributes('-topmost',True)
    password=simpledialog.askstring('CyberShield Oracle owner login','Enter the existing CS_OWNER password as raw characters, WITHOUT surrounding quotes or SQLPlus escaping. It stays in memory only.',show='*',parent=window)
    window.destroy()
    if password is None:print('Owner login cancelled; no migration attempted.',flush=True);return 2
    con=None
    try:
        con=oracledb.connect(user='CS_OWNER',password=password,dsn=os.environ['ORACLE_DSN'],tcp_connect_timeout=10)
        password=None
        with con.cursor() as cur:
            cur.execute("SELECT user,sys_context('USERENV','SESSION_USER'),sys_context('USERENV','CURRENT_SCHEMA'),sys_context('USERENV','CON_NAME'),sys_context('USERENV','SERVICE_NAME') FROM dual")
            identity=cur.fetchone();print('Genuine owner session:',identity,flush=True)
            if identity[:3]!=('CS_OWNER','CS_OWNER','CS_OWNER') or identity[3]!='FREEPDB1':raise RuntimeError('Owner identity/PDB guard failed')
            cur.execute("SELECT version FROM schema_migration WHERE version='V010_asset_admin'")
            installed=cur.fetchone() is not None
            cur.execute("SELECT object_name,status FROM user_objects WHERE object_name IN ('SP_SAVE_SERVER','SP_SAVE_IP') AND object_type='PROCEDURE'")
            existing=dict(cur.fetchall())
            if installed:
                if existing!={'SP_SAVE_SERVER':'VALID','SP_SAVE_IP':'VALID'}:raise RuntimeError('Migration record/object mismatch; stopping without replacing objects')
                print('V010 is already recorded with both VALID procedures; not reapplying CREATE statements.',flush=True)
            elif existing:
                raise RuntimeError('Partial asset procedure installation detected; stopping without replacing objects')
        if not installed:run_script(con,paths[0])
        run_script(con,paths[1])
        with con.cursor() as cur:
            cur.execute("SELECT object_name,status FROM user_objects WHERE object_name IN ('SP_SAVE_SERVER','SP_SAVE_IP') AND object_type='PROCEDURE'")
            statuses=dict(cur.fetchall());assert statuses=={'SP_SAVE_SERVER':'VALID','SP_SAVE_IP':'VALID'}
            cur.execute("SELECT name,line,position,text FROM user_errors WHERE name IN ('SP_SAVE_SERVER','SP_SAVE_IP') AND attribute='ERROR'")
            assert not cur.fetchall()
            cur.execute("SELECT table_name,privilege,grantee FROM user_tab_privs_made WHERE table_name IN ('SP_SAVE_SERVER','SP_SAVE_IP') AND grantee='CS_APP' ORDER BY table_name")
            grants=cur.fetchall();assert grants==[('SP_SAVE_IP','EXECUTE','CS_APP'),('SP_SAVE_SERVER','EXECUTE','CS_APP')]
            cur.execute("SELECT table_name,privilege FROM user_tab_privs_made WHERE grantee='CS_APP' AND privilege IN ('INSERT','UPDATE','DELETE')")
            assert not cur.fetchall()
        print('PASS: both procedures VALID, no compilation errors, EXECUTE-only grants verified; no direct table DML grants.',flush=True)
        report={'verified_at':datetime.now(timezone.utc).isoformat(),'connection_user':'CS_OWNER','service':identity[4],'pdb':identity[3],
            'procedures':statuses,'runtime_grants':grants,'scripts':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},'owner_password_persisted':False}
        (ROOT/'ASSET_MIGRATION_VERIFICATION.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        return 0
    except oracledb.Error as exc:
        if con is not None:con.rollback()
        error=exc.args[0]
        print('Oracle migration stopped. Error code:',getattr(error,'code',None),flush=True)
        print('Login failed; no migration statements were executed.' if con is None else 'No credentials were logged. DDL may already have committed; inspect object state before retrying.',flush=True)
        return 1
    finally:
        password=None
        if con is not None:con.close()

if __name__=='__main__':raise SystemExit(main())
