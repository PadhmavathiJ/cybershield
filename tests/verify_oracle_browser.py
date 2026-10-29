"""Opt-in real Edge/Oracle acceptance. Prompts for existing website passwords.
No password resets, session injection, saved credentials/cookies, HAR or traces.
On a failed scenario, type retry after fixing the test/application, or stop.
"""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import importlib
import json
import secrets
import threading
from datetime import datetime,timezone
from werkzeug.serving import make_server,WSGIRequestHandler
from playwright.sync_api import sync_playwright,expect
import app as root

class QuietHandler(WSGIRequestHandler):
    def log_request(self,*args,**kwargs):pass

def credentials(defaults=None):
    import tkinter as tk
    from tkinter import ttk
    defaults=defaults or {'ADMIN':'admin@cybershield.example','MANAGER':'manager@cybershield.example','ANALYST':'analyst30@cybershield.example','AUDITOR':'auditor@cybershield.example'}
    window=tk.Tk();window.title('CyberShield - EXISTING website passwords');window.attributes('-topmost',True)
    ttk.Label(window,text='Existing WEBSITE passwords only, raw characters without quote wrappers.\nNo passwords will be changed, logged or saved. This is not the Oracle owner login.').grid(row=0,column=0,columnspan=3,padx=14,pady=12)
    fields={};result={}
    for n,(role,email) in enumerate(defaults.items(),1):
        ttk.Label(window,text=role).grid(row=n,column=0,padx=8,pady=6)
        account=ttk.Entry(window,width=42);account.insert(0,email);account.grid(row=n,column=1,padx=8)
        password=ttk.Entry(window,width=28,show='*');password.grid(row=n,column=2,padx=8)
        fields[role]=(account,password)
    status=ttk.Label(window,text='');status.grid(row=5,column=0,columnspan=3)
    def submit():
        if not all(password.get() for account,password in fields.values()):
            status.config(text='Enter each existing password to verify its actual login.');return
        for role,(account,password) in fields.items():result[role]=(account.get().strip().lower(),password.get())
        window.destroy()
    ttk.Button(window,text='Run real browser verification',command=submit).grid(row=6,column=0,columnspan=2,pady=12)
    ttk.Button(window,text='Cancel',command=window.destroy).grid(row=6,column=2,pady=12)
    fields[next(iter(fields))][1].focus_set();window.mainloop();return result

def main():
    report={'started_at':datetime.now(timezone.utc).isoformat(),'checks':[],'failures':[],'ids':{},'authentication':'Actual Edge password-entry login; no injected sessions','screenshots':[]}
    artifact=ROOT/'BROWSER_ORACLE_VERIFICATION.json'
    accounts=credentials()
    if not accounts:
        print('Private password entry cancelled; browser login not verified.',flush=True);return 2
    server=make_server('127.0.0.1',0,root.app,request_handler=QuietHandler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    base=f'http://127.0.0.1:{server.server_port}';report['website']=base
    def passed(message):report['checks'].append(message);print('PASS:',message,flush=True)
    state={'root':root,'ROOT':ROOT,'base':base,'report':report,'passed':passed,'users':{},'pages':{},'done':set(),'key':secrets.token_hex(6)}
    try:
        with sync_playwright() as pw:
            browser=pw.chromium.launch(channel='msedge',headless=True)
            report['browser']='Microsoft Edge '+browser.version
            for role,(email,password) in accounts.items():
                user=root.query_one("SELECT u.user_id,u.role_code,inv.investigator_id FROM cs_owner.app_user u LEFT JOIN cs_owner.investigator inv ON inv.user_id=u.user_id AND inv.availability <> 'INACTIVE' WHERE lower(u.email)=:email AND u.is_active=1",{'email':email})
                assert user and user['role_code']==role
                assert role!='ANALYST' or user['investigator_id']
                page=browser.new_context(viewport={'width':1440,'height':1050}).new_page();page.set_default_timeout(15000)
                page.goto(base+'/login');page.get_by_label('Email address',exact=True).fill(email)
                page.get_by_label('Password',exact=True).fill(password)
                page.get_by_role('button',name='Sign in',exact=False).click();page.wait_for_load_state()
                if not page.url.endswith('/dashboard'):
                    report['failures'].append(role+' initial password login rejected; no password reset.')
                    print(role+' password login rejected. Reopening a private dialog for only this role; other sessions are retained.',flush=True)
                    correction=credentials({role:email})
                    if role not in correction:continue
                    corrected_email,corrected_password=correction[role]
                    if corrected_email!=email:
                        report['failures'].append(role+' account changed during correction; restart required to validate metadata.');continue
                    page.goto(base+'/login');page.get_by_label('Email address',exact=True).fill(email)
                    page.get_by_label('Password',exact=True).fill(corrected_password)
                    page.get_by_role('button',name='Sign in',exact=False).click();page.wait_for_load_state()
                    corrected_password=None;correction.clear()
                    if not page.url.endswith('/dashboard'):
                        report['failures'].append(role+' corrected password login rejected. No further automatic attempts.');continue
                    report.setdefault('resolved_failures',[]).append(role+' initial password-entry rejection resolved by private user re-entry')
                expect(page.locator('.role-pill')).to_have_text(role)
                state['users'][role]=user;state['pages'][role]=page
                passed(role+' actual password-entry browser login and role verified')
            accounts.clear();password=None
            if len(state['pages'])!=4:raise RuntimeError('Not all role logins passed')
            import browser_scenarios
            while True:
                try:
                    browser_scenarios.run(state)
                    report['status']='passed'
                    report['failure_history']=report.pop('failures',[])
                    report['failures']=[]
                    break
                except Exception as exc:
                    phase=state.get('phase','browser scenario')
                    # Do not print exception call logs; login/form fields can contain secrets.
                    failure=phase+': '+type(exc).__name__
                    report['failures'].append(failure);report['status']='failed'
                    artifact.write_text(json.dumps(report,indent=2,default=str),encoding='utf-8')
                    print('FAIL:',failure,'; browser sessions retained. Type retry after correction, or stop.',flush=True)
                    command=sys.stdin.readline().strip()
                    if command!='retry':break
                    importlib.invalidate_caches();browser_scenarios=importlib.reload(browser_scenarios)
            browser.close()
    except Exception as exc:
        report['status']='failed';report['failures'].append('Browser/login setup: '+type(exc).__name__+'; sensitive exception detail suppressed')
        print(report['failures'][-1],flush=True)
    finally:
        accounts.clear();report['finished_at']=datetime.now(timezone.utc).isoformat()
        artifact.write_text(json.dumps(report,indent=2,default=str),encoding='utf-8')
        server.shutdown();server.server_close();root.close_pool()
    return 0 if report.get('status')=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
