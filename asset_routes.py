"""Optional Oracle asset administration, gated on additive procedures/grants."""
import ipaddress
import re
from flask import abort, flash, redirect, render_template, request, url_for


def register_assets(app,api):
    roles_required=api['roles_required']
    obj=api['obj']
    safe_read=api['safe_read']
    safe_one=api['safe_one']

    def available(name):
        return bool(safe_one("""SELECT o.object_name FROM all_objects o
            WHERE o.owner=:owner AND o.object_name=:proc_name AND o.object_type='PROCEDURE' AND o.status='VALID'
            AND EXISTS (SELECT 1 FROM all_tab_privs p WHERE p.table_schema=o.owner AND p.table_name=o.object_name
                AND p.privilege='EXECUTE' AND p.grantee=USER)""",{'owner':api['OWNER'],'proc_name':name.upper()}))

    @app.route('/admin/assets',methods=['GET','POST'])
    @roles_required('ADMIN')
    def admin_assets():
        enabled=available('sp_save_server') and available('sp_save_ip')
        if request.method=='POST':
            if not enabled:
                abort(503,description='Asset administration requires the separate V010_asset_admin.sql migration and grants_asset_admin.sql, executed as CS_OWNER. No asset was changed.')
            kind=request.form.get('kind','')
            target=request.form.get('target_id','').strip()
            try:
                target_id=int(target) if target else None
                if target_id is not None and target_id<=0:raise ValueError
                if kind=='server':
                    hostname=request.form.get('hostname','').strip().lower()
                    os_name=request.form.get('os_name','').strip()
                    department=request.form.get('department','').strip()
                    criticality=request.form.get('criticality','').upper()
                    active=int(request.form.get('is_active',''))
                    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,119}',hostname) or not 1<=len(os_name)<=100 or not 1<=len(department)<=100 or criticality not in {'LOW','MEDIUM','HIGH','CRITICAL'} or active not in {0,1}:raise ValueError
                    name='sp_save_server'
                    params=[api['actor_id'](),target_id,hostname,os_name,department,criticality,active,None]
                elif kind=='ip':
                    address=ipaddress.ip_address(request.form.get('ip_text','').strip())
                    country=request.form.get('country_code','').strip().upper() or None
                    simulated=int(request.form.get('is_simulated',''))
                    if simulated not in {0,1} or (country and not re.fullmatch('[A-Z]{2}',country)):raise ValueError
                    name='sp_save_ip'
                    params=[api['actor_id'](),target_id,address.exploded,country,simulated,None]
                else:raise ValueError
            except ValueError:
                abort(400,description='Check the selected record, hostname/IP, required fields and option values.')
            try:
                api['call_proc'](name,params,api['actor_id'](),(len(params)-1,))
                flash('Asset saved in Oracle with a redacted audit record.','success')
                return redirect(url_for('admin_assets'))
            except Exception as exc:
                api['workflow_error'](exc,'Oracle rejected this asset change. No save was confirmed.')
        edit_server=None;edit_ip=None
        if request.args.get('server_id'):
            edit_server=safe_one(f"SELECT * FROM {obj('server')} WHERE server_id=:target_id",{'target_id':request.args.get('server_id',type=int)})
            if not edit_server:abort(404)
        if request.args.get('ip_id'):
            edit_ip=safe_one(f"SELECT * FROM {obj('ip_address')} WHERE ip_id=:target_id",{'target_id':request.args.get('ip_id',type=int)})
            if not edit_ip:abort(404)
        return render_template('asset_admin.html',enabled=enabled,edit_server=edit_server or {},edit_ip=edit_ip or {},
            servers=safe_read(f"SELECT * FROM {obj('server')} ORDER BY hostname"),
            ips=safe_read(f"SELECT * FROM {obj('ip_address')} ORDER BY ip_text"))
