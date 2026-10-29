-- Additive only. Execute as CS_OWNER, never CS_APP. No existing tables or data are rebuilt.
WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK
SET DEFINE OFF
BEGIN
    IF SYS_CONTEXT('USERENV','SESSION_USER') <> 'CS_OWNER' THEN
        RAISE_APPLICATION_ERROR(-20007,'Run this migration as CS_OWNER');
    END IF;
END;
/
CREATE PROCEDURE sp_save_server (
    p_actor_id IN NUMBER,
    p_target_server_id IN NUMBER,
    p_hostname IN VARCHAR2,
    p_os_name IN VARCHAR2,
    p_department IN VARCHAR2,
    p_criticality IN VARCHAR2,
    p_is_active IN NUMBER,
    p_server_id OUT NUMBER
) AUTHID DEFINER IS
    v_role VARCHAR2(10);
    v_action VARCHAR2(10);
BEGIN
    SAVEPOINT cs_save_server_start;
    p_server_id := NULL;
    cs_security.assert_actor(p_actor_id,v_role);
    IF v_role <> 'ADMIN' THEN
        RAISE_APPLICATION_ERROR(-20007,'Administrator permission required');
    END IF;
    IF TRIM(p_hostname) IS NULL OR LENGTH(p_hostname)>120
       OR NOT REGEXP_LIKE(p_hostname,'^[A-Za-z0-9][A-Za-z0-9._-]*$')
       OR TRIM(p_os_name) IS NULL OR LENGTH(p_os_name)>100
       OR TRIM(p_department) IS NULL OR LENGTH(p_department)>100
       OR p_criticality IS NULL OR p_criticality NOT IN ('LOW','MEDIUM','HIGH','CRITICAL')
       OR p_is_active IS NULL OR p_is_active NOT IN (0,1)
       OR (p_target_server_id IS NOT NULL AND
           (p_target_server_id<=0 OR p_target_server_id<>TRUNC(p_target_server_id))) THEN
        RAISE_APPLICATION_ERROR(-20010,'Invalid server fields');
    END IF;
    IF p_target_server_id IS NULL THEN
        INSERT INTO server(hostname,os_name,department,criticality,is_active)
        VALUES(LOWER(p_hostname),TRIM(p_os_name),TRIM(p_department),p_criticality,p_is_active)
        RETURNING server_id INTO p_server_id;
        v_action := 'INSERT';
    ELSE
        UPDATE server SET hostname=LOWER(p_hostname),os_name=TRIM(p_os_name),
            department=TRIM(p_department),criticality=p_criticality,is_active=p_is_active
        WHERE server_id=p_target_server_id;
        IF SQL%ROWCOUNT=0 THEN RAISE_APPLICATION_ERROR(-20001,'Server not found'); END IF;
        p_server_id := p_target_server_id;
        v_action := 'UPDATE';
    END IF;
    cs_audit.record_change(v_action,'server',p_server_id,NULL,'{"fields":"redacted","workflow":"asset_admin"}');
EXCEPTION
    WHEN DUP_VAL_ON_INDEX THEN
        ROLLBACK TO cs_save_server_start; p_server_id := NULL;
        RAISE_APPLICATION_ERROR(-20009,'Hostname already exists');
    WHEN OTHERS THEN
        ROLLBACK TO cs_save_server_start; p_server_id := NULL; RAISE;
END;
/
SHOW ERRORS PROCEDURE sp_save_server
CREATE PROCEDURE sp_save_ip (
    p_actor_id IN NUMBER,
    p_target_ip_id IN NUMBER,
    p_ip_text IN VARCHAR2,
    p_country_code IN VARCHAR2,
    p_is_simulated IN NUMBER,
    p_ip_id OUT NUMBER
) AUTHID DEFINER IS
    v_role VARCHAR2(10);
    v_action VARCHAR2(10);
    v_valid BOOLEAN := FALSE;
BEGIN
    SAVEPOINT cs_save_ip_start;
    p_ip_id := NULL;
    cs_security.assert_actor(p_actor_id,v_role);
    IF v_role <> 'ADMIN' THEN
        RAISE_APPLICATION_ERROR(-20007,'Administrator permission required');
    END IF;
    -- IPv6 must be fully expanded (the frontend canonicalizes with ipaddress).
    IF REGEXP_LIKE(p_ip_text,'^([[:xdigit:]]{4}:){7}[[:xdigit:]]{4}$') THEN
        v_valid := TRUE;
    ELSIF REGEXP_LIKE(p_ip_text,'^([0-9]{1,3}\.){3}[0-9]{1,3}$') THEN
        v_valid := TRUE;
        FOR n IN 1..4 LOOP
            IF TO_NUMBER(REGEXP_SUBSTR(p_ip_text,'[0-9]+',1,n))>255 THEN v_valid := FALSE; END IF;
        END LOOP;
    END IF;
    IF p_ip_text IS NULL OR NOT v_valid OR LENGTH(p_ip_text)>45
       OR (p_country_code IS NOT NULL AND NOT REGEXP_LIKE(p_country_code,'^[A-Z]{2}$'))
       OR p_is_simulated IS NULL OR p_is_simulated NOT IN (0,1)
       OR (p_target_ip_id IS NOT NULL AND
           (p_target_ip_id<=0 OR p_target_ip_id<>TRUNC(p_target_ip_id))) THEN
        RAISE_APPLICATION_ERROR(-20010,'Invalid IP address fields');
    END IF;
    IF p_target_ip_id IS NULL THEN
        INSERT INTO ip_address(ip_text,country_code,is_simulated)
        VALUES(LOWER(p_ip_text),p_country_code,p_is_simulated)
        RETURNING ip_id INTO p_ip_id;
        v_action := 'INSERT';
    ELSE
        UPDATE ip_address SET ip_text=LOWER(p_ip_text),country_code=p_country_code,is_simulated=p_is_simulated
        WHERE ip_id=p_target_ip_id;
        IF SQL%ROWCOUNT=0 THEN RAISE_APPLICATION_ERROR(-20001,'IP address not found'); END IF;
        p_ip_id := p_target_ip_id;
        v_action := 'UPDATE';
    END IF;
    cs_audit.record_change(v_action,'ip_address',p_ip_id,NULL,'{"fields":"redacted","workflow":"asset_admin"}');
EXCEPTION
    WHEN DUP_VAL_ON_INDEX THEN
        ROLLBACK TO cs_save_ip_start; p_ip_id := NULL;
        RAISE_APPLICATION_ERROR(-20009,'IP address already exists');
    WHEN OTHERS THEN
        ROLLBACK TO cs_save_ip_start; p_ip_id := NULL; RAISE;
END;
/
SHOW ERRORS PROCEDURE sp_save_ip
BEGIN
    FOR r IN (SELECT object_name FROM user_objects WHERE object_type='PROCEDURE'
              AND object_name IN ('SP_SAVE_SERVER','SP_SAVE_IP') AND status <> 'VALID') LOOP
        RAISE_APPLICATION_ERROR(-20010,'Asset procedure compilation failed; inspect USER_ERRORS');
    END LOOP;
END;
/
INSERT INTO schema_migration(version,description)
VALUES('V010_asset_admin','Add ADMIN-only definer-rights server/IP procedures with redacted auditing');
COMMIT;
PROMPT Asset procedures installed. Apply db/grants_asset_admin.sql as CS_OWNER next.
EXIT
