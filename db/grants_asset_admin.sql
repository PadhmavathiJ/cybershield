-- Execute as CS_OWNER after V010_asset_admin.sql. No direct DML or system privileges.
WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK
BEGIN
    IF SYS_CONTEXT('USERENV','SESSION_USER') <> 'CS_OWNER' THEN
        RAISE_APPLICATION_ERROR(-20007,'Run grants as CS_OWNER');
    END IF;
END;
/
GRANT EXECUTE ON sp_save_server TO cs_app;
GRANT EXECUTE ON sp_save_ip TO cs_app;
EXIT
