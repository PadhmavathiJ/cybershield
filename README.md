# CyberShield SOC — merged full-stack project

This package combines:
- Person 1's Oracle/PLSQL database scripts from `db/` (copied without editing their contents).
- Person 2's frontend templates and CSS from the frontend archive.
- An Oracle-oriented Flask backend, connection pool, role checks, CSRF protection, routes and workflow procedure calls.

## Important status statement
This is an integration implementation, not proof of a deployed or fully tested Oracle environment. SQL object creation, runtime grants, seed execution, stored-procedure calls and end-to-end workflows must be verified against your own Oracle instance. No live detection is implemented; the supplied event workflow includes simulated events.

## Run locally (Windows PowerShell)
1. Extract the archive.
2. Open PowerShell in this folder:
   `cd .\cybershield_soc`
3. Create a virtual environment:
   `py -m venv .venv`
   `.\.venv\Scripts\Activate.ps1`
4. Install dependencies:
   `python -m pip install -r requirements.txt`
5. Copy `.env.example` to `.env`, then fill in the Oracle credentials and DSN:
   `Copy-Item .env.example .env`
6. Confirm the Person 1 SQL has been deployed in the intended Oracle schema, in order:
   - `db/V001_tables.sql`
   - `db/V002_constraints_indexes.sql`
   - `db/V003_security_helpers.sql`
   - `db/V004_incident_workflows.sql`
   - `db/V005_forensic_workflows.sql`
   - `db/V006_audit_triggers.sql`
   - `db/V007_reporting_views.sql`
   - `db/V008_runtime_grants.sql` (run with the required owner privileges)
7. Seed demo data only if appropriate for your test schema. Review `db/V009_seed.sql` and its hash-generation helper first; do not run against production or a shared schema without approval.
8. Start Flask:
   `python app.py`
9. Open `http://127.0.0.1:5000/health` first. It checks only Oracle connectivity, not all schema objects. Then sign in with an existing `app_user` record whose password hash matches Werkzeug's `check_password_hash`.

## Roles
Oracle role codes are `ADMIN`, `MANAGER`, `ANALYST`, `AUDITOR`. Self-registration is disabled. The SQL grants are intended for the `CS_APP` runtime user; use a separate schema owner for deployment.

## Files
- `app.py`: Flask routes and Oracle integration.
- `db.py`: Oracle connection pool.
- `auth.py`, `services.py`, `errors.py`: retained backend helpers.
- `templates/`, `static/`: merged frontend.
- `db/`: Person 1 SQL, verification scripts and database utilities, preserved as supplied.
- `legacy_sqlite_reference/`: old SQLite prototype files, kept for reference only. They are not used by the Oracle Flask app.

## Notes and known integration boundaries
- The reporting page currently displays the dashboard summary as a report row; MTTA/MTTR calculations are not implemented because the provided views do not directly expose a fully specified reporting-period aggregate.
- The incident messaging page from the older prototype is intentionally not persisted because Person 1's schema has no message table or message procedure.
- User creation UI from the old frontend does not create accounts. Account provisioning should be implemented only after agreeing a secure password policy and whether to add a dedicated PL/SQL procedure.
- `sp_ingest_event` is defined but no public event-ingestion form is exposed in this initial integration. This avoids presenting a form as live monitoring.
- Some table-explorer routes are read-only. There are no arbitrary table insert/update/delete endpoints.
- Evidence files are stored outside `static/` using generated storage keys; the DB holds metadata only.
