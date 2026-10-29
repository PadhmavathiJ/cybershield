# CyberShield Oracle workflow handoff

The active application is root `app.py`, importing `db.py`, `workflow_routes.py` and `asset_routes.py`. Runtime is python-oracledb through CS_APP into CS_OWNER. No SQLite fallback was added. Existing .env, passwords, old migrations, tables, grants, evidence and original demo records were preserved. Nothing was committed or pushed.

## Working features

- ADMIN simulation ingestion against existing active servers/IPs/attack types through SP_INGEST_EVENT; real severity-score threshold alerts. Identical source-key retries return the existing event. Incident creation is a separate Admin action, not automatic detection.
- ADMIN creates incidents from eligible unlinked alerts through SP_CREATE_INCIDENT.
- ADMIN/MANAGER assignment queue, eligible investigator selection and assignment ending through existing procedures.
- ANALYST My investigations and assigned-case reads/writes; lifecycle, response/investigation notes, evidence registration, forensic analysis and resolution. Reads follow the Oracle helper policy permitting historical assignments; writes need a current active assignment. Existing stricter active-assignment evidence download checks were retained.
- Case detail shows linked alerts/events/assets, active assignments, status history, evidence, analysis, responses and resolutions. Forms follow role, object access and lifecycle stage.
- AUDITOR read-only access; direct mutation POSTs denied. MANAGER cannot perform operational Analyst writes. Session roles/activation refreshed from Oracle on each authenticated request.
- Parameterized list search, relevant status/severity/UTC date filters, numeric event score filters, preserved pagination parameters and empty states. Report dates affect actual Oracle incident-cycle rows and calculated MTTA/MTTR/closure rate.
- CSRF, rollback, safe Oracle application errors and actor context. `client_identifier=None` fixes DPY-4011 caused by empty-string context clearing with the installed driver. Aware datetime inputs use explicit TIMESTAMP WITH TIME ZONE binds.
- Corrected EVIDENCE.collected_by join through INVESTIGATOR. Only Oracle-supported INTERNAL/RESTRICTED sensitivities are offered. Removed unsupported customer/engineer account forms; User access is read-only with the real roles. Database explorer omits password_hash.

## Verification

`ORACLE_VERIFICATION.json` records real HTTP and independent Oracle checks. The full cycle was exercised through a running root Flask server with signed test sessions for existing users and valid CSRF tokens. Password login and browser automation were not tested. No account or password was changed.

Verified simulation: event 263, alert 263, incident 168 (CLOSED), evidence 180. Exact history: OPEN -> TRIAGED -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED. Verified response action, resolution, initial custody, forensic analysis, closed cycle and ended assignment. All 13 workflow entity types had authenticated audit records (28 rows for this case/event/evidence).

Earlier diagnostic simulations 166 and 167 were also closed through the frontend; all three new simulated cases remain in Oracle as evidence of verification. No original demo case was used for mutations.

Passed checks include four-role HTTP rendering, Manager assignment, assigned-Analyst access, unassigned-Analyst read/write/download denial, Auditor direct POST denial, Manager operational POST denial, invalid-transition rollback, source-key deduplication, committed subsequent reads, actual filter include/exclude/empty results, and pooled actor-context clearing. Runtime direct system privileges: CREATE SESSION only; no direct CS_OWNER INSERT/UPDATE/DELETE grants were found.

43 isolated pytest tests passed, including mocked Oracle-boundary regression tests. These are separate from the real HTTP/Oracle checks. Root-only pytest configuration excludes the older cybershield_soc tests.

```powershell
.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
# Read-only checks against an already-running root app and the recorded simulation:
.venv\Scripts\python.exe tests/verify_oracle_reads.py
# Opt-in: creates another NEW labelled simulation, evidence file and audit trail:
.venv\Scripts\python.exe tests/verify_oracle_http.py
```

## Owner migration required only for asset writes

`db/V010_asset_admin.sql` adds SP_SAVE_SERVER and SP_SAVE_IP, with AUTHID DEFINER, explicit authenticated ADMIN checks, validation, savepoint rollback and redacted audit entries. `db/grants_asset_admin.sql` grants EXECUTE only. Existing tables/procedures/triggers are not replaced. IP inputs are validated/canonicalized in Python; the procedure validates IPv4 or expanded IPv6.

These scripts have NOT been executed or Oracle-compiled. CS_APP was not used for owner SQL. Until the owner runs both scripts, Asset administration remains read-only and direct saves return 503 with an explicit migration message. Asset persistence/auditing cannot be claimed as verified yet.

From the repository root (SQL*Plus prompts for the existing owner password):

```powershell
sqlplus CS_OWNER@LAPTOP-KB0P82O2:1521/FREEPDB1 @db/V010_asset_admin.sql
sqlplus CS_OWNER@LAPTOP-KB0P82O2:1521/FREEPDB1 @db/grants_asset_admin.sql
```

After installation, verify both procedures are VALID, use a new labelled test asset to exercise create/update via Admin > Asset administration, and check its server/ip_address audit records. Do not rerun old migrations or grant table DML. User creation/activation and automatic incident detection remain unimplemented; the UI does not promise those saves.

## Startup and demo

```powershell
# Run from C:\Users\pooja\Documents\cybershield\cybershield:
.venv\Scripts\python.exe app.py
```

The root application was left running at http://127.0.0.1:5000 (process 24768). Logs are oracle-app.stdout.log and oracle-app.stderr.log, excluded by .gitignore. To restart this instance first: `Stop-Process -Id 24768`.

1. Sign in as the existing ADMIN. Events > Submit simulated event. Select existing assets, enter score 99 and clearly labelled simulation details. Save; follow the real alert link and Create incident. Supply title/description/severity.
2. Sign out; sign in as the existing MANAGER. Assignments > select the new incident and an eligible existing Analyst investigator > LEAD > Assign in Oracle. Review SLA deadlines and workload.
3. Sign out; sign in as that assigned ANALYST. My investigations > case > TRIAGED with reason > INVESTIGATING with reason. Record an investigation/response note and outcome. Register evidence if needed; open the evidence to record analysis. Change to CONTAINED, then Resolve with summary/root cause/loss, then CLOSED with a reason.
4. Sign out; sign in as the existing AUDITOR. Open the case/history and audit trail; filter by case ID and date, and review Reports. No operational mutation forms are available.

Core Oracle SOC lifecycle is verified. Optional asset writes await owner installation and verification. Password-entry login and interactive browser behavior were not independently verified in this session.


## Subsequent connection diagnosis and asset installation

The previously pending V010 migration and grants are now installed and verified. See ORACLE_CONNECTION_DIAGNOSIS.md and ASSET_MIGRATION_VERIFICATION.json for current status; this supersedes the earlier pending-asset notes above.

The recurring SQL*Plus ORA-12543 was reproduced as special-character password parsing: the unquoted password corrupted the destination to 0.0.0.1 with an empty service. Quoting the password at the prompt succeeded. No listener/password change was needed. Python Thin and Thick both connected.

A genuine, privately authenticated CS_OWNER Python session applied the original guarded scripts with proper PL/SQL block/directive handling. Both procedures are VALID, CS_APP has EXECUTE-only grants, and frontend create/update checks persisted new test server 261 (inactive) and simulated IP 281 with four redacted audit entries. Non-Admin frontend/procedure denial and duplicate-write rollback passed. Total focused unit tests: 54 passing. Owner credentials were never persisted. No feature work was added during the diagnostic turn beyond applying the requested existing asset migration.


## Current verified automatic simulator and browser demo

See ORACLE_DEMO_GUIDE.md for the current implementation and demonstration. It supersedes earlier notes saying automatic incidents or actual password-entry browser checks were unimplemented. The existing migration and connection diagnosis remain completed and unchanged. User provisioning remains unimplemented.
