# Verified Oracle-only demo

Start root app from this repository:

```powershell
.venv\Scripts\python.exe app.py
```

The updated root website is already running at http://127.0.0.1:5000. The root server was restarted after verification; Oracle /health returns true. Existing .env and CS_APP runtime configuration remain in use. Do not start cybershield_soc or rerun migrations.

## Actual detection rule

A labelled simulated security event creates an alert when its severity_score is greater than or equal to CS_OWNER.SOC_POLICY.alert_threshold (currently 70). Whenever SP_INGEST_EVENT returns an alert, the simulator uses SP_CREATE_INCIDENT to create its incident automatically. This is severity-score threshold detection; it does not count failed logins.

Both procedure calls run on the same CS_APP connection with the authenticated actor, one final commit, rollback on failure and cleared CLIENT_IDENTIFIER. Repeating an identical source key, event time and payload returns the same event/alert/incident. Conflicting data for an existing source key is rejected. SP_CREATE_INCIDENT serializes concurrent creators by locking the alert; the application reads the winning link after its duplicate rejection. There is no SQLite fallback and no new migration or table DML grant.

## Click-by-click demo

1. ADMIN: sign in with the existing website password. Asset administration > create a labelled test server and simulated IP. Edit either record to demonstrate persisted updates. Events > Submit simulated event > select that active server/IP, choose an attack type, enter score 99 and labelled simulation details > Save simulated event to Oracle. The page opens the automatically created incident. Below score 70, only the event is saved. Retry with the original source key/time/payload to demonstrate deduplication.
2. MANAGER: sign in > Assignments > select the new incident, an existing active Analyst investigator, and LEAD > Assign in Oracle. Manager can read the case but has no Analyst lifecycle/response forms.
3. Assigned ANALYST: sign in > My investigations > case > TRIAGED with reason > INVESTIGATING with reason. Record a response/investigation note and outcome. Register evidence > choose the case, upload a file, then open it to save analysis and download the evidence. Return to the case > CONTAINED > resolve with summary/root cause/loss > CLOSED with reason.
4. AUDITOR: sign in > Incidents > search the source key/case ID and filter CLOSED/CRITICAL > open history, evidence, analysis, response and resolution. Audit trail filters show committed audit records. Reports supports a real date range and CSV export. Operational mutation forms are absent and direct POSTs are denied.

User access is a read-only account inventory. User creation/activation is NOT implemented; no provisioning claim is made.

## Verification performed

- Real Microsoft Edge 156.0.4314.50 using Playwright, actual password entry for ADMIN, MANAGER, analyst30 and AUDITOR, actual navigation/form clicks and downloads. No injected sessions were used for the browser acceptance cycle; no passwords, browser cookies, login screenshots, traces or HAR were persisted. The first separate Admin attempt was rejected; a fresh private entry succeeded without a reset.
- Browser-created server 263, simulated IP 282, event 281, alert 281, incident 186 (CLOSED), assignment 250, evidence 198. The test server was left inactive. Below-threshold event 282 has no alert/incident.
- Six exact history stages: OPEN -> TRIAGED -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED. Committed response, custody, forensic analysis and resolution. Ended assignment and investigation cycle. Oracle actor auditing verified for all 13 workflow entity types, 26 rows for this event/case/evidence.
- Browser dashboard values matched Oracle: active servers 30 -> 31 -> 30; events 123 -> 124 -> 125; open incidents 45 -> 46 -> 45. These are point-in-time snapshots, not hardcoded application metrics.
- Nine list search/Clear forms plus status, severity, score and UTC date filters were exercised in the browser. Role-specific navigation destinations returned expected results. Manager/Auditor direct lifecycle POSTs were denied. All four browser logout buttons worked, including mobile Analyst layout.
- Four concurrent retries of the browser event reused its closed incident. Two additional real CS_APP race tests verified concurrent first submissions and an existing unlinked alert; each produced exactly one event/alert/incident and rejected a conflicting payload. Their test incidents 187, 188 were also closed. After these extra checks the live Oracle dashboard is: active servers 30, total events 127, critical alerts 66, open incidents 45, active investigators 30, SLA breaches 15.
- 64 focused pytest tests passed. Mocked transaction/authorization tests are separate from the real browser/Oracle checks. git diff --check passed. Completed migration file hashes remain unchanged.

## Failures found and corrected

- Initial select-option test locators required an exact nested label match. Corrected the test selectors; this was not an Oracle/app failure.
- Opening evidence registration from a case exposed Jinja's undefined Python int reference. Switched preselection in evidence/alert forms to Jinja's int filter and added two regression tests.
- Long fixed navigation made Sign out unreachable. Added sidebar scrolling and mobile Sign out visibility; verified normal browser clicks afterward.

Failure history remains in BROWSER_ORACLE_VERIFICATION.json; final status is passed with no unresolved failures. The first login attempt report is retained separately. The browser test used resumable phases to retain genuine authenticated sessions while correcting failures.

## Evidence and repeatable checks

- BROWSER_ORACLE_VERIFICATION.json: real browser results, record IDs, navigation, dashboard snapshots, corrected failures and read-only post-restart checks.
- SIMULATOR_CONCURRENCY_VERIFICATION.json: actual Oracle concurrent creation/retry checks.
- verification-artifacts/auditor-closed-simulated-case.png: authenticated Auditor case screenshot, no credential fields.
- GIT_REVIEW_VERIFICATION.json: changed-file secret review. No commit or push was performed.
- ORACLE_CONNECTION_DIAGNOSIS.md and ASSET_MIGRATION_VERIFICATION.json: completed connection diagnosis/asset migration, preserved. Do not rerun those migrations.

```powershell
.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
# Read-only checks of the recorded browser case on the running website:
.venv\Scripts\python.exe tests/verify_oracle_reads.py http://127.0.0.1:5000 BROWSER_ORACLE_VERIFICATION.json
# Opt-in: prompts privately and creates NEW simulation records:
.venv\Scripts\python.exe -m pip install -r requirements-browser.txt
.venv\Scripts\python.exe tests/verify_oracle_browser.py
```

Remaining limits: no user provisioning, no new configurable detection-rule editor, and browser acceptance was performed in Edge (other browser engines were not tested). Connection diagnosis, populated Oracle data and existing users/password hashes were preserved. The application remains on root app.py and restricted CS_APP.
