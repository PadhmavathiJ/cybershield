# CyberShield SOC — Full-stack incident management demo

CyberShield is a Flask + SQLite web application built around the 19 core tables in the supplied ER diagram. It includes role-based authentication, customer incident reporting, engineer access requests, customer approval/rejection, investigation actions, incident resolution, administrator database management, and an audit log.

## Roles and workflow

- **Admin:** dashboard for all core table counts, browse/create/edit/delete records in the 19 core tables, review the audit log, and manage account roles/active status. Admin screens never select or display password hashes. Passwords cannot be retrieved; users must choose a new password through a future password-reset feature (not included in this demo).
- **Complainer / Customer:** register, sign in, submit incidents, see only their own incidents, and approve or reject an engineer's access request for their incident.
- **Engineer:** Admin-created accounts only. Each engineer has a specialization and maximum severity capability. Engineers see a queue of open incident summaries within their severity level, but cannot see the private report details or conversation until the customer approves their access request. Until the customer approves, the engineer cannot open the case details or record actions. Once approved, they can record response actions and resolve the incident.

## Included tables

The 19 core ER tables are `ip_address`, `server`, `attack_type`, `security_event`, `alert`, `evidence`, `chain_of_custody`, `forensic_analysis`, `threat_actor`, `historical_threat_intelligence`, `attack_campaign`, `campaign_event`, `incident`, `sla`, `investigator`, `incident_assignment`, `response_action`, `resolution`, and `audit_log`.

Two workflow tables are added to support the requested login and approval workflow: `users` (accounts and password hashes) and `access_request` (approval/rejection trail). The `incident` table includes `created_by_user_id` to associate customer reports with their owner. Passwords are stored with Werkzeug's password hashing function, never as plaintext.

## Requirements

- Python 3.10 or newer (Python 3.13 is supported by current Flask releases)
- Internet connection only if pip needs to download Flask/Werkzeug
- Windows + VS Code, macOS, or Linux

## Run on Windows / VS Code

1. Extract the ZIP file.
2. Open the extracted `cybershield_soc` folder in VS Code.
3. Open Terminal > New Terminal in that folder.
4. Create a virtual environment:

   ```powershell
   py -m venv .venv
   ```

5. Activate it:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, use Command Prompt and run `.venv\Scripts\activate.bat`, or run `.venv\Scripts\python.exe -m pip install -r requirements.txt` and `.venv\Scripts\python.exe app.py` without activating.

6. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

7. Start the application:

   ```powershell
   python app.py
   ```

8. Open **http://127.0.0.1:5000** in your browser. SQLite database `cybershield.db` and its tables are initialized automatically on first run.

## Demo logins

| Role | Email | Password |
|---|---|---|
| Admin | `admin@cybershield.local` | `Admin@123` |
| Engineer | `engineer@cybershield.local` | `Engineer@123` |
| Customer | `customer@cybershield.local` | `Customer@123` |

Demo accounts are created automatically if those emails do not already exist. Public registrations are always customer accounts. Engineers cannot self-register; the Admin creates each engineer account in User access, sets the initial password, specialization, and maximum severity. The password is hashed and cannot be viewed again after creation. Share initial passwords with engineers securely and ask them to change them before real deployment. Do not deploy the demo credentials to a public server; change them before any real use.

## Fix demo login credentials without deleting data

If a demo login says the email/password is incorrect or the account is disabled, stop the app and run this command from the project folder (the same folder containing `app.py`):

```powershell
python repair_demo_logins.py
```

This resets and enables only the three built-in demo accounts. It preserves incidents, evidence, audit records, and other application data. Start the app again with `python app.py`. Run this script only for the local demo environment because it resets the built-in demo passwords to the documented values.

## Recommended workflow demo

1. Sign in as customer (`customer@cybershield.local`) and create an incident.
2. Sign out, sign in as engineer (`engineer@cybershield.local`), find the incident, and submit an access request with a reason.
3. Sign out and sign in as customer. Approve or reject the request. Rejecting keeps the engineer locked out; approving enables the engineer to open the case.
4. Sign in as engineer, open the approved case, record response actions, then add a root cause and resolve it.
5. Sign in as admin to browse all 19 core tables, edit records, create engineer accounts with a specialization and maximum severity, manage account status, and inspect the audit log. Password hashes are not shown. Engineers are filtered to the maximum severity configured by the Admin; a Critical-capability engineer can see Low, Medium, High, and Critical open cases.

## Data and safety notes

- All database calls use parameterized SQL for user-provided values. Foreign-key checks are enabled on every connection.
- The audit log records app-level create/update/delete actions, login/logout, access decisions, and incident workflow events. It is an application audit trail, not tamper-proof forensic logging.
- The app uses a CSRF form token and HTTP-only, SameSite session cookies. The default secret key is for local development only. Set `CYBERSHIELD_SECRET` to a long random secret before deployment.
- Debug mode is off by default. Do not expose Flask's development server to the internet. A production deployment needs a production WSGI server, HTTPS, backups, account recovery, rate limiting, stronger operational monitoring, and a security review.
- The dashboard is a functional academic prototype, not a live SOC integration. It does not ingest real network traffic or automatically detect attacks.
- The chart's handwritten fields may be hard to read; the core table/attribute names are implemented from the legible diagram and normalized to SQLite naming conventions.

## Reset local demo data

Stop the app, delete `cybershield.db`, and restart `python app.py`. This recreates the schema and three demo accounts. This permanently deletes locally stored records.

## Health check

Open **http://127.0.0.1:5000/health**. A successful response includes database status and table counts.

## Updated role workflow and normalization

- Registration supports unlimited Complainer/Customer and Engineer accounts. Public registration cannot create an Admin account. The canonical demo Admin is `admin@cybershield.local`; initialization enforces one Admin role.
- Customers can view only their own incidents and case conversations. Engineers can browse open incidents and request access independently; each customer approval applies only to that engineer and incident. Several engineers can work on the same incident if each is approved.
- Customers and approved engineers can exchange messages in the incident conversation. Admins can inspect all core tables and audit records.
- Incident submission automatically writes the incident, a linked security event, a linked alert, and an audit record. Evidence and forensic records must be added only when there is actual demo evidence to record.
- See `NORMALIZATION.md` for the 1NF, 2NF, 3NF and BCNF design notes.

## Updated role workflow and normalization
- Registration supports multiple Complainer/Customer and Engineer accounts. Public registration cannot create an Admin account. The canonical demo Admin is `admin@cybershield.local`; initialization demotes any other Admin role.
- Customers can view only their own incidents and case conversations. Engineers can browse open incidents and request access independently; approval applies to that engineer and incident. Multiple engineers can work on one incident if each is approved.
- Customers and approved engineers can exchange messages in the incident conversation. Admins can inspect all 19 core tables and audit records.
- Incident submission automatically writes a linked incident, security event, alert, and audit entry. Evidence and forensic records must not be fabricated.
- See `NORMALIZATION.md` for 1NF, 2NF, 3NF, and BCNF design notes.
