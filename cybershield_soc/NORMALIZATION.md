# CyberShield SOC database normalization notes

The 19 ER-diagram tables are retained and available to the administrator through Database explorer. The application also uses `users`, `access_request`, and `incident_message` for authentication, customer-controlled engineer access, and case conversations.

## Normalization approach
- **1NF:** Every field stores one value; repeating investigation actions are represented as separate `response_action` rows, and messages are separate `incident_message` rows.
- **2NF:** Non-key attributes in tables with composite keys depend on the complete key. `campaign_event` uses `(campaign_id, event_id)` as its composite primary key and stores only attributes of that campaign-event association.
- **3NF:** Reusable concepts are stored separately. Attack categories are in `attack_type`; host data is in `server`; IP details are in `ip_address`; observations are in `security_event`; alerts reference events; incidents reference the relevant event and alert; actions reference incidents and investigators; resolutions are stored separately with one resolution per incident.
- **BCNF:** Identified candidate keys are enforced with primary keys and unique constraints (including account email, server host name, attack type name, and one resolution per incident). BCNF holds where the modeled functional dependencies are determined by candidate keys; any new business rules should be checked against their actual functional dependencies.

## Core relationships
- `ip_address`, `server`, and `attack_type` each relate one-to-many to `security_event`.
- `security_event` relates one-to-many to `alert`; an incident references its event and alert.
- `incident` relates one-to-many to evidence, response actions, messages, and access requests.
- Users can report many incidents and send many messages.
- Each `access_request` stores one engineer's request and the customer's decision. Multiple engineers can request the same incident; approval is per engineer and incident.
- `incident_assignment` represents the many-to-many relationship between incidents and investigators.

## Automatic persistence
Submitting a customer incident automatically saves the incident, creates/reuses generic `server` and `attack_type` reference rows, records a `security_event`, creates an `alert`, links these records with foreign keys, and writes an audit entry. Real evidence, custody transfers, and forensic findings are not fabricated; insert those when demo evidence is supplied. Writes use parameterized SQL and foreign-key enforcement.

## Engineer capability fields
The `users` table stores each engineer's `specialization` and `max_severity` attributes alongside the account identity. This is one capability profile per user, so it does not create repeating groups. If the project later needs multiple specialties per engineer or a history of certifications, those should be moved into separate `engineer_specialization` and `engineer_qualification` relations rather than adding comma-separated values to `users`.

## Incident report privacy
`incident.summary` stores only the short public work-queue summary. The longer customer-provided description is stored separately in `incident.details`. Engineers see summaries in the work queue, while the detail route and messages are guarded by the customer-approved access request. Customer dashboard queries are filtered by `created_by_user_id`.
