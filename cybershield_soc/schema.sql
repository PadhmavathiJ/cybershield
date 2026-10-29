PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','complainer','engineer')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ip_address (
    ip_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_string TEXT NOT NULL UNIQUE,
    is_internal INTEGER NOT NULL DEFAULT 0 CHECK (is_internal IN (0,1)),
    geo_location TEXT,
    isp TEXT,
    first_seen_utc TEXT,
    last_seen_utc TEXT
);

CREATE TABLE IF NOT EXISTS server (
    server_id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_name TEXT NOT NULL UNIQUE,
    critically_level TEXT NOT NULL DEFAULT 'medium',
    owner_dept TEXT,
    os_type TEXT,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
    ip_id INTEGER,
    FOREIGN KEY (ip_id) REFERENCES ip_address(ip_id) ON UPDATE CASCADE ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS attack_type (
    attack_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    category TEXT,
    description TEXT,
    kill_chain_phase TEXT,
    delivery_method TEXT
);

CREATE TABLE IF NOT EXISTS security_event (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    ip_id INTEGER,
    attack_type_id INTEGER,
    event_timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity_score INTEGER NOT NULL DEFAULT 1 CHECK (severity_score BETWEEN 1 AND 10),
    protocol TEXT,
    packet_count INTEGER DEFAULT 0,
    bytes_count INTEGER DEFAULT 0,
    is_flagged INTEGER NOT NULL DEFAULT 0 CHECK (is_flagged IN (0,1)),
    FOREIGN KEY (server_id) REFERENCES server(server_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (ip_id) REFERENCES ip_address(ip_id) ON UPDATE CASCADE ON DELETE SET NULL,
    FOREIGN KEY (attack_type_id) REFERENCES attack_type(attack_type_id) ON UPDATE CASCADE ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS alert (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    risk_score REAL NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (event_id) REFERENCES security_event(event_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    incident_id INTEGER,
    evidence_type TEXT NOT NULL,
    file_size INTEGER DEFAULT 0,
    source_location TEXT,
    hash_value TEXT,
    collected_by TEXT,
    collected_at TEXT,
    is_sensitive INTEGER NOT NULL DEFAULT 0 CHECK (is_sensitive IN (0,1)),
    FOREIGN KEY (event_id) REFERENCES security_event(event_id) ON UPDATE CASCADE ON DELETE SET NULL,
    FOREIGN KEY (incident_id) REFERENCES incident(incident_id) ON UPDATE CASCADE ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS chain_of_custody (
    custody_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL,
    investigator_id INTEGER,
    transfer_method TEXT,
    received_condition TEXT,
    remarks TEXT,
    transfer_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    purpose TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (investigator_id) REFERENCES investigator(investigator_id) ON UPDATE CASCADE ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS forensic_analysis (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL,
    investigator_id INTEGER,
    findings TEXT,
    technique_used TEXT,
    malware_iocs TEXT,
    confidence_level REAL DEFAULT 0 CHECK (confidence_level BETWEEN 0 AND 100),
    analyzed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (investigator_id) REFERENCES investigator(investigator_id) ON UPDATE CASCADE ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS threat_actor (
    actor_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alias TEXT NOT NULL,
    motivation TEXT,
    first_seen TEXT,
    last_seen TEXT,
    actor_type TEXT,
    country_origin TEXT
);

CREATE TABLE IF NOT EXISTS historical_threat_intelligence (
    intel_id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    industry TEXT,
    org_firm_names TEXT,
    defense_mechanism TEXT,
    source TEXT,
    last_updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_id) REFERENCES threat_actor(actor_id) ON UPDATE CASCADE ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS attack_campaign (
    campaign_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    start_time TEXT,
    end_time TEXT,
    status TEXT NOT NULL DEFAULT 'planned',
    objective TEXT,
    description TEXT,
    action_id INTEGER,
    FOREIGN KEY (action_id) REFERENCES response_action(action_id) ON UPDATE CASCADE ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS campaign_event (
    campaign_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (campaign_id, event_id),
    FOREIGN KEY (campaign_id) REFERENCES attack_campaign(campaign_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES security_event(event_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sla (
    sla_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER UNIQUE,
    response_deadline TEXT,
    breach_hours REAL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    resolution_deadline TEXT,
    FOREIGN KEY (incident_id) REFERENCES incident(incident_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    alert_id INTEGER,
    campaign_id INTEGER,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    summary TEXT NOT NULL,
    created_by_user_id INTEGER,
    opened_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at TEXT,
    FOREIGN KEY (event_id) REFERENCES security_event(event_id) ON UPDATE CASCADE ON DELETE SET NULL,
    FOREIGN KEY (alert_id) REFERENCES alert(alert_id) ON UPDATE CASCADE ON DELETE SET NULL,
    FOREIGN KEY (campaign_id) REFERENCES attack_campaign(campaign_id) ON UPDATE CASCADE ON DELETE SET NULL,
    FOREIGN KEY (created_by_user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS investigator (
    investigator_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    phone TEXT,
    specialization TEXT,
    experience_years INTEGER DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1))
);

CREATE TABLE IF NOT EXISTS incident_assignment (
    assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    investigator_id INTEGER NOT NULL,
    role TEXT,
    is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0,1)),
    assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incident(incident_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (investigator_id) REFERENCES investigator(investigator_id) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS access_request (
    request_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    engineer_user_id INTEGER NOT NULL,
    complainer_user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decided_at TEXT,
    decision_note TEXT,
    UNIQUE (incident_id, engineer_user_id),
    FOREIGN KEY (incident_id) REFERENCES incident(incident_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (engineer_user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (complainer_user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS response_action (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    investigator_id INTEGER,
    action_type TEXT NOT NULL,
    description TEXT,
    performed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    outcome TEXT,
    FOREIGN KEY (incident_id) REFERENCES incident(incident_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (investigator_id) REFERENCES investigator(investigator_id) ON UPDATE CASCADE ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS resolution (
    resolution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL UNIQUE,
    investigator_id INTEGER,
    closed_at TEXT,
    final_status TEXT NOT NULL DEFAULT 'resolved',
    financial_loss REAL DEFAULT 0,
    root_cause TEXT,
    lessons_learned TEXT,
    FOREIGN KEY (incident_id) REFERENCES incident(incident_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (investigator_id) REFERENCES investigator(investigator_id) ON UPDATE CASCADE ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    table_name TEXT NOT NULL,
    record_id INTEGER,
    old_values TEXT,
    new_values TEXT,
    action_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_incident_creator ON incident(created_by_user_id);
CREATE INDEX IF NOT EXISTS idx_access_request_status ON access_request(status);
CREATE INDEX IF NOT EXISTS idx_security_event_timestamp ON security_event(event_timestamp);
CREATE INDEX IF NOT EXISTS idx_security_event_server ON security_event(server_id);
CREATE INDEX IF NOT EXISTS idx_incident_status ON incident(status);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alert(status);


CREATE TABLE IF NOT EXISTS incident_message (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    sender_user_id INTEGER NOT NULL,
    body TEXT NOT NULL CHECK(length(trim(body)) >= 1),
    sent_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incident(incident_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (sender_user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_incident_message_case_time ON incident_message(incident_id, sent_at);
CREATE INDEX IF NOT EXISTS idx_access_request_customer_status ON access_request(complainer_user_id, status);
CREATE INDEX IF NOT EXISTS idx_incident_customer_status ON incident(created_by_user_id, status);
