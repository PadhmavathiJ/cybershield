from app import connect_db, init_db

init_db()
con = connect_db()
if con.execute('SELECT COUNT(*) FROM ip_address').fetchone()[0] == 0:
    ip_id = con.execute('INSERT INTO ip_address (ip_string, is_internal, geo_location, isp, first_seen_utc, last_seen_utc) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)', ('203.0.113.42', 0, 'Example network', 'Example ISP')).lastrowid
    server_id = con.execute('INSERT INTO server (host_name, critically_level, owner_dept, os_type, is_active, ip_id) VALUES (?, ?, ?, ?, ?, ?)', ('web-prod-01', 'high', 'IT Operations', 'Ubuntu Linux', 1, ip_id)).lastrowid
    type_id = con.execute('INSERT INTO attack_type (name, category, description, kill_chain_phase, delivery_method) VALUES (?, ?, ?, ?, ?)', ('SQL Injection', 'Web Application', 'Suspicious SQL injection pattern against a web endpoint', 'Exploitation', 'HTTP request')).lastrowid
    event_id = con.execute('INSERT INTO security_event (server_id, ip_id, attack_type_id, event_timestamp, severity_score, protocol, packet_count, bytes_count, is_flagged) VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?)', (server_id, ip_id, type_id, 8, 'HTTPS', 24, 18400, 1)).lastrowid
    alert_id = con.execute('INSERT INTO alert (event_id, risk_score, severity, status) VALUES (?, ?, ?, ?)', (event_id, 82.5, 'high', 'open')).lastrowid
    customer_id = con.execute("SELECT user_id FROM users WHERE email='customer@cybershield.local'").fetchone()[0]
    incident_id = con.execute('INSERT INTO incident (event_id, alert_id, severity, status, summary, created_by_user_id) VALUES (?, ?, ?, ?, ?, ?)', (event_id, alert_id, 'high', 'investigating', 'Suspicious SQL injection activity on production web server', customer_id)).lastrowid
    investigator_id = con.execute('INSERT INTO investigator (name, email, phone, specialization, experience_years, is_active) VALUES (?, ?, ?, ?, ?, ?)', ('Alex Morgan', 'alex.morgan@example.test', '000-000-0000', 'Application Security', 4, 1)).lastrowid
    action_id = con.execute('INSERT INTO response_action (incident_id, investigator_id, action_type, description, outcome) VALUES (?, ?, ?, ?, ?)', (incident_id, investigator_id, 'Block source', 'Temporarily blocked the suspicious source and reviewed web server logs', 'Source blocked; investigation ongoing')).lastrowid
    campaign_id = con.execute('INSERT INTO attack_campaign (name, start_time, status, objective, description, action_id) VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?, ?)', ('Web perimeter review', 'active', 'Investigate related web attacks', 'Demo campaign linking a campaign to a security event', action_id)).lastrowid
    con.execute('UPDATE incident SET campaign_id=? WHERE incident_id=?', (campaign_id, incident_id))
    con.execute('INSERT INTO campaign_event (campaign_id, event_id) VALUES (?, ?)', (campaign_id, event_id))
    evidence_id = con.execute('INSERT INTO evidence (event_id, incident_id, evidence_type, file_size, source_location, hash_value, collected_by, collected_at, is_sensitive) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)', (event_id, incident_id, 'Web server log excerpt', 4096, '/evidence/demo/web-access.log', 'demo-sha256-placeholder', 'Alex Morgan', 0)).lastrowid
    con.execute('INSERT INTO chain_of_custody (evidence_id, investigator_id, transfer_method, received_condition, remarks, purpose) VALUES (?, ?, ?, ?, ?, ?)', (evidence_id, investigator_id, 'Secure upload', 'Intact', 'Demonstration evidence record', 'Forensic review'))
    con.execute('INSERT INTO forensic_analysis (evidence_id, investigator_id, findings, technique_used, malware_iocs, confidence_level) VALUES (?, ?, ?, ?, ?, ?)', (evidence_id, investigator_id, 'Repeated suspicious query parameters observed in sample log', 'Log correlation', 'No malware IOC confirmed in demo data', 75.0))
    con.execute('INSERT INTO sla (incident_id, response_deadline, breach_hours, status, resolution_deadline) VALUES (?, datetime(CURRENT_TIMESTAMP, "+1 hour"), 0, ?, datetime(CURRENT_TIMESTAMP, "+24 hours"))', (incident_id, 'active'))
    con.execute('INSERT INTO historical_threat_intelligence (industry, org_firm_names, defense_mechanism, source) VALUES (?, ?, ?, ?)', ('Technology', 'Example organization', 'Input validation and WAF rules', 'Internal demo intelligence'))
    con.execute('INSERT INTO evidence (event_id, incident_id, evidence_type, file_size, source_location, collected_by, collected_at, is_sensitive) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)', (event_id, incident_id, 'Packet capture metadata', 1024, '/evidence/demo/capture.pcap.meta', 'Alex Morgan', 1))
    con.execute('INSERT INTO resolution (incident_id, investigator_id, final_status, financial_loss, root_cause, lessons_learned) VALUES (?, ?, ?, ?, ?, ?)', (incident_id, investigator_id, 'pending', 0, 'Under investigation', 'Validate inputs and review WAF coverage'))
    con.execute('INSERT INTO incident_assignment (incident_id, investigator_id, role, is_primary) VALUES (?, ?, ?, ?)', (incident_id, investigator_id, 'Lead investigator', 1))
    con.execute('INSERT INTO threat_actor (alias, motivation, first_seen, last_seen, actor_type, country_origin) VALUES (?, ?, ?, ?, ?, ?)', ('Demo Actor', 'Financial gain', '2026-01-01', '2026-10-01', 'Unknown', 'Unknown'))
    con.commit()
    print('Demo records added.')
else:
    print('Database already contains IP records; no demo data added.')
con.close()
