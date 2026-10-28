ALTER TABLE app_user ADD (
    CONSTRAINT ck_user_role CHECK (
        role_code IN ('ADMIN','MANAGER','ANALYST','AUDITOR')
    ),
    CONSTRAINT ck_user_active CHECK (is_active IN (0,1)),
    CONSTRAINT ck_user_email_trim CHECK (email = TRIM(email))
);

CREATE UNIQUE INDEX uq_user_email_ci
    ON app_user (LOWER(email));

ALTER TABLE investigator ADD (
    CONSTRAINT fk_inv_user FOREIGN KEY (user_id)
        REFERENCES app_user(user_id),
    CONSTRAINT uq_inv_user UNIQUE (user_id),
    CONSTRAINT ck_inv_availability CHECK (
        availability IN ('AVAILABLE','BUSY','INACTIVE')
    )
);

ALTER TABLE ip_address ADD (
    CONSTRAINT uq_ip_text UNIQUE (ip_text),
    CONSTRAINT ck_ip_simulated CHECK (is_simulated IN (0,1))
);

ALTER TABLE server ADD (
    CONSTRAINT uq_server_hostname UNIQUE (hostname),
    CONSTRAINT ck_server_criticality CHECK (
        criticality IN ('LOW','MEDIUM','HIGH','CRITICAL')
    ),
    CONSTRAINT ck_server_active CHECK (is_active IN (0,1))
);

ALTER TABLE server_ip_address ADD (
    CONSTRAINT fk_sip_server FOREIGN KEY (server_id)
        REFERENCES server(server_id),
    CONSTRAINT fk_sip_ip FOREIGN KEY (ip_id)
        REFERENCES ip_address(ip_id),
    CONSTRAINT ck_sip_dates CHECK (
        valid_to IS NULL OR valid_to > valid_from
    )
);

CREATE UNIQUE INDEX uq_sip_start
    ON server_ip_address (
        server_id,
        ip_id,
        SYS_EXTRACT_UTC(valid_from)
    );

CREATE UNIQUE INDEX uq_sip_current_pair
    ON server_ip_address (
        CASE WHEN valid_to IS NULL THEN server_id END,
        CASE WHEN valid_to IS NULL THEN ip_id END
    );

ALTER TABLE attack_type ADD (
    CONSTRAINT uq_attack_type_name UNIQUE (name)
);

ALTER TABLE threat_actor ADD (
    CONSTRAINT uq_actor_name UNIQUE (name),
    CONSTRAINT ck_actor_attribution CHECK (
        attribution_status IN ('UNVERIFIED','ASSERTED')
    )
);

ALTER TABLE historical_threat_intelligence ADD (
    CONSTRAINT fk_hti_actor FOREIGN KEY (actor_id)
        REFERENCES threat_actor(actor_id),
    CONSTRAINT fk_hti_attack FOREIGN KEY (attack_type_id)
        REFERENCES attack_type(attack_type_id),
    CONSTRAINT ck_hti_confidence CHECK (
        confidence BETWEEN 0 AND 100
    )
);

ALTER TABLE attack_campaign ADD (
    CONSTRAINT fk_campaign_actor FOREIGN KEY (actor_id)
        REFERENCES threat_actor(actor_id),
    CONSTRAINT uq_campaign_name UNIQUE (name),
    CONSTRAINT ck_campaign_dates CHECK (
        ended_at IS NULL OR ended_at >= started_at
    )
);

ALTER TABLE soc_policy ADD (
    CONSTRAINT ck_policy_nonnegative CHECK (number_value >= 0),
    CONSTRAINT ck_policy_threshold CHECK (
        policy_key <> 'alert_threshold'
        OR number_value BETWEEN 0 AND 100
    )
);

ALTER TABLE security_event ADD (
    CONSTRAINT uq_event_source_key UNIQUE (source_event_key),
    CONSTRAINT fk_event_server FOREIGN KEY (server_id)
        REFERENCES server(server_id),
    CONSTRAINT fk_event_source_ip FOREIGN KEY (source_ip_id)
        REFERENCES ip_address(ip_id),
    CONSTRAINT fk_event_attack FOREIGN KEY (attack_type_id)
        REFERENCES attack_type(attack_type_id),
    CONSTRAINT ck_event_packets CHECK (packet_count >= 0),
    CONSTRAINT ck_event_bytes_in CHECK (bytes_in >= 0),
    CONSTRAINT ck_event_bytes_out CHECK (bytes_out >= 0),
    CONSTRAINT ck_event_score CHECK (
        severity_score BETWEEN 0 AND 100
    ),
    CONSTRAINT ck_event_simulated CHECK (
        is_simulated IN (0,1)
    )
);

ALTER TABLE alert ADD (
    CONSTRAINT fk_alert_event FOREIGN KEY (event_id)
        REFERENCES security_event(event_id),
    CONSTRAINT uq_alert_event UNIQUE (event_id),
    CONSTRAINT fk_alert_triager FOREIGN KEY (triaged_by)
        REFERENCES app_user(user_id),
    CONSTRAINT ck_alert_severity CHECK (
        severity IN ('LOW','MEDIUM','HIGH','CRITICAL')
    ),
    CONSTRAINT ck_alert_status CHECK (
        status IN ('NEW','ACKNOWLEDGED','ESCALATED','DISMISSED')
    ),
    CONSTRAINT ck_alert_ack_time CHECK (
        acknowledged_at IS NULL
        OR acknowledged_at >= created_at
    )
);

ALTER TABLE campaign_event ADD (
    CONSTRAINT fk_ce_campaign FOREIGN KEY (campaign_id)
        REFERENCES attack_campaign(campaign_id),
    CONSTRAINT fk_ce_event FOREIGN KEY (event_id)
        REFERENCES security_event(event_id)
);

ALTER TABLE incident ADD (
    CONSTRAINT fk_incident_campaign FOREIGN KEY (campaign_id)
        REFERENCES attack_campaign(campaign_id),
    CONSTRAINT fk_incident_creator FOREIGN KEY (created_by)
        REFERENCES app_user(user_id),
    CONSTRAINT ck_incident_severity CHECK (
        severity IN ('LOW','MEDIUM','HIGH','CRITICAL')
    ),
    CONSTRAINT ck_incident_status CHECK (
        status IN (
            'OPEN','TRIAGED','INVESTIGATING',
            'CONTAINED','RESOLVED','CLOSED'
        )
    ),
    CONSTRAINT ck_incident_close_time CHECK (
        closed_at IS NULL OR closed_at >= opened_at
    ),
    CONSTRAINT ck_incident_closed CHECK (
        (status = 'CLOSED' AND closed_at IS NOT NULL)
        OR
        (status <> 'CLOSED' AND closed_at IS NULL)
    )
);

ALTER TABLE incident_alert ADD (
    CONSTRAINT fk_ia_incident FOREIGN KEY (incident_id)
        REFERENCES incident(incident_id),
    CONSTRAINT fk_ia_alert FOREIGN KEY (alert_id)
        REFERENCES alert(alert_id),
    CONSTRAINT uq_ia_alert UNIQUE (alert_id)
);

ALTER TABLE investigation_cycle ADD (
    CONSTRAINT fk_cycle_incident FOREIGN KEY (incident_id)
        REFERENCES incident(incident_id),
    CONSTRAINT uq_cycle_number UNIQUE (incident_id, cycle_no),
    CONSTRAINT ck_cycle_number CHECK (cycle_no >= 1),
    CONSTRAINT ck_cycle_dates CHECK (
        ended_at IS NULL OR ended_at >= started_at
    ),
    CONSTRAINT ck_cycle_reopen_reason CHECK (
        cycle_no = 1 OR reopen_reason IS NOT NULL
    )
);

CREATE UNIQUE INDEX uq_cycle_active
    ON investigation_cycle (
        CASE WHEN ended_at IS NULL THEN incident_id END
    );

ALTER TABLE incident_assignment ADD (
    CONSTRAINT fk_assign_cycle FOREIGN KEY (cycle_id)
        REFERENCES investigation_cycle(cycle_id),
    CONSTRAINT fk_assign_inv FOREIGN KEY (investigator_id)
        REFERENCES investigator(investigator_id),
    CONSTRAINT fk_assign_actor FOREIGN KEY (assigned_by)
        REFERENCES app_user(user_id),
    CONSTRAINT ck_assign_role CHECK (
        assignment_role IN ('LEAD','SUPPORT')
    ),
    CONSTRAINT ck_assign_dates CHECK (
        ended_at IS NULL OR ended_at >= assigned_at
    )
);

CREATE UNIQUE INDEX uq_assign_active_lead
    ON incident_assignment (
        CASE
            WHEN ended_at IS NULL AND assignment_role = 'LEAD'
            THEN cycle_id
        END
    );

CREATE UNIQUE INDEX uq_assign_active_member
    ON incident_assignment (
        CASE WHEN ended_at IS NULL THEN cycle_id END,
        CASE WHEN ended_at IS NULL THEN investigator_id END
    );

ALTER TABLE sla ADD (
    CONSTRAINT fk_sla_cycle FOREIGN KEY (cycle_id)
        REFERENCES investigation_cycle(cycle_id),
    CONSTRAINT uq_sla_cycle UNIQUE (cycle_id),
    CONSTRAINT fk_sla_escalator FOREIGN KEY (escalated_by)
        REFERENCES app_user(user_id),
    CONSTRAINT ck_sla_deadlines CHECK (
        resolution_due_at >= response_due_at
    ),
    CONSTRAINT ck_sla_escalation CHECK (
        (
            escalated_at IS NULL
            AND escalated_by IS NULL
        )
        OR
        (
            escalated_at IS NOT NULL
            AND escalated_by IS NOT NULL
            AND breach_reason IS NOT NULL
        )
    )
);

ALTER TABLE incident_status_history ADD (
    CONSTRAINT fk_history_cycle FOREIGN KEY (cycle_id)
        REFERENCES investigation_cycle(cycle_id),
    CONSTRAINT fk_history_actor FOREIGN KEY (changed_by)
        REFERENCES app_user(user_id),
    CONSTRAINT ck_history_from CHECK (
        from_status IN (
            'OPEN','TRIAGED','INVESTIGATING',
            'CONTAINED','RESOLVED','CLOSED'
        )
    ),
    CONSTRAINT ck_history_to CHECK (
        to_status IN (
            'OPEN','TRIAGED','INVESTIGATING',
            'CONTAINED','RESOLVED','CLOSED'
        )
    ),
    CONSTRAINT ck_history_changed CHECK (
        from_status IS NULL OR from_status <> to_status
    )
);

ALTER TABLE evidence ADD (
    CONSTRAINT fk_evidence_incident FOREIGN KEY (incident_id)
        REFERENCES incident(incident_id),
    CONSTRAINT fk_evidence_collector FOREIGN KEY (collected_by)
        REFERENCES investigator(investigator_id),
    CONSTRAINT fk_evidence_custodian FOREIGN KEY (current_custodian_id)
        REFERENCES investigator(investigator_id),
    CONSTRAINT uq_evidence_storage UNIQUE (storage_key),
    CONSTRAINT ck_evidence_size CHECK (file_size >= 0),
    CONSTRAINT ck_evidence_sensitivity CHECK (
        sensitivity IN ('INTERNAL','RESTRICTED')
    ),
    CONSTRAINT ck_evidence_hash CHECK (
        REGEXP_LIKE(sha256, '^[0-9A-Fa-f]{64}$')
    )
);

ALTER TABLE chain_of_custody ADD (
    CONSTRAINT fk_custody_evidence FOREIGN KEY (evidence_id)
        REFERENCES evidence(evidence_id),
    CONSTRAINT fk_custody_from FOREIGN KEY (from_investigator_id)
        REFERENCES investigator(investigator_id),
    CONSTRAINT fk_custody_to FOREIGN KEY (to_investigator_id)
        REFERENCES investigator(investigator_id),
    CONSTRAINT fk_custody_actor FOREIGN KEY (performed_by)
        REFERENCES app_user(user_id),
    CONSTRAINT ck_custody_distinct CHECK (
        from_investigator_id IS NULL
        OR from_investigator_id <> to_investigator_id
    )
);

CREATE UNIQUE INDEX uq_custody_initial
    ON chain_of_custody (
        CASE
            WHEN from_investigator_id IS NULL THEN evidence_id
        END
    );

ALTER TABLE forensic_analysis ADD (
    CONSTRAINT fk_analysis_evidence FOREIGN KEY (evidence_id)
        REFERENCES evidence(evidence_id),
    CONSTRAINT fk_analysis_inv FOREIGN KEY (investigator_id)
        REFERENCES investigator(investigator_id),
    CONSTRAINT fk_analysis_previous FOREIGN KEY (supersedes_analysis_id)
        REFERENCES forensic_analysis(analysis_id),
    CONSTRAINT ck_analysis_confidence CHECK (
        confidence BETWEEN 0 AND 100
    ),
    CONSTRAINT ck_analysis_not_self CHECK (
        supersedes_analysis_id IS NULL
        OR supersedes_analysis_id <> analysis_id
    )
);

ALTER TABLE response_action ADD (
    CONSTRAINT fk_action_cycle FOREIGN KEY (cycle_id)
        REFERENCES investigation_cycle(cycle_id),
    CONSTRAINT fk_action_actor FOREIGN KEY (performed_by)
        REFERENCES app_user(user_id)
);

ALTER TABLE resolution ADD (
    CONSTRAINT fk_resolution_cycle FOREIGN KEY (cycle_id)
        REFERENCES investigation_cycle(cycle_id),
    CONSTRAINT uq_resolution_cycle UNIQUE (cycle_id),
    CONSTRAINT fk_resolution_actor FOREIGN KEY (resolved_by)
        REFERENCES app_user(user_id),
    CONSTRAINT ck_resolution_loss CHECK (financial_loss >= 0)
);

ALTER TABLE audit_log ADD (
    CONSTRAINT fk_audit_actor FOREIGN KEY (actor_user_id)
        REFERENCES app_user(user_id)
);

CREATE INDEX ix_sip_ip
    ON server_ip_address (ip_id);

CREATE INDEX ix_hti_actor
    ON historical_threat_intelligence (actor_id);

CREATE INDEX ix_hti_attack
    ON historical_threat_intelligence (attack_type_id);

CREATE INDEX ix_campaign_actor
    ON attack_campaign (actor_id);

CREATE INDEX ix_event_time
    ON security_event (event_at);

CREATE INDEX ix_event_server_time
    ON security_event (server_id, event_at);

CREATE INDEX ix_event_ip_time
    ON security_event (source_ip_id, event_at);

CREATE INDEX ix_event_attack
    ON security_event (attack_type_id);

CREATE INDEX ix_alert_status_severity
    ON alert (status, severity);

CREATE INDEX ix_alert_triager
    ON alert (triaged_by);

CREATE INDEX ix_ce_event
    ON campaign_event (event_id);

CREATE INDEX ix_incident_status_time
    ON incident (status, opened_at);

CREATE INDEX ix_incident_campaign
    ON incident (campaign_id);

CREATE INDEX ix_incident_creator
    ON incident (created_by);

CREATE INDEX ix_assign_cycle
    ON incident_assignment (cycle_id);

CREATE INDEX ix_assign_inv_end
    ON incident_assignment (investigator_id, ended_at);

CREATE INDEX ix_assign_actor
    ON incident_assignment (assigned_by);

CREATE INDEX ix_sla_escalator
    ON sla (escalated_by);

CREATE INDEX ix_history_cycle_time
    ON incident_status_history (cycle_id, changed_at);

CREATE INDEX ix_history_actor
    ON incident_status_history (changed_by);

CREATE INDEX ix_evidence_incident
    ON evidence (incident_id);

CREATE INDEX ix_evidence_collector
    ON evidence (collected_by);

CREATE INDEX ix_evidence_custodian
    ON evidence (current_custodian_id);

CREATE INDEX ix_custody_evidence_time
    ON chain_of_custody (evidence_id, transferred_at);

CREATE INDEX ix_custody_from
    ON chain_of_custody (from_investigator_id);

CREATE INDEX ix_custody_to
    ON chain_of_custody (to_investigator_id);

CREATE INDEX ix_custody_actor
    ON chain_of_custody (performed_by);

CREATE INDEX ix_analysis_evidence
    ON forensic_analysis (evidence_id);

CREATE INDEX ix_analysis_inv
    ON forensic_analysis (investigator_id);

CREATE INDEX ix_analysis_previous
    ON forensic_analysis (supersedes_analysis_id);

CREATE INDEX ix_action_cycle
    ON response_action (cycle_id);

CREATE INDEX ix_action_actor
    ON response_action (performed_by);

CREATE INDEX ix_resolution_actor
    ON resolution (resolved_by);

CREATE INDEX ix_audit_actor
    ON audit_log (actor_user_id);

CREATE INDEX ix_audit_entity_time
    ON audit_log (entity_name, entity_id, occurred_at);