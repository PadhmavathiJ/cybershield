SET SERVEROUTPUT ON
SET DEFINE ON
SET VERIFY OFF

ACCEPT cs_demo_hash CHAR PROMPT 'Paste the generated demo password hash: ' HIDE

VARIABLE demo_hash VARCHAR2(255)

BEGIN
    :demo_hash := '&cs_demo_hash';
END;
/

UNDEFINE cs_demo_hash

DECLARE
    TYPE id_array IS TABLE OF NUMBER INDEX BY PLS_INTEGER;

    v_users id_array;
    v_investigators id_array;
    v_servers id_array;
    v_ips id_array;
    v_types id_array;
    v_actors id_array;
    v_campaigns id_array;
    v_events id_array;
    v_alerts id_array;
    v_evidence_hash VARCHAR2(64);

    v_attack_names SYS.ODCIVARCHAR2LIST :=
        SYS.ODCIVARCHAR2LIST(
            'SQL Injection',
            'Cross Site Scripting',
            'Credential Stuffing',
            'Password Spraying',
            'SSH Brute Force',
            'RDP Brute Force',
            'DNS Tunneling',
            'DNS Amplification',
            'SYN Flood',
            'HTTP Request Flood',
            'Port Scanning',
            'Service Enumeration',
            'Directory Traversal',
            'Command Injection',
            'Server Side Request Forgery',
            'Insecure File Upload',
            'Session Hijacking',
            'Phishing',
            'Spear Phishing',
            'Malicious Attachment',
            'Ransomware Activity',
            'Cryptomining Activity',
            'Data Exfiltration',
            'Privilege Escalation',
            'Lateral Movement',
            'Suspicious PowerShell',
            'Web Shell Activity',
            'Unauthorized Configuration Change',
            'Suspicious Scheduled Task',
            'Credential Dumping'
        );

    v_admin NUMBER;
    v_manager NUMBER;
    v_auditor NUMBER;
    v_incident NUMBER;
    v_evidence NUMBER;
    v_analysis NUMBER;
    v_action NUMBER;
    v_resolution NUMBER;
    v_assignment NUMBER;
    v_new_cycle NUMBER;
    v_lead PLS_INTEGER;
    v_receiver PLS_INTEGER;
    v_parent PLS_INTEGER;
    v_count NUMBER;
    v_hash VARCHAR2(255);
    v_previous_client VARCHAR2(64);
    v_protocol VARCHAR2(16);
    v_now TIMESTAMP WITH TIME ZONE := SYSTIMESTAMP;

    PROCEDURE set_actor(p_user NUMBER) IS
    BEGIN
        DBMS_SESSION.SET_IDENTIFIER(
            TO_CHAR(p_user, 'FM9999999990')
        );
    END;

    PROCEDURE restore_context IS
    BEGIN
        IF v_previous_client IS NULL THEN
            DBMS_SESSION.CLEAR_IDENTIFIER;
        ELSE
            DBMS_SESSION.SET_IDENTIFIER(v_previous_client);
        END IF;
    END;

BEGIN
    v_previous_client :=
        SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER');

    SAVEPOINT seed_start;

    IF SYS_CONTEXT('USERENV', 'SESSION_USER') <> 'CS_OWNER' THEN
        RAISE_APPLICATION_ERROR(
            -20999, 'Run the seed as CS_OWNER'
        );
    END IF;

    v_hash := :demo_hash;

    IF v_hash IS NULL
       OR NOT REGEXP_LIKE(
           v_hash,
           '^pbkdf2:sha256:1000000\$[0-9a-f]{32}\$[0-9a-f]{64}$'
       )
    THEN
        RAISE_APPLICATION_ERROR(
            -20999, 'Paste the hash from create_demo_hash.py'
        );
    END IF;

    FOR t IN (
        SELECT table_name
        FROM user_tables
        WHERE table_name NOT IN (
            'SOC_POLICY', 'SCHEMA_MIGRATION'
        )
    ) LOOP
        EXECUTE IMMEDIATE
            'SELECT COUNT(*) FROM ' ||
            DBMS_ASSERT.SIMPLE_SQL_NAME(t.table_name)
        INTO v_count;

        IF v_count > 0 THEN
            RAISE_APPLICATION_ERROR(
                -20999,
                'Seed requires empty business tables: ' || t.table_name
            );
        END IF;
    END LOOP;

    MERGE INTO soc_policy p
    USING (
        SELECT 'alert_threshold' policy_key, 70 number_value,
               'Minimum simulated event score for alert creation' description
        FROM dual
        UNION ALL
        SELECT 'response_hours', 1,
               'Demo response deadline measured in hours'
        FROM dual
        UNION ALL
        SELECT 'resolution_hours', 24,
               'Demo resolution deadline measured in hours'
        FROM dual
    ) s
    ON (p.policy_key = s.policy_key)
    WHEN MATCHED THEN
        UPDATE SET
            p.number_value = s.number_value,
            p.description = s.description
    WHEN NOT MATCHED THEN
        INSERT (policy_key, number_value, description)
        VALUES (s.policy_key, s.number_value, s.description);

    FOR i IN 1..30 LOOP
        INSERT INTO app_user (
            email, password_hash, full_name, role_code
        ) VALUES (
            CASE
                WHEN i = 1 THEN 'admin@cybershield.example'
                ELSE 'analyst' || TO_CHAR(i, 'FM00') ||
                     '@cybershield.example'
            END,
            v_hash,
            'Demo Investigator ' || TO_CHAR(i, 'FM00'),
            CASE WHEN i = 1 THEN 'ADMIN' ELSE 'ANALYST' END
        )
        RETURNING user_id INTO v_users(i);

        INSERT INTO investigator (
            user_id, specialization, availability
        ) VALUES (
            v_users(i),
            CASE MOD(i, 3)
                WHEN 0 THEN 'Network forensics'
                WHEN 1 THEN 'Log analysis'
                ELSE 'Incident response'
            END,
            'AVAILABLE'
        )
        RETURNING investigator_id INTO v_investigators(i);
    END LOOP;

    v_admin := v_users(1);
    set_actor(v_admin);

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'manager@cybershield.example',
        v_hash, 'Demo SOC Manager', 'MANAGER'
    )
    RETURNING user_id INTO v_manager;

    INSERT INTO app_user (
        email, password_hash, full_name, role_code
    ) VALUES (
        'auditor@cybershield.example',
        v_hash, 'Demo SOC Auditor', 'AUDITOR'
    )
    RETURNING user_id INTO v_auditor;

    FOR i IN 1..30 LOOP
        INSERT INTO ip_address (
            ip_text, country_code, is_simulated
        ) VALUES (
            '192.0.2.' || TO_CHAR(i),
            CASE MOD(i, 5)
                WHEN 0 THEN 'IN'
                WHEN 1 THEN 'US'
                WHEN 2 THEN 'GB'
                WHEN 3 THEN 'DE'
                ELSE NULL
            END,
            1
        )
        RETURNING ip_id INTO v_ips(i);

        INSERT INTO server (
            hostname, os_name, department, criticality
        ) VALUES (
            'DEMO-SRV-' || TO_CHAR(i, 'FM00'),
            CASE WHEN MOD(i, 2) = 0 THEN 'Linux' ELSE 'Windows' END,
            CASE MOD(i, 3)
                WHEN 0 THEN 'Finance'
                WHEN 1 THEN 'Engineering'
                ELSE 'Operations'
            END,
            CASE
                WHEN MOD(i, 3) = 0 THEN 'CRITICAL'
                ELSE 'HIGH'
            END
        )
        RETURNING server_id INTO v_servers(i);

        INSERT INTO server_ip_address (
            server_id, ip_id, valid_from
        ) VALUES (
            v_servers(i), v_ips(i),
            v_now - INTERVAL '30' DAY
        );

        INSERT INTO attack_type (
            name, description
        ) VALUES (
            v_attack_names(i),
            'Synthetic scenario demonstrating ' ||
            v_attack_names(i) || '; no real attack executed'
        )
        RETURNING attack_type_id INTO v_types(i);

        INSERT INTO threat_actor (
            name, description, attribution_status
        ) VALUES (
            'Fictional Actor ' || TO_CHAR(i, 'FM00'),
            'Invented demo actor; no attribution to a real person or group',
            'UNVERIFIED'
        )
        RETURNING actor_id INTO v_actors(i);

        INSERT INTO historical_threat_intelligence (
            actor_id,
            attack_type_id,
            title,
            source_ref,
            observed_at,
            confidence,
            details
        ) VALUES (
            v_actors(i),
            v_types(i),
            'Simulated intelligence for ' || v_attack_names(i),
            'demo://intelligence/' || TO_CHAR(i),
            v_now - NUMTODSINTERVAL(i, 'DAY'),
            50 + MOD(i, 40),
            'Fictional intelligence used for relational query demonstrations'
        );

        INSERT INTO attack_campaign (
            actor_id, name, started_at, description
        ) VALUES (
            v_actors(i),
            'Simulated Campaign ' || TO_CHAR(i, 'FM00'),
            v_now - INTERVAL '30' DAY,
            'Synthetic campaign involving ' || v_attack_names(i)
        )
        RETURNING campaign_id INTO v_campaigns(i);
    END LOOP;

    FOR i IN 1..120 LOOP
        v_parent := MOD(i - 1, 30) + 1;

        v_protocol :=
            CASE MOD(i, 3)
                WHEN 0 THEN 'HTTPS'
                WHEN 1 THEN 'TCP'
                ELSE 'DNS'
            END;

        sp_ingest_event(
            v_admin,
            'DEMO-EVENT-' || TO_CHAR(i, 'FM000'),
            v_servers(v_parent),
            v_ips(v_parent),
            v_types(v_parent),
            v_now - NUMTODSINTERVAL(MOD(i, 14), 'DAY'),
            v_protocol,
            i * 10,
            i * 100,
            i * 50,
            CASE WHEN MOD(i, 2) = 0 THEN 95 ELSE 80 END,
            'SIMULATED event for ' || v_attack_names(v_parent),
            v_events(i),
            v_alerts(i)
        );

        INSERT INTO campaign_event (
            campaign_id, event_id
        ) VALUES (
            v_campaigns(v_parent), v_events(i)
        );
    END LOOP;

    FOR i IN 1..60 LOOP
        v_lead := MOD(i - 1, 30) + 1;
        v_receiver := MOD(v_lead, 30) + 1;

        set_actor(v_admin);

        sp_create_incident(
            v_admin,
            v_alerts(i),
            'DEMO Case ' || TO_CHAR(i, 'FM000') ||
                ' ' || v_attack_names(v_lead),
            'Synthetic investigation for the CyberShield demonstration',
            CASE WHEN MOD(i, 2) = 0 THEN 'CRITICAL' ELSE 'HIGH' END,
            v_campaigns(v_lead),
            v_incident
        );

        IF i <= 30 THEN
            sp_link_alert(
                v_admin, v_incident, v_alerts(i + 60)
            );
        END IF;

        sp_assign_investigator(
            v_admin,
            v_incident,
            v_investigators(v_lead),
            'LEAD',
            v_assignment
        );

        sp_assign_investigator(
            v_admin,
            v_incident,
            v_investigators(v_receiver),
            'SUPPORT',
            v_assignment
        );

        set_actor(v_users(v_lead));

        sp_triage_alert(
            v_users(v_lead),
            v_alerts(i),
            'ACKNOWLEDGED',
            'Simulated alert reviewed by assigned lead'
        );

        sp_change_status(
            v_users(v_lead), v_incident,
            'TRIAGED', 'Simulated case triaged'
        );

        sp_change_status(
            v_users(v_lead), v_incident,
            'INVESTIGATING', 'Simulated investigation started'
        );
        SELECT LOWER(
    RAWTOHEX(
        STANDARD_HASH(
            'CyberShield synthetic evidence ' || TO_CHAR(i),
            'SHA256'
        )
    )
)
INTO v_evidence_hash
FROM dual;

        sp_register_evidence(
            v_users(v_lead),
            v_incident,
            'LOG',
            'demo-evidence-' || TO_CHAR(i, 'FM000') || '.log',
            'simulated-case-' || TO_CHAR(i, 'FM000') || '.log',
            SYSTIMESTAMP - INTERVAL '1' MINUTE,
            v_evidence_hash,
            LENGTHB('CyberShield synthetic evidence ' || TO_CHAR(i)),
            CASE WHEN MOD(i, 3) = 0
                 THEN 'RESTRICTED' ELSE 'INTERNAL' END,
            v_evidence
        );

        sp_add_analysis(
            v_users(v_lead),
            v_evidence,
            NULL,
            'Simulated log correlation',
            'Synthetic findings associated with ' ||
                v_attack_names(v_lead),
            'Documentation IP 192.0.2.' || TO_CHAR(v_lead),
            70 + MOD(i, 25),
            v_analysis
        );

        sp_transfer_evidence(
            v_users(v_lead),
            v_evidence,
            v_investigators(v_lead),
            v_investigators(v_receiver),
            'CONTROLLED_HANDOVER',
            'Peer review of synthetic evidence',
            'Demo metadata handed over intact'
        );

        sp_record_action(
            v_users(v_lead),
            v_incident,
            'SIMULATED_CONTAINMENT',
            'Recorded simulated containment; no real infrastructure changed',
            'Simulated containment successful',
            v_action
        );

        sp_change_status(
            v_users(v_lead), v_incident,
            'CONTAINED', 'Simulated containment completed'
        );

        IF i <= 30 THEN
            sp_resolve_incident(
                v_users(v_lead),
                v_incident,
                'Synthetic case resolved after peer review',
                'Simulated weakness: ' || v_attack_names(v_lead),
                'Review monitoring and response controls',
                0,
                v_resolution
            );

            sp_change_status(
                v_users(v_lead), v_incident,
                'CLOSED', 'Simulated closure approved'
            );

            IF i <= 15 THEN
                set_actor(v_admin);

                sp_reopen_incident(
                    v_admin,
                    v_incident,
                    'New simulated indicator requires a second investigation',
                    v_new_cycle
                );

                sp_assign_investigator(
                    v_admin,
                    v_incident,
                    v_investigators(v_lead),
                    'LEAD',
                    v_assignment
                );

                sp_assign_investigator(
                    v_admin,
                    v_incident,
                    v_investigators(v_receiver),
                    'SUPPORT',
                    v_assignment
                );
            END IF;
        END IF;
    END LOOP;

    FOR t IN (
        SELECT table_name
        FROM user_tables
        WHERE table_name NOT IN (
            'SOC_POLICY', 'SCHEMA_MIGRATION'
        )
        ORDER BY table_name
    ) LOOP
        EXECUTE IMMEDIATE
            'SELECT COUNT(*) FROM ' ||
            DBMS_ASSERT.SIMPLE_SQL_NAME(t.table_name)
        INTO v_count;

        IF v_count < 30 THEN
            RAISE_APPLICATION_ERROR(
                -20999,
                t.table_name || ' has fewer than 30 records'
            );
        END IF;

        DBMS_OUTPUT.PUT_LINE(
            RPAD(t.table_name, 34) || TO_CHAR(v_count)
        );
    END LOOP;

    restore_context;

    COMMIT;

    DBMS_OUTPUT.PUT_LINE(
        'SUCCESS: Demo dataset committed; all business tables have at least 30 rows'
    );

EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO seed_start;
        restore_context;
        RAISE;
END;
/

BEGIN
    :demo_hash := NULL;
END;
/