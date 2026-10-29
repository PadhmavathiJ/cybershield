from pathlib import Path

servers = '''{% extends "base.html" %}
{% block title %}Asset Inventory · CyberShield SOC{% endblock %}
{% block heading %}Asset Inventory{% endblock %}
{% block content %}
<section class="soc-page">
    <div class="soc-page-head">
        <div>
            <p class="eyebrow">ASSET MANAGEMENT</p>
            <h1>Register a server</h1>
            <p class="muted">Assets are saved in Oracle and used by the detection workflow.</p>
        </div>
    </div>
    {% if me.role_code == "ADMIN" %}
    <form method="post" action="{{ url_for('servers') }}" class="soc-panel">
        <input type="hidden" name="_csrf" value="{{ csrf_token }}">
        <div class="form-grid">
            <label>Hostname
                <input name="hostname" maxlength="200" required placeholder="e.g. WEB-SERVER-01">
            </label>
            <label>Operating system
                <input name="os_name" maxlength="100" placeholder="e.g. Windows Server">
            </label>
            <label>Department
                <input name="department" maxlength="100" placeholder="e.g. IT">
            </label>
            <label>Criticality
                <select name="criticality" required>
                    <option value="LOW">Low</option>
                    <option value="MEDIUM" selected>Medium</option>
                    <option value="HIGH">High</option>
                    <option value="CRITICAL">Critical</option>
                </select>
            </label>
        </div>
        <button class="btn primary" type="submit">Register asset</button>
    </form>
    {% endif %}
    <h2>Registered assets</h2>
    <div class="soc-table-wrap">
        <table class="soc-table">
            <thead><tr><th>Hostname</th><th>Operating system</th><th>Department</th><th>Criticality</th><th>Active</th></tr></thead>
            <tbody>
            {% for item in items %}
                <tr>
                    <td>{{ item.hostname }}</td>
                    <td>{{ item.os_name or "—" }}</td>
                    <td>{{ item.department or "—" }}</td>
                    <td>{{ item.criticality }}</td>
                    <td>{{ "Yes" if item.is_active == 1 else "No" }}</td>
                </tr>
            {% else %}
                <tr><td colspan="5">No assets registered yet.</td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</section>
<style>
.soc-panel{padding:20px;margin:20px 0;border:1px solid var(--border,#ddd);border-radius:12px}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:18px}
.form-grid label{display:flex;flex-direction:column;gap:7px}
.form-grid input,.form-grid select{padding:11px;border:1px solid #aab4c2;border-radius:7px;max-width:100%}
</style>
{% endblock %}
'''

events = '''{% extends "base.html" %}
{% block title %}Security Events · CyberShield SOC{% endblock %}
{% block heading %}Security Events{% endblock %}
{% block content %}
<section class="soc-page">
    <div class="soc-page-head">
        <div>
            <p class="eyebrow">RULE-BASED EVENT SIMULATOR</p>
            <h1>Submit a security event</h1>
            <p class="muted">These events are simulated for demonstration. They are not collected automatically from real computers.</p>
        </div>
    </div>
    {% if me.role_code in ["ADMIN", "MANAGER", "ANALYST"] %}
    <form method="post" action="{{ url_for('events') }}" class="soc-panel">
        <input type="hidden" name="_csrf" value="{{ csrf_token }}">
        <div class="form-grid">
            <label>Target asset
                <select name="server_id" required>
                    <option value="">Select a registered asset</option>
                    {% for asset in assets %}
                    <option value="{{ asset.server_id }}">{{ asset.hostname }} — {{ asset.criticality }}</option>
                    {% endfor %}
                </select>
            </label>
            <label>Source IP address
                <input name="source_ip" maxlength="45" required placeholder="e.g. 192.0.2.25">
            </label>
            <label>Event type
                <select name="attack_type" required>
                    <option value="Failed Login">Failed Login</option>
                    <option value="Malware">Malware</option>
                    <option value="Blocked Connection">Blocked Connection</option>
                    <option value="Suspicious Activity">Suspicious Activity</option>
                </select>
            </label>
            <label>Severity score (1–10)
                <input type="number" name="severity_score" min="1" max="10" value="5" required>
            </label>
            <label>Protocol
                <select name="protocol">
                    <option value="SIMULATED">Simulated</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="HTTP">HTTP</option>
                    <option value="SSH">SSH</option>
                </select>
            </label>
            <label>Packet count
                <input type="number" name="packet_count" min="0" value="1" required>
            </label>
            <label>Bytes observed
                <input type="number" name="bytes_count" min="0" value="0" required>
            </label>
        </div>
        <button class="btn primary" type="submit">Submit event to Oracle</button>
    </form>
    {% endif %}
    <h2>Recorded events</h2>
    <div class="soc-table-wrap">
        <table class="soc-table">
            <thead><tr><th>ID</th><th>Time</th><th>Asset</th><th>Source IP</th><th>Event type</th><th>Score</th><th>Simulated</th></tr></thead>
            <tbody>
            {% for item in items %}
                <tr>
                    <td>{{ item.event_id }}</td>
                    <td>{{ item.event_at }}</td>
                    <td>{{ item.hostname }}</td>
                    <td>{{ item.source_ip or "—" }}</td>
                    <td>{{ item.attack_type }}</td>
                    <td>{{ item.severity_score }}</td>
                    <td>{{ "Yes" if item.is_simulated == 1 else "No" }}</td>
                </tr>
            {% else %}
                <tr><td colspan="7">No events recorded yet.</td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</section>
<style>
.soc-panel{padding:20px;margin:20px 0;border:1px solid var(--border,#ddd);border-radius:12px}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:18px}
.form-grid label{display:flex;flex-direction:column;gap:7px}
.form-grid input,.form-grid select{padding:11px;border:1px solid #aab4c2;border-radius:7px;max-width:100%}
</style>
{% endblock %}
'''

Path("templates/servers.html").write_text(servers, encoding="utf-8")
Path("templates/events.html").write_text(events, encoding="utf-8")
print("SUCCESS: Asset registration form added.")
print("SUCCESS: Security event simulator form added.")
