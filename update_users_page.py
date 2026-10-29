from pathlib import Path

p = Path("app.py")
s = p.read_text(encoding="utf-8")

s = s.replace(
    "from werkzeug.security import check_password_hash",
    "from werkzeug.security import check_password_hash, generate_password_hash"
)

start = s.index('@app.get("/admin/users")')
end = s.index('@app.get("/tables")', start)

new_route = '''@app.route("/admin/users", methods=["GET", "POST"])
@roles_required("ADMIN")
def admin_users():
    if request.method == "POST":
        action = request.form.get("action", "").strip().lower()

        if action == "create":
            name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            role_code = request.form.get("role_code", "").strip().upper()

            if not name or not email or not password:
                flash("Name, email and password are required.", "error")
            elif len(name) > 200 or len(email) > 320:
                flash("Name or email is too long.", "error")
            elif len(password) < 8:
                flash("Password must contain at least 8 characters.", "error")
            elif role_code not in ROLES:
                flash("Select a valid role.", "error")
            else:
                con = get_connection()
                cur = None
                try:
                    cur = con.cursor()
                    cur.execute(
                        f"SELECT COUNT(*) FROM {obj('app_user')} WHERE LOWER(email)=:email",
                        {"email": email.lower()}
                    )
                    if cur.fetchone()[0]:
                        flash("An account with that email already exists.", "error")
                    else:
                        cur.execute(
                            f"""INSERT INTO {obj('app_user')}
                            (email, password_hash, full_name, role_code, is_active)
                            VALUES (:email, :password_hash, :full_name, :role_code, 1)""",
                            {
                                "email": email,
                                "password_hash": generate_password_hash(password),
                                "full_name": name,
                                "role_code": role_code
                            }
                        )
                        con.commit()
                        flash("User account created successfully.", "success")
                except Exception:
                    con.rollback()
                    app.logger.exception("Could not create user account")
                    flash("Could not create account. Check the application log.", "error")
                finally:
                    if cur is not None:
                        cur.close()
                    con.close()

        elif action == "update":
            user_id = request.form.get("user_id", "").strip()
            role_code = request.form.get("role_code", "").strip().upper()
            is_active = request.form.get("is_active", "").strip()

            if not user_id.isdigit() or role_code not in ROLES or is_active not in {"0", "1"}:
                flash("Invalid user update details.", "error")
            elif int(user_id) == int(actor_id()) and (role_code != "ADMIN" or is_active != "1"):
                flash("You cannot remove your own administrator access or deactivate yourself.", "error")
            else:
                con = get_connection()
                cur = None
                try:
                    cur = con.cursor()
                    cur.execute(
                        f"""UPDATE {obj('app_user')}
                        SET role_code=:role_code, is_active=:is_active
                        WHERE user_id=:user_id""",
                        {
                            "role_code": role_code,
                            "is_active": int(is_active),
                            "user_id": int(user_id)
                        }
                    )
                    if cur.rowcount:
                        con.commit()
                        flash("User account updated.", "success")
                    else:
                        con.rollback()
                        flash("User account was not found.", "error")
                except Exception:
                    con.rollback()
                    app.logger.exception("Could not update user account")
                    flash("Could not update account. Check the application log.", "error")
                finally:
                    if cur is not None:
                        cur.close()
                    con.close()
        else:
            flash("Invalid user-management action.", "error")

        return redirect(url_for("admin_users"))

    users = safe_read(
        f"""SELECT user_id, full_name, email, role_code, is_active, created_at
        FROM {obj('app_user')} ORDER BY full_name"""
    )
    return render_template("users.html", users=users)


'''

s = s[:start] + new_route + s[end:]
p.write_text(s, encoding="utf-8")

template = '''{% extends "base.html" %}
{% block title %}User Access · CyberShield SOC{% endblock %}
{% block heading %}User access management{% endblock %}
{% block content %}
<div class="panel">
    <h2>Create account</h2>
    <p>Create an account for a member of the Security Operations Center.</p>
    <form method="post" action="{{ url_for('admin_users') }}">
        <input type="hidden" name="_csrf" value="{{ csrf_token }}">
        <input type="hidden" name="action" value="create">
        <div class="form-grid">
            <label>Full name
                <input type="text" name="full_name" maxlength="200" required>
            </label>
            <label>Email address
                <input type="email" name="email" maxlength="320" required>
            </label>
            <label>Temporary password
                <input type="password" name="password" minlength="8" autocomplete="new-password" required>
            </label>
            <label>Role
                <select name="role_code" required>
                    <option value="ANALYST">Analyst</option>
                    <option value="MANAGER">Manager</option>
                    <option value="AUDITOR">Auditor</option>
                    <option value="ADMIN">Admin</option>
                </select>
            </label>
        </div>
        <button type="submit">Create account</button>
    </form>
</div>

<div class="panel">
    <h2>Existing accounts</h2>
    <p>{{ users|length }} account(s) in the Oracle database.</p>
    <div class="table-wrap">
        <table>
            <thead>
                <tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Created</th><th>Save changes</th></tr>
            </thead>
            <tbody>
            {% for u in users %}
                <tr>
                    <td>{{ u.full_name }}</td>
                    <td>{{ u.email }}</td>
                    <td colspan="4">
                        <form method="post" action="{{ url_for('admin_users') }}" class="user-update-form">
                            <input type="hidden" name="_csrf" value="{{ csrf_token }}">
                            <input type="hidden" name="action" value="update">
                            <input type="hidden" name="user_id" value="{{ u.user_id }}">
                            <label>Role
                                <select name="role_code" required>
                                    {% for r in ['ADMIN', 'MANAGER', 'ANALYST', 'AUDITOR'] %}
                                    <option value="{{ r }}" {% if u.role_code == r %}selected{% endif %}>{{ r }}</option>
                                    {% endfor %}
                                </select>
                            </label>
                            <label>Status
                                <select name="is_active" required>
                                    <option value="1" {% if u.is_active == 1 %}selected{% endif %}>Active</option>
                                    <option value="0" {% if u.is_active == 0 %}selected{% endif %}>Inactive</option>
                                </select>
                            </label>
                            <span>{{ u.created_at }}</span>
                            <button type="submit">Save</button>
                        </form>
                    </td>
                </tr>
            {% else %}
                <tr><td colspan="6">No user accounts found.</td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<style>
.panel { background: var(--panel, #fff); border: 1px solid var(--border, #ddd); border-radius: 12px; padding: 20px; margin-bottom: 20px; }
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 16px; margin: 18px 0; }
.form-grid label, .user-update-form label { display: flex; flex-direction: column; gap: 6px; }
input, select { padding: 10px; border: 1px solid #b9c3d0; border-radius: 7px; max-width: 100%; }
button { padding: 10px 16px; border: 0; border-radius: 7px; cursor: pointer; }
.table-wrap { overflow-x: auto; }
.user-update-form { display: flex; align-items: end; gap: 10px; flex-wrap: wrap; }
.user-update-form select { min-width: 110px; }
</style>
{% endblock %}
'''

Path("templates/users.html").write_text(template, encoding="utf-8")
print("Updated app.py and templates/users.html")
