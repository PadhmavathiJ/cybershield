from pathlib import Path
import re

p = Path("app.py")
s = p.read_text(encoding="utf-8")

pattern = r'@app\.get\("/servers"\)\s+@login_required\s+def servers\(\):.*?(?=\n@app\.get\("/events"\))'

replacement = '''@app.route("/servers", methods=["GET", "POST"])
@roles_required("ADMIN")
def servers():
    if request.method == "POST":
        hostname = request.form.get("hostname", "").strip()
        os_name = request.form.get("os_name", "").strip()
        department = request.form.get("department", "").strip()
        criticality = request.form.get("criticality", "").strip().upper()

        if not hostname:
            flash("Hostname is required.", "error")
            return redirect(url_for("servers"))

        if criticality not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            flash("Select a valid criticality.", "error")
            return redirect(url_for("servers"))

        con = get_connection()
        cur = None
        try:
            cur = con.cursor()
            cur.execute(
                f"SELECT COUNT(*) FROM {obj('server')} WHERE UPPER(hostname)=UPPER(:hostname)",
                {"hostname": hostname}
            )

            if cur.fetchone()[0]:
                flash("A server with this hostname already exists.", "error")
                return redirect(url_for("servers"))

            cur.execute(
                f"""INSERT INTO {obj('server')}
                (hostname, os_name, department, criticality, is_active)
                VALUES (:hostname, :os_name, :department, :criticality, 1)""",
                {
                    "hostname": hostname,
                    "os_name": os_name or None,
                    "department": department or None,
                    "criticality": criticality
                }
            )
            con.commit()
            flash("Server registered successfully in Oracle.", "success")
        except Exception:
            con.rollback()
            app.logger.exception("Server registration failed")
            flash("Server registration failed. Check the Flask terminal for details.", "error")
        finally:
            if cur is not None:
                cur.close()
            con.close()

        return redirect(url_for("servers"))

    items = safe_read(
        f"SELECT server_id, hostname, os_name, department, criticality, is_active "
        f"FROM {obj('server')} ORDER BY hostname"
    )
    items, pagination = paged(items)
    return render_template(
        "servers.html",
        items=items,
        pagination=pagination,
        filters=filter_context()
    )
'''

updated, count = re.subn(pattern, replacement, s, count=1, flags=re.S)

if count != 1:
    print("ERROR: Could not safely locate the existing servers route. No changes made.")
    raise SystemExit(1)

p.write_text(updated, encoding="utf-8")
print("SUCCESS: /servers now supports GET and POST.")
