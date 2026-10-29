from pathlib import Path
import re

app_path = Path("app.py")
app_text = app_path.read_text(encoding="utf-8")

pattern = r'@app\.get\("/"\)\s+def home\(\):.*?(?=\n@app\.route\("/login")'
replacement = '''@app.get("/")
def home():
    return redirect(url_for("login"))
'''

updated, count = re.subn(pattern, replacement, app_text, count=1, flags=re.S)

if count != 1:
    print("ERROR: Could not safely update the homepage route. app.py was not changed.")
    raise SystemExit(1)

if "generate_password_hash" in updated:
    app_text = updated
else:
    app_text = updated

app_path.write_text(app_text, encoding="utf-8")

base_path = Path("templates/base.html")
html = base_path.read_text(encoding="utf-8")

marker = "CYBERSHIELD-FIXED-SIGNOUT"

if marker not in html:
    signout = '''
{% if me.user_id %}
<div id="CYBERSHIELD-FIXED-SIGNOUT" style="position:fixed;right:24px;bottom:24px;z-index:99999">
<form method="post" action="{{ url_for('logout') }}" style="margin:0">
<input type="hidden" name="_csrf" value="{{ csrf_token }}">
<button type="submit" style="background:#b42318;color:white;padding:14px 22px;border:2px solid white;border-radius:10px;font-size:16px;font-weight:700;box-shadow:0 4px 18px #0005;cursor:pointer">Sign Out</button>
</form>
</div>
{% endif %}
'''
    if "</body>" not in html:
        print("ERROR: Could not find the end of base.html.")
        raise SystemExit(1)
    html = html.replace("</body>", signout + "\n</body>", 1)
    base_path.write_text(html, encoding="utf-8")

print("SUCCESS: Homepage now redirects to login.")
print("SUCCESS: A fixed Sign Out button is enabled for logged-in users.")
