from pathlib import Path

p = Path("templates/base.html")
s = p.read_text(encoding="utf-8")

old = '<div class="top-right"><span class="status-dot"></span><span>Oracle-backed</span><span class="role-pill">{{ me.role_code }}</span></div>'

new = '''<div class="top-right">
<span class="status-dot"></span><span>Oracle-backed</span>
<span class="role-pill">{{ me.role_code }}</span>
<form method="post" action="{{ url_for('logout') }}" style="display:inline-flex;margin-left:12px">
<input type="hidden" name="_csrf" value="{{ csrf_token }}">
<button type="submit" style="background:#b42318;color:white;padding:10px 16px;border:0;border-radius:8px;font-weight:600;cursor:pointer">Sign Out</button>
</form>
</div>'''

if old not in s:
    print("Could not find the expected top navigation. No changes made.")
else:
    p.write_text(s.replace(old, new, 1), encoding="utf-8")
    print("Added a visible Sign Out button to the top navigation.")
