from functools import wraps
from flask import abort, redirect, request, session, url_for

ROLES = {"ADMIN", "MANAGER", "ANALYST", "AUDITOR"}

def current_user():
    for k in ("me", "user"):
        u = session.get(k)
        if isinstance(u, dict):
            return u
    if session.get("user_id") is not None:
        return {
            "user_id": session.get("user_id"),
            "role_code": session.get("role_code", session.get("role", ""))
        }
    return None

def actor_id():
    u = current_user()
    if not u:
        return None
    return u.get("user_id", u.get("id"))

def current_role():
    u = current_user()
    if not u:
        return None
    r = u.get("role_code", u.get("role", ""))
    return str(r).strip().upper()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def roles_required(*roles):
    allowed = {str(r).strip().upper() for r in roles}
    invalid = allowed - ROLES
    if invalid:
        raise ValueError("Unknown role configured")
    def decorate(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user():
                return redirect(url_for("login", next=request.path))
            if current_role() not in allowed:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorate