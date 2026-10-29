import pytest
from flask import Flask, jsonify, session
from auth import current_user, current_role, actor_id, login_required, roles_required

@pytest.fixture
def app():
    a = Flask(__name__)
    a.config["SECRET_KEY"] = "test-only-secret"

    @a.get("/login")
    def login():
        return "Login required", 200

    @a.get("/private")
    @login_required
    def private():
        return jsonify({"actor_id": actor_id(), "role": current_role()})

    @a.get("/admin")
    @roles_required("ADMIN")
    def admin():
        return "Admin only", 200

    return a

def test_anonymous_user_redirects(app):
    c = app.test_client()
    r = c.get("/private")
    assert r.status_code == 302
    assert "/login" in r.location

def test_authenticated_user_can_access_private_route(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["user"] = {"user_id": 12, "role_code": "ANALYST"}
    r = c.get("/private")
    assert r.status_code == 200
    assert r.json["actor_id"] == 12
    assert r.json["role"] == "ANALYST"

def test_non_admin_is_forbidden(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["user"] = {"user_id": 12, "role_code": "ANALYST"}
    r = c.get("/admin")
    assert r.status_code == 403

def test_admin_can_access_admin_route(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["user"] = {"user_id": 1, "role_code": "ADMIN"}
    r = c.get("/admin")
    assert r.status_code == 200

def test_unknown_role_is_rejected():
    with pytest.raises(ValueError):
        roles_required("SUPERUSER")