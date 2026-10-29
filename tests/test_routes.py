import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("FLASK_SECRET_KEY", "test-only-secret")
from app import app

def test_health_route_exists():
    assert app.url_map
    assert any(rule.rule == "/health" for rule in app.url_map.iter_rules())

def test_required_routes_registered():
    paths = {rule.rule for rule in app.url_map.iter_rules()}
    expected = {"/login", "/logout", "/dashboard", "/servers", "/events", "/alerts",
                "/incidents", "/assignments", "/evidence", "/response", "/sla",
                "/reports", "/audit", "/threat-intel", "/settings", "/health"}
    assert expected.issubset(paths)

def test_login_page_renders_without_database():
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Sign in to CyberShield" in response.data
