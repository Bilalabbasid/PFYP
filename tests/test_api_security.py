import pytest

from app import create_app
from app.extensions import db
from config import TestConfig


def test_api_scan(client):
    resp = client.post("/api/v1/scan", json={"url": "http://paypa1.com/signin"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["classification"] == "Likely Phishing" and data["score"] >= 60
    assert any(r["rule_id"] == "typosquatting" for r in data["reasons"])


def test_api_errors(client):
    assert client.post("/api/v1/scan", json={}).status_code == 400
    assert client.post("/api/v1/scan", data="nope").status_code == 400
    resp = client.post("/api/v1/scan", json={"url": "javascript:alert(1)"})
    assert resp.status_code == 422 and "error" in resp.get_json()


def test_api_health(client):
    data = client.get("/api/v1/health").get_json()
    assert data["status"] == "ok"


def test_security_headers(client):
    resp = client.get("/")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]


class CSRFConfig(TestConfig):
    WTF_CSRF_ENABLED = True


@pytest.fixture()
def csrf_app():
    app = create_app(CSRFConfig)
    yield app
    with app.app_context():
        db.drop_all()


def test_csrf_blocks_forged_posts(csrf_app):
    c = csrf_app.test_client()
    # forms posted without the CSRF token are rejected
    assert c.post("/scan", data={"url": "https://google.com"}).status_code == 400
    assert c.post("/auth/login", data={"username": "a", "password": "b"}).status_code == 400
    # real pages always include the token, and the JSON API is exempt
    assert b'name="csrf_token"' in c.get("/auth/login").data
    assert c.post("/api/v1/scan", json={"url": "https://google.com"}).status_code == 200


def test_404_page(client):
    resp = client.get("/does-not-exist")
    assert resp.status_code == 404 and b"does not exist" in resp.data


def test_api_analyze_does_not_save(app, client):
    from app.models import Scan
    resp = client.post("/api/v1/analyze", json={"url": "https://accounts.google.com.security-check-login.info/x"})
    data = resp.get_json()
    assert resp.status_code == 200 and data["classification"] == "Likely Phishing"
    assert data["anatomy"]["registered_domain"] == "security-check-login.info"
    with app.app_context():
        assert Scan.query.count() == 0
