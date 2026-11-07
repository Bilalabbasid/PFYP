from app.extensions import db
from app.models import Scan

from .conftest import login, make_user


def scan(client, url):
    return client.post("/scan", data={"url": url}, follow_redirects=True)


def test_anonymous_scan_shows_result(app, client):
    resp = scan(client, "http://paypa1.com/signin")
    assert resp.status_code == 200
    html = resp.data.decode()
    assert "Likely Phishing" in html and "Look-alike (typosquatted) domain" in html
    assert 'href="http://paypa1.com' not in html  # scanned URL is never a clickable link
    with app.app_context():
        s = Scan.query.one()
        assert s.user_id is None and s.domain == "paypa1.com" and s.score >= 60


def test_anonymous_result_private_to_session(app, client):
    scan(client, "https://example-website.com/login")
    with app.app_context():
        sid = Scan.query.one().id
    assert client.get(f"/scan/{sid}").status_code == 200
    other = app.test_client()
    assert other.get(f"/scan/{sid}").status_code == 404


def test_invalid_url_shows_error(app, client):
    resp = client.post("/scan", data={"url": "javascript:alert(1)"})
    assert resp.status_code == 400 and b"commonly abused" in resp.data
    resp = client.post("/scan", data={"url": ""})
    assert resp.status_code == 400 and b"Please enter a URL" in resp.data
    with app.app_context():
        assert Scan.query.count() == 0


def test_xss_in_url_is_escaped(app, client):
    resp = scan(client, 'http://evil.com/"><script>alert(1)</script>')
    assert b"<script>alert(1)</script>" not in resp.data
    assert b"&lt;script&gt;" in resp.data or b"%3Cscript%3E" in resp.data


def test_history_for_logged_in_user(app, user_client):
    for u in ["https://www.google.com/", "http://paypa1.com/signin",
              "https://example-website.com/login"]:
        scan(user_client, u)
    html = user_client.get("/history").data.decode()
    assert "www.google.com" in html and "paypa1.com" in html and "example-website.com" in html
    filtered = user_client.get("/history?classification=Likely+Phishing").data.decode()
    assert "paypa1.com" in filtered and "www.google.com/" not in filtered
    searched = user_client.get("/history?q=google").data.decode()
    assert "www.google.com" in searched and "paypa1.com" not in searched


def test_history_export_csv(app, user_client):
    scan(user_client, "http://paypa1.com/signin")
    resp = user_client.get("/history/export.csv")
    assert resp.status_code == 200 and resp.mimetype == "text/csv"
    body = resp.data.decode()
    assert body.splitlines()[0].startswith("id,scanned_at_utc,url")
    assert "paypa1.com" in body and "Likely Phishing" in body


def test_users_cannot_see_each_others_scans(app, user_client):
    scan(user_client, "http://paypa1.com/signin")
    with app.app_context():
        sid = Scan.query.one().id
    make_user(app, "mallory", "Mallory123")
    other = app.test_client()
    login(other, "mallory", "Mallory123")
    assert other.get(f"/scan/{sid}").status_code == 404
    assert b"paypa1.com" not in other.get("/history").data
    assert other.post(f"/history/{sid}/delete").status_code == 404


def test_delete_and_clear_history(app, user_client):
    scan(user_client, "https://www.google.com/")
    scan(user_client, "http://paypa1.com/signin")
    with app.app_context():
        first = Scan.query.order_by(Scan.id).first().id
    user_client.post(f"/history/{first}/delete")
    with app.app_context():
        assert Scan.query.count() == 1
    resp = user_client.post("/history/clear", follow_redirects=True)
    assert b"Cleared 1 scan" in resp.data
    with app.app_context():
        assert Scan.query.count() == 0


def test_history_requires_login(client):
    resp = client.get("/history")
    assert resp.status_code == 302 and "/auth/login" in resp.headers["Location"]


def test_scan_is_logged(app, client):
    from app.models import ActivityLog
    scan(client, "https://www.google.com/")
    with app.app_context():
        assert ActivityLog.query.filter_by(action="scan").count() == 1
        assert db.session.query(Scan).count() == 1
