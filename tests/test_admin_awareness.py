from app.extensions import db
from app.models import AwarenessArticle, Scan, User

from .conftest import make_user


def test_admin_pages_require_admin(app, client, user_client):
    anon = app.test_client()
    assert anon.get("/admin/").status_code == 302
    for path in ["/admin/", "/admin/users", "/admin/scans", "/admin/articles",
                 "/admin/articles/new", "/admin/activity"]:
        assert user_client.get(path).status_code == 403, path


def test_admin_dashboard_and_lists(app, admin_client):
    admin_client.post("/scan", data={"url": "http://paypa1.com/signin"})
    admin_client.post("/scan", data={"url": "https://www.google.com/"})
    for path in ["/admin/", "/admin/users", "/admin/scans", "/admin/articles",
                 "/admin/activity", "/admin/scans?classification=Likely+Phishing"]:
        resp = admin_client.get(path)
        assert resp.status_code == 200, path
    dash = admin_client.get("/admin/").data.decode()
    assert "paypa1.com" in dash and "Most-flagged domains" in dash
    assert 'data-stat="total-scans">2<' in dash


def test_admin_manage_users(app, admin_client):
    uid = make_user(app, "victim", "Victim123")
    admin_client.post(f"/admin/users/{uid}/toggle-active")
    with app.app_context():
        assert db.session.get(User, uid).active is False
    admin_client.post(f"/admin/users/{uid}/toggle-admin")
    with app.app_context():
        assert db.session.get(User, uid).is_admin is True
    admin_client.post(f"/admin/users/{uid}/delete")
    with app.app_context():
        assert db.session.get(User, uid) is None


def test_admin_cannot_modify_self(app, admin_client):
    with app.app_context():
        me = User.query.filter_by(username="admin").one().id
    admin_client.post(f"/admin/users/{me}/toggle-admin")
    admin_client.post(f"/admin/users/{me}/delete")
    with app.app_context():
        assert db.session.get(User, me).is_admin is True


def test_admin_delete_scan(app, admin_client):
    admin_client.post("/scan", data={"url": "http://paypa1.com/signin"})
    with app.app_context():
        sid = Scan.query.one().id
    admin_client.post(f"/admin/scans/{sid}/delete")
    with app.app_context():
        assert Scan.query.count() == 0


def test_awareness_content_seeded_and_viewable(app, client):
    resp = client.get("/awareness/")
    html = resp.data.decode()
    for title in ["What is Phishing?", "Common Phishing Techniques",
                  "How to Identify Suspicious URLs", "Safe Browsing Practices",
                  "Password Security", "Multi-Factor Authentication",
                  "How to Report Suspicious Links"]:
        assert title in html
    page = client.get("/awareness/what-is-phishing")
    assert page.status_code == 200 and b"<strong>social engineering</strong>" in page.data
    assert client.get("/awareness/quiz").status_code == 200
    with app.app_context():
        assert AwarenessArticle.query.filter_by(slug="what-is-phishing").one().views == 1


def test_admin_article_crud_and_escaping(app, admin_client, client):
    resp = admin_client.post("/admin/articles/new", data={
        "title": "QR Code Phishing", "category": "Techniques", "icon": "phone",
        "summary": "Scan with care", "position": 9, "published": "y",
        "content": "Intro **bold**\n\n- item one\n- item two\n\n<script>alert(1)</script>",
    }, follow_redirects=True)
    assert b"Article created" in resp.data
    page = client.get("/awareness/qr-code-phishing").data
    assert b"<strong>bold</strong>" in page and b"<li>item one</li>" in page
    assert b"<script>alert(1)</script>" not in page and b"&lt;script&gt;" in page

    with app.app_context():
        aid = AwarenessArticle.query.filter_by(slug="qr-code-phishing").one().id
    admin_client.post(f"/admin/articles/{aid}/edit", data={
        "title": "QR Code Phishing (Quishing)", "category": "Techniques", "icon": "phone",
        "summary": "Updated", "content": "New text", "position": 9,
    })
    with app.app_context():
        a = db.session.get(AwarenessArticle, aid)
        assert a.summary == "Updated" and a.published is False
        assert a.slug == "qr-code-phishing-quishing"
    # unpublished article is hidden from the public
    assert client.get("/awareness/qr-code-phishing-quishing").status_code == 404
    admin_client.post(f"/admin/articles/{aid}/delete")
    with app.app_context():
        assert db.session.get(AwarenessArticle, aid) is None


def test_article_formatter_heading_followed_by_list():
    from app.utils import render_article
    html = str(render_article("Intro line\n## How to stay safe\n- one\n- **two**\n1. first\n2) second\nend"))
    assert html == ("<p>Intro line</p>\n<h3>How to stay safe</h3>\n"
                    "<ul><li>one</li><li><strong>two</strong></li></ul>\n"
                    "<ol><li>first</li><li>second</li></ol>\n<p>end</p>")
