from app.extensions import db
from app.models import ActivityLog, User

from .conftest import login, make_user


def register(client, username="bob", email="bob@example.com", password="Secret123",
             confirm=None):
    return client.post("/auth/register", data={
        "username": username, "email": email, "full_name": "Bob",
        "password": password, "confirm": confirm or password,
    }, follow_redirects=True)


def test_register_and_auto_login(app, client):
    resp = register(client)
    assert resp.status_code == 200 and b"Your account has been created" in resp.data
    with app.app_context():
        user = User.query.filter_by(username="bob").one()
        assert user.password_hash != "Secret123" and user.check_password("Secret123")
        assert not user.is_admin  # public sign-up never creates admins
    assert client.get("/history").status_code == 200


def test_register_validation(app, client):
    assert b"at least 8 characters" in register(client, password="abc1").data
    assert b"letters and numbers" in register(client, password="abcdefgh").data
    assert b"Passwords do not match" in register(client, confirm="Other1234").data
    assert b"valid email" in register(client, email="nope").data.lower() or \
        b"invalid email" in register(client, email="nope").data.lower()
    register(client)
    client.post("/auth/logout")
    assert b"already taken" in register(client, username="BOB", email="x@example.com").data
    assert b"already exists" in register(client, username="bob2").data


def test_login_logout(app, client):
    make_user(app)
    resp = login(client, "alice", "wrong")
    assert b"Invalid username/email or password" in resp.data
    resp = login(client, "alice@example.com", "Passw0rd!")
    assert b"Welcome back" in resp.data
    assert client.post("/auth/logout", follow_redirects=True).status_code == 200
    assert client.get("/history").status_code == 302


def test_logout_requires_post(app, user_client):
    assert user_client.get("/auth/logout").status_code == 405


def test_account_lockout_after_failed_attempts(app, client):
    make_user(app)
    for _ in range(app.config["MAX_FAILED_LOGINS"]):
        login(client, "alice", "bad-password")
    resp = login(client, "alice", "Passw0rd!")  # correct password, but locked
    assert b"temporarily locked" in resp.data
    with app.app_context():
        assert User.query.filter_by(username="alice").one().is_locked()
        assert ActivityLog.query.filter_by(action="account_locked").count() == 1


def test_disabled_user_cannot_login(app, client):
    uid = make_user(app)
    with app.app_context():
        db.session.get(User, uid).active = False
        db.session.commit()
    assert b"disabled" in login(client).data


def test_open_redirect_blocked(app, client):
    make_user(app)
    resp = client.post("/auth/login?next=https://evil.com/",
                       data={"username": "alice", "password": "Passw0rd!"})
    assert resp.status_code == 302 and "evil.com" not in resp.headers["Location"]
    client.post("/auth/logout")
    resp = client.post("/auth/login?next=/history",
                       data={"username": "alice", "password": "Passw0rd!"})
    assert resp.headers["Location"].endswith("/history")


def test_profile_update_and_password_change(app, user_client):
    resp = user_client.post("/auth/profile", data={
        "p-full_name": "Alice Smith", "p-email": "alice.new@example.com", "p-submit": "1",
    }, follow_redirects=True)
    assert b"Profile updated" in resp.data
    resp = user_client.post("/auth/profile", data={
        "pw-current_password": "wrong", "pw-new_password": "NewPass123",
        "pw-confirm": "NewPass123", "pw-submit": "1"}, follow_redirects=True)
    assert b"Current password is incorrect" in resp.data
    resp = user_client.post("/auth/profile", data={
        "pw-current_password": "Passw0rd!", "pw-new_password": "NewPass123",
        "pw-confirm": "NewPass123", "pw-submit": "1"}, follow_redirects=True)
    assert b"Password changed" in resp.data
    with app.app_context():
        u = User.query.filter_by(username="alice").one()
        assert u.full_name == "Alice Smith" and u.email == "alice.new@example.com"
        assert u.check_password("NewPass123")
