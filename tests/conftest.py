import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import User  # noqa: E402
from config import TestConfig  # noqa: E402


@pytest.fixture()
def app():
    app = create_app(TestConfig)
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def make_user(app, username="alice", password="Passw0rd!", email=None, admin=False):
    with app.app_context():
        user = User(username=username, email=email or f"{username}@example.com",
                    is_admin=admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user.id


def login(client, username="alice", password="Passw0rd!"):
    return client.post("/auth/login", data={"username": username, "password": password},
                       follow_redirects=True)


@pytest.fixture()
def user_client(app, client):
    make_user(app)
    login(client)
    return client


@pytest.fixture()
def admin_client(app):
    make_user(app, "admin", "Admin1234", admin=True)
    c = app.test_client()
    login(c, "admin", "Admin1234")
    return c
