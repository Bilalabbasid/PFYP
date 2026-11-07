"""Application configuration.

Values are read from environment variables (or a local ``.env`` file loaded by
``run.py``) so the same code runs on a laptop with SQLite and on a server with
MySQL.

    DATABASE_URL=mysql+pymysql://user:password@localhost:3306/phishguard
"""
import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _secret_key() -> str:
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    # Persist a generated key so sessions survive restarts in development.
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    path = os.path.join(INSTANCE_DIR, "secret_key")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(key)
    return key


class Config:
    SECRET_KEY = _secret_key()
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(INSTANCE_DIR, "phishguard.db"),
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 280}
    # SQLite (development) creates tables automatically. MySQL uses migrations
    # (`flask --app run db upgrade`) unless AUTO_CREATE_TABLES=1 is set.
    AUTO_CREATE_TABLES = _bool("AUTO_CREATE_TABLES",
                               SQLALCHEMY_DATABASE_URI.startswith("sqlite"))

    # Session / cookie hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_TIME_LIMIT = None

    # Set to 1 when running behind nginx, Docker ingress or a hosting platform
    BEHIND_PROXY = _bool("BEHIND_PROXY", False)

    # Detection
    ML_ENABLED = _bool("ML_ENABLED", True)
    ML_MODEL_PATH = os.environ.get(
        "ML_MODEL_PATH", os.path.join(BASE_DIR, "ml", "model.joblib")
    )

    # Login protection
    MAX_FAILED_LOGINS = int(os.environ.get("MAX_FAILED_LOGINS", 5))
    LOCKOUT_MINUTES = int(os.environ.get("LOCKOUT_MINUTES", 10))

    HISTORY_PER_PAGE = 15
    ADMIN_PER_PAGE = 20


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    AUTO_CREATE_TABLES = True
    WTF_CSRF_ENABLED = False
    ML_ENABLED = False
    SECRET_KEY = "test-secret"
