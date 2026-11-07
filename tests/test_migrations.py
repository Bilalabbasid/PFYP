"""The Alembic migrations must build exactly the schema defined in app/models.py."""
import os

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask_migrate import upgrade

from app import create_app
from app.extensions import db
from config import TestConfig

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_migrations_match_models(tmp_path):
    class MigConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + str(tmp_path / "mig.db").replace("\\", "/")
        AUTO_CREATE_TABLES = False

    app = create_app(MigConfig)
    with app.app_context():
        upgrade(directory=os.path.join(ROOT, "migrations"))
        with db.engine.connect() as conn:
            diff = compare_metadata(MigrationContext.configure(conn), db.metadata)
        assert diff == [], f"Models changed without a migration: {diff}"
        tables = set(db.inspect(db.engine).get_table_names())
        assert {"users", "scans", "awareness_articles", "activity_logs", "alembic_version"} <= tables
        db.engine.dispose()
