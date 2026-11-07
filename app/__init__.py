"""PhishGuard - Phishing Link Detection and Cybersecurity Awareness System."""
from __future__ import annotations

import os

from flask import Flask, render_template

from config import Config

from .extensions import csrf, db, login_manager, migrate


def create_app(config_class=Config) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)
    os.makedirs(app.instance_path, exist_ok=True)

    if app.config.get("BEHIND_PROXY"):
        # Behind nginx / a hosting platform: trust one proxy for the client IP
        # and the original scheme (needed for secure cookies and correct URLs).
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db.init_app(app)
    # render_as_batch lets Alembic ALTER tables on SQLite as well as MySQL
    migrate.init_app(app, db, compare_type=True, render_as_batch=True)
    login_manager.init_app(app)
    csrf.init_app(app)

    from .admin.routes import bp as admin_bp
    from .api.routes import bp as api_bp
    from .auth.routes import bp as auth_bp
    from .awareness.routes import bp as awareness_bp
    from .main.routes import bp as main_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(awareness_bp, url_prefix="/awareness")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    csrf.exempt(api_bp)

    from . import cli
    cli.register(app)

    from .detection import defang
    from .utils import render_article

    app.jinja_env.filters["defang"] = defang
    app.jinja_env.filters["article"] = render_article

    @app.url_defaults
    def static_cache_bust(endpoint, values):
        # append the file's modification time so browsers fetch updated CSS/JS
        if endpoint == "static" and "filename" in values:
            path = os.path.join(app.static_folder, values["filename"])
            if os.path.isfile(path):
                values["v"] = int(os.stat(path).st_mtime)

    @app.template_filter("dt")
    def format_dt(value, fmt="%d %b %Y, %H:%M"):
        return value.strftime(fmt) + " UTC" if value else "-"

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com data:; "
            "img-src 'self' data:; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        return response

    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("errors/error.html", code=403,
                               message="You do not have permission to view this page."), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("errors/error.html", code=404,
                               message="The page you are looking for does not exist."), 404

    @app.errorhandler(500)
    def server_error(_e):
        db.session.rollback()
        return render_template("errors/error.html", code=500,
                               message="Something went wrong on our side."), 500

    _prepare_database(app)
    return app


def _prepare_database(app: Flask) -> None:
    """Create tables (SQLite/dev only) and insert default awareness content.

    For MySQL/production the schema is managed with migrations instead:
        flask --app run db upgrade
    """
    from sqlalchemy.exc import SQLAlchemyError

    from .seed import seed_awareness_content

    with app.app_context():
        try:
            if app.config.get("AUTO_CREATE_TABLES"):
                fresh = "users" not in db.inspect(db.engine).get_table_names()
                if fresh:
                    # Brand-new database: build it in one go and record it as
                    # being at the latest migration, so a later
                    # `flask db upgrade` only applies newer migrations.
                    db.create_all()
                    _stamp_latest_migration(app)
            seed_awareness_content()
        except SQLAlchemyError as exc:
            db.session.rollback()
            app.logger.warning(
                "Database not ready (%s). If you are using MySQL, run "
                "'flask --app run db upgrade' to create the tables.",
                exc.__class__.__name__)


def _stamp_latest_migration(app: Flask) -> None:
    if app.config.get("TESTING"):
        return
    directory = os.path.join(os.path.dirname(app.root_path), "migrations")
    if os.path.isdir(directory):
        from flask_migrate import stamp
        stamp(directory=directory)
