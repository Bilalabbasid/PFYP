"""Command-line helpers:  flask --app run <command>"""
import getpass
import random
from datetime import timedelta

import click

from .extensions import db
from .models import Scan, User, utcnow


def register(app):
    @app.cli.command("init-db")
    def init_db():
        """Create all database tables."""
        db.create_all()
        click.echo("Database tables created.")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--email", prompt=True)
    @click.option("--password", default=None, help="Omit to be prompted securely.")
    def create_admin(username, email, password):
        """Create an administrator account (or promote an existing user)."""
        user = User.query.filter((User.username == username) | (User.email == email.lower())).first()
        if user:
            user.is_admin = True
            db.session.commit()
            click.echo(f"Existing user '{user.username}' is now an administrator.")
            return
        if not password:
            password = getpass.getpass("Password: ")
        if len(password) < 8:
            raise click.ClickException("Password must be at least 8 characters.")
        user = User(username=username, email=email.lower(), is_admin=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Administrator '{username}' created.")

    @app.cli.command("seed-demo")
    @click.option("--scans", default=40, help="Number of sample scans to create.")
    def seed_demo(scans):
        """Create a demo user and sample scans so the dashboard has data."""
        from .detection import analyze
        from .detection.validators import URLValidationError

        # Demo-only accounts for local testing. Never use these on a real server.
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", email="admin@example.com",
                         full_name="Demo Administrator", is_admin=True)
            admin.set_password("Admin1234")
            db.session.add(admin)
            click.echo("Created demo administrator: admin / Admin1234")
        demo = User.query.filter_by(username="demo").first()
        if not demo:
            demo = User(username="demo", email="demo@example.com", full_name="Demo User")
            demo.set_password("Demo1234")
            db.session.add(demo)
            click.echo("Created demo user: demo / Demo1234")
        db.session.commit()
        samples = [
            "https://www.google.com/", "https://github.com/login",
            "https://en.wikipedia.org/wiki/Phishing", "https://www.daraz.pk/",
            "http://paypa1.com/signin", "https://secure-paypal-account-verify.tk/update",
            "http://192.168.10.5/bank/login.php", "https://bit.ly/3abcXYZ",
            "https://example-website.com/login", "http://www.paypal.com@evil.xyz/login",
            "https://appleid.apple.com.verify-account.info/",
            "https://my-site.netlify.app/office365/login.html",
            "https://faceb00k-login.com", "https://www.amazon.com/gp/your-account",
        ]
        rng = random.Random(42)
        for _ in range(scans):
            url = rng.choice(samples)
            try:
                r = analyze(url, use_ml=False)
            except URLValidationError:
                continue
            db.session.add(Scan(
                user_id=demo.id if rng.random() < 0.7 else None, url=r.url,
                normalised_url=r.normalised_url, domain=r.features.host,
                classification=r.classification, score=r.score, rule_score=r.rule_score,
                reasons=[f.to_dict() for f in r.findings], good_signs=r.good_signs,
                notes=r.notes, features=r.features.to_dict(), source="web",
                created_at=utcnow() - timedelta(days=rng.randint(0, 13),
                                                minutes=rng.randint(0, 1400)),
            ))
        db.session.commit()
        click.echo(f"Added {scans} sample scans.")
