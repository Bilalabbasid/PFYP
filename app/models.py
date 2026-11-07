from __future__ import annotations

import re
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .detection.rules import ADVICE, CSS_CLASS
from .extensions import db, login_manager


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(100), default="")
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    failed_logins = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    scans = db.relationship("Scan", backref="user", lazy="dynamic",
                            cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self) -> bool:  # used by Flask-Login
        return bool(self.active)

    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > utcnow()

    def __repr__(self) -> str:
        return f"<User {self.username}>"


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    url = db.Column(db.Text, nullable=False)
    normalised_url = db.Column(db.Text, nullable=False)
    domain = db.Column(db.String(255), nullable=False, index=True)
    classification = db.Column(db.String(20), nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False)
    rule_score = db.Column(db.Integer, nullable=False)
    ml_probability = db.Column(db.Float, nullable=True)
    reasons = db.Column(db.JSON, nullable=False, default=list)
    good_signs = db.Column(db.JSON, nullable=False, default=list)
    notes = db.Column(db.JSON, nullable=False, default=list)
    features = db.Column(db.JSON, nullable=False, default=dict)
    source = db.Column(db.String(10), default="web", nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    @property
    def css_class(self) -> str:
        return CSS_CLASS.get(self.classification, "secondary")

    @property
    def risk_reasons(self) -> list[dict]:
        return [r for r in (self.reasons or []) if r.get("weight", 0) > 0]

    @property
    def advice(self) -> str:
        return ADVICE.get(self.classification, "")


class AwarenessArticle(db.Model):
    __tablename__ = "awareness_articles"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    slug = db.Column(db.String(160), unique=True, nullable=False, index=True)
    category = db.Column(db.String(50), nullable=False, default="General")
    icon = db.Column(db.String(40), nullable=False, default="shield-check")
    summary = db.Column(db.String(300), nullable=False, default="")
    content = db.Column(db.Text, nullable=False, default="")
    published = db.Column(db.Boolean, default=True, nullable=False)
    position = db.Column(db.Integer, default=0, nullable=False)
    views = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    @staticmethod
    def slugify(text: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
        return slug[:150] or "article"


class ActivityLog(db.Model):
    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
                        nullable=True, index=True)
    action = db.Column(db.String(50), nullable=False, index=True)
    detail = db.Column(db.String(500), default="")
    ip_address = db.Column(db.String(45), default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    user = db.relationship("User", foreign_keys=[user_id])
