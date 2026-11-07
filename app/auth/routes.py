from datetime import timedelta
from urllib.parse import urlsplit

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func, or_

from ..extensions import db
from ..forms import ChangePasswordForm, LoginForm, ProfileForm, RegisterForm
from ..models import Scan, User, utcnow
from ..utils import log_activity

bp = Blueprint("auth", __name__)


def _safe_next(target: str | None) -> str:
    """Only allow redirects to paths on this site (prevents open redirects)."""
    if not target:
        return url_for("main.index")
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//"):
        return url_for("main.index")
    return target


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        if User.query.filter(func.lower(User.username) == username.lower()).first():
            form.username.errors.append("That username is already taken.")
        elif User.query.filter_by(email=email).first():
            form.email.errors.append("An account with that email already exists.")
        else:
            user = User(username=username, email=email,
                        full_name=(form.full_name.data or "").strip())
            user.set_password(form.password.data)
            user.last_login = utcnow()
            # Administrators are created with the `flask create-admin` command,
            # never through public registration.
            db.session.add(user)
            db.session.flush()
            log_activity("register", f"New account '{username}'", user_id=user.id,
                         commit=False)
            db.session.commit()
            login_user(user)
            flash("Welcome! Your account has been created.", "success")
            return redirect(url_for("main.index"))
    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    form = LoginForm()
    if form.validate_on_submit():
        ident = form.username.data.strip()
        user = User.query.filter(or_(func.lower(User.username) == ident.lower(),
                                     User.email == ident.lower())).first()
        generic_error = "Invalid username/email or password."
        if user is None:
            log_activity("login_failed", f"Unknown user '{ident[:60]}'")
            flash(generic_error, "danger")
        elif user.is_locked():
            flash("Too many failed attempts. This account is temporarily locked; "
                  "try again later.", "danger")
        elif not user.check_password(form.password.data):
            user.failed_logins += 1
            cfg = current_app.config
            if user.failed_logins >= cfg["MAX_FAILED_LOGINS"]:
                user.locked_until = utcnow() + timedelta(minutes=cfg["LOCKOUT_MINUTES"])
                user.failed_logins = 0
                log_activity("account_locked", f"'{user.username}' locked",
                             user_id=user.id, commit=False)
            log_activity("login_failed", f"Wrong password for '{user.username}'",
                         user_id=user.id, commit=False)
            db.session.commit()
            flash(generic_error, "danger")
        elif not user.is_active:
            flash("This account has been disabled by an administrator.", "danger")
        else:
            user.failed_logins = 0
            user.locked_until = None
            user.last_login = utcnow()
            login_user(user, remember=form.remember.data)
            log_activity("login", f"'{user.username}' logged in", user_id=user.id,
                         commit=False)
            db.session.commit()
            flash(f"Welcome back, {user.full_name or user.username}!", "success")
            return redirect(_safe_next(request.args.get("next")))
    return render_template("auth/login.html", form=form)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log_activity("logout", f"'{current_user.username}' logged out")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("main.index"))


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    profile_form = ProfileForm(prefix="p", obj=current_user)
    password_form = ChangePasswordForm(prefix="pw")

    if profile_form.submit.data and profile_form.validate_on_submit():
        email = profile_form.email.data.strip().lower()
        clash = User.query.filter(User.email == email, User.id != current_user.id).first()
        if clash:
            profile_form.email.errors.append("That email is used by another account.")
        else:
            current_user.email = email
            current_user.full_name = (profile_form.full_name.data or "").strip()
            log_activity("profile_update", "Profile updated", commit=False)
            db.session.commit()
            flash("Profile updated.", "success")
            return redirect(url_for("auth.profile"))

    if password_form.submit.data and password_form.validate_on_submit():
        if not current_user.check_password(password_form.current_password.data):
            password_form.current_password.errors.append("Current password is incorrect.")
        else:
            current_user.set_password(password_form.new_password.data)
            log_activity("password_change", "Password changed", commit=False)
            db.session.commit()
            flash("Password changed successfully.", "success")
            return redirect(url_for("auth.profile"))

    stats = dict(db.session.query(Scan.classification, func.count(Scan.id))
                 .filter(Scan.user_id == current_user.id)
                 .group_by(Scan.classification).all())
    return render_template("auth/profile.html", profile_form=profile_form,
                           password_form=password_form, stats=stats,
                           total=sum(stats.values()))
