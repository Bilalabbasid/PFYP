from datetime import timedelta

from flask import (Blueprint, abort, current_app, flash, redirect, render_template,
                   request, url_for)
from flask_login import current_user
from sqlalchemy import func

from ..detection import PHISHING, SAFE, SUSPICIOUS, ml
from ..detection.rules import PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD
from ..extensions import db
from ..forms import ArticleForm
from ..models import ActivityLog, AwarenessArticle, Scan, User, utcnow
from ..utils import admin_required, log_activity

bp = Blueprint("admin", __name__)

CLASSIFICATIONS = [SAFE, SUSPICIOUS, PHISHING]


@bp.route("/")
@admin_required
def dashboard():
    total_scans = db.session.query(func.count(Scan.id)).scalar() or 0
    counts = dict(db.session.query(Scan.classification, func.count(Scan.id))
                  .group_by(Scan.classification).all())
    total_users = db.session.query(func.count(User.id)).scalar() or 0
    since = utcnow() - timedelta(days=1)
    scans_24h = Scan.query.filter(Scan.created_at >= since).count()
    new_users_7d = User.query.filter(User.created_at >= utcnow() - timedelta(days=7)).count()

    # scans per day for the last 14 days (computed in Python: DB-agnostic)
    start = (utcnow() - timedelta(days=13)).replace(hour=0, minute=0, second=0, microsecond=0)
    days = [(start + timedelta(days=i)).date() for i in range(14)]
    per_day = {d: {c: 0 for c in CLASSIFICATIONS} for d in days}
    for created, cls in (db.session.query(Scan.created_at, Scan.classification)
                         .filter(Scan.created_at >= start).all()):
        if created.date() in per_day and cls in CLASSIFICATIONS:
            per_day[created.date()][cls] += 1
    chart = {
        "labels": [d.strftime("%d %b") for d in days],
        "safe": [per_day[d][SAFE] for d in days],
        "suspicious": [per_day[d][SUSPICIOUS] for d in days],
        "phishing": [per_day[d][PHISHING] for d in days],
    }

    top_domains = (db.session.query(Scan.domain, func.count(Scan.id).label("n"),
                                    func.max(Scan.score))
                   .filter(Scan.classification != SAFE)
                   .group_by(Scan.domain).order_by(func.count(Scan.id).desc())
                   .limit(8).all())
    recent = Scan.query.order_by(Scan.created_at.desc(), Scan.id.desc()).limit(8).all()
    activity = (ActivityLog.query.order_by(ActivityLog.created_at.desc(),
                                           ActivityLog.id.desc()).limit(8).all())
    cfg = current_app.config
    model = ml.model_info(cfg["ML_MODEL_PATH"]) if cfg.get("ML_ENABLED") else None
    return render_template(
        "admin/dashboard.html", total_scans=total_scans, counts=counts,
        total_users=total_users, scans_24h=scans_24h, new_users_7d=new_users_7d,
        chart=chart, top_domains=top_domains, recent=recent, activity=activity,
        model=model, ml_enabled=cfg.get("ML_ENABLED"),
        suspicious_threshold=SUSPICIOUS_THRESHOLD, phishing_threshold=PHISHING_THRESHOLD,
        articles=AwarenessArticle.query.count(),
    )


# ---------------------------------------------------------------- users ----

@bp.route("/users")
@admin_required
def users():
    search = request.args.get("q", "").strip()
    q = User.query
    if search:
        like = f"%{search}%"
        q = q.filter((User.username.ilike(like)) | (User.email.ilike(like)))
    page = request.args.get("page", 1, type=int)
    pagination = q.order_by(User.created_at.desc()).paginate(
        page=page, per_page=current_app.config["ADMIN_PER_PAGE"], error_out=False)
    scan_counts = dict(db.session.query(Scan.user_id, func.count(Scan.id))
                       .group_by(Scan.user_id).all())
    return render_template("admin/users.html", pagination=pagination,
                           users=pagination.items, scan_counts=scan_counts, search=search)


def _target_user(user_id: int) -> User:
    user = db.session.get(User, user_id) or abort(404)
    if user.id == current_user.id:
        flash("You cannot change your own account from the admin panel.", "warning")
        abort(redirect(url_for("admin.users")))
    return user


@bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_active(user_id):
    user = _target_user(user_id)
    user.active = not user.active
    log_activity("admin_user", f"{'Enabled' if user.active else 'Disabled'} '{user.username}'",
                 commit=False)
    db.session.commit()
    flash(f"User '{user.username}' {'enabled' if user.active else 'disabled'}.", "success")
    return redirect(request.referrer or url_for("admin.users"))


@bp.route("/users/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    user = _target_user(user_id)
    user.is_admin = not user.is_admin
    log_activity("admin_user", f"{'Granted' if user.is_admin else 'Revoked'} admin for "
                               f"'{user.username}'", commit=False)
    db.session.commit()
    flash(f"Admin rights {'granted to' if user.is_admin else 'removed from'} "
          f"'{user.username}'.", "success")
    return redirect(request.referrer or url_for("admin.users"))


@bp.route("/users/<int:user_id>/unlock", methods=["POST"])
@admin_required
def unlock_user(user_id):
    user = _target_user(user_id)
    user.locked_until = None
    user.failed_logins = 0
    log_activity("admin_user", f"Unlocked '{user.username}'", commit=False)
    db.session.commit()
    flash(f"User '{user.username}' unlocked.", "success")
    return redirect(request.referrer or url_for("admin.users"))


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = _target_user(user_id)
    name = user.username
    ActivityLog.query.filter_by(user_id=user.id).update({"user_id": None})
    db.session.delete(user)
    log_activity("admin_user", f"Deleted user '{name}'", commit=False)
    db.session.commit()
    flash(f"User '{name}' and their scan history were deleted.", "success")
    return redirect(url_for("admin.users"))


# ---------------------------------------------------------------- scans ----

@bp.route("/scans")
@admin_required
def scans():
    cls = request.args.get("classification", "")
    search = request.args.get("q", "").strip()
    q = Scan.query
    if cls in CLASSIFICATIONS:
        q = q.filter(Scan.classification == cls)
    if search:
        q = q.filter(Scan.url.ilike(f"%{search}%"))
    page = request.args.get("page", 1, type=int)
    pagination = q.order_by(Scan.created_at.desc(), Scan.id.desc()).paginate(
        page=page, per_page=current_app.config["ADMIN_PER_PAGE"], error_out=False)
    return render_template("admin/scans.html", pagination=pagination,
                           scans=pagination.items, classifications=CLASSIFICATIONS,
                           selected=cls, search=search)


@bp.route("/scans/<int:scan_id>/delete", methods=["POST"])
@admin_required
def delete_scan(scan_id):
    scan = db.session.get(Scan, scan_id) or abort(404)
    db.session.delete(scan)
    log_activity("admin_scan", f"Deleted scan #{scan_id}", commit=False)
    db.session.commit()
    flash(f"Scan #{scan_id} deleted.", "success")
    return redirect(request.referrer or url_for("admin.scans"))


# ------------------------------------------------------------- articles ----

@bp.route("/articles")
@admin_required
def articles():
    items = AwarenessArticle.query.order_by(AwarenessArticle.position,
                                            AwarenessArticle.id).all()
    return render_template("admin/articles.html", articles=items)


def _unique_slug(title: str, exclude_id: int | None = None) -> str:
    base = AwarenessArticle.slugify(title)
    slug, n = base, 2
    while True:
        q = AwarenessArticle.query.filter_by(slug=slug)
        if exclude_id:
            q = q.filter(AwarenessArticle.id != exclude_id)
        if not q.first():
            return slug
        slug = f"{base}-{n}"
        n += 1


@bp.route("/articles/new", methods=["GET", "POST"])
@admin_required
def new_article():
    form = ArticleForm()
    if form.validate_on_submit():
        item = AwarenessArticle(slug=_unique_slug(form.title.data))
        form.populate_obj(item)
        item.position = form.position.data or 0
        db.session.add(item)
        log_activity("admin_article", f"Created article '{item.title}'", commit=False)
        db.session.commit()
        flash("Article created.", "success")
        return redirect(url_for("admin.articles"))
    return render_template("admin/article_form.html", form=form, article=None)


@bp.route("/articles/<int:article_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_article(article_id):
    item = db.session.get(AwarenessArticle, article_id) or abort(404)
    form = ArticleForm(obj=item)
    if form.validate_on_submit():
        title_changed = form.title.data != item.title
        form.populate_obj(item)
        item.position = form.position.data or 0
        if title_changed:
            item.slug = _unique_slug(item.title, exclude_id=item.id)
        log_activity("admin_article", f"Edited article '{item.title}'", commit=False)
        db.session.commit()
        flash("Article updated.", "success")
        return redirect(url_for("admin.articles"))
    return render_template("admin/article_form.html", form=form, article=item)


@bp.route("/articles/<int:article_id>/delete", methods=["POST"])
@admin_required
def delete_article(article_id):
    item = db.session.get(AwarenessArticle, article_id) or abort(404)
    title = item.title
    db.session.delete(item)
    log_activity("admin_article", f"Deleted article '{title}'", commit=False)
    db.session.commit()
    flash("Article deleted.", "success")
    return redirect(url_for("admin.articles"))


# ------------------------------------------------------------- activity ----

@bp.route("/activity")
@admin_required
def activity():
    action = request.args.get("action", "")
    q = ActivityLog.query
    if action:
        q = q.filter(ActivityLog.action == action)
    page = request.args.get("page", 1, type=int)
    pagination = q.order_by(ActivityLog.created_at.desc(), ActivityLog.id.desc()).paginate(
        page=page, per_page=current_app.config["ADMIN_PER_PAGE"] * 2, error_out=False)
    actions = [a for (a,) in db.session.query(ActivityLog.action).distinct()
               .order_by(ActivityLog.action).all()]
    return render_template("admin/activity.html", pagination=pagination,
                           logs=pagination.items, actions=actions, selected=action)
