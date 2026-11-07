import csv
import io

from flask import (Blueprint, Response, abort, current_app, flash, redirect,
                   render_template, request, session, url_for)
from flask_login import current_user, login_required
from sqlalchemy import func

from ..detection import PHISHING, SAFE, SUSPICIOUS, URLValidationError
from ..extensions import db
from ..forms import ScanForm
from ..models import AwarenessArticle, Scan
from ..services import run_scan
from ..utils import log_activity

bp = Blueprint("main", __name__)

CLASSIFICATIONS = [SAFE, SUSPICIOUS, PHISHING]
ANON_SCANS_KEY = "anon_scans"


def _render_index(form, status=200):
    total = db.session.query(func.count(Scan.id)).scalar() or 0
    phishing = db.session.query(func.count(Scan.id)).filter(
        Scan.classification == PHISHING).scalar() or 0
    articles = (AwarenessArticle.query.filter_by(published=True)
                .order_by(AwarenessArticle.position, AwarenessArticle.id).limit(3).all())
    recent = []
    if current_user.is_authenticated:
        recent = (Scan.query.filter_by(user_id=current_user.id)
                  .order_by(Scan.created_at.desc(), Scan.id.desc()).limit(5).all())
    from ..detection.rules import RULES
    return render_template("main/index.html", form=form, total_scans=total,
                           phishing_scans=phishing, articles=articles, recent=recent,
                           check_count=len(RULES)), status


@bp.route("/", methods=["GET"])
def index():
    return _render_index(ScanForm())


@bp.route("/scan", methods=["POST"])
def scan():
    form = ScanForm()
    if not form.validate_on_submit():
        for errors in form.errors.values():
            for err in errors:
                flash(err, "danger")
        return _render_index(form, 400)
    try:
        record = run_scan(form.url.data, source="web")
    except URLValidationError as exc:
        flash(str(exc), "danger")
        return _render_index(form, 400)
    if not current_user.is_authenticated:
        # remember anonymous scans in the session so the visitor can view them
        owned = session.get(ANON_SCANS_KEY, [])[-49:]
        owned.append(record.id)
        session[ANON_SCANS_KEY] = owned
    return redirect(url_for("main.result", scan_id=record.id))


def _can_view(scan: Scan) -> bool:
    if current_user.is_authenticated:
        return current_user.is_admin or scan.user_id == current_user.id
    return scan.user_id is None and scan.id in session.get(ANON_SCANS_KEY, [])


@bp.route("/scan/<int:scan_id>")
def result(scan_id):
    scan = db.session.get(Scan, scan_id) or abort(404)
    if not _can_view(scan):
        abort(404)
    return render_template("main/result.html", scan=scan, form=ScanForm())


def _history_query():
    q = Scan.query.filter_by(user_id=current_user.id)
    cls = request.args.get("classification", "")
    search = request.args.get("q", "").strip()
    if cls in CLASSIFICATIONS:
        q = q.filter(Scan.classification == cls)
    if search:
        q = q.filter(Scan.url.ilike(f"%{search}%"))
    return q.order_by(Scan.created_at.desc(), Scan.id.desc()), cls, search


@bp.route("/history")
@login_required
def history():
    q, cls, search = _history_query()
    page = request.args.get("page", 1, type=int)
    pagination = q.paginate(page=page, per_page=current_app.config["HISTORY_PER_PAGE"],
                            error_out=False)
    counts = dict(db.session.query(Scan.classification, func.count(Scan.id))
                  .filter(Scan.user_id == current_user.id)
                  .group_by(Scan.classification).all())
    return render_template("main/history.html", pagination=pagination,
                           scans=pagination.items, counts=counts,
                           classifications=CLASSIFICATIONS, selected=cls, search=search)


@bp.route("/history/export.csv")
@login_required
def export_history():
    q, _cls, _search = _history_query()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "scanned_at_utc", "url", "domain", "classification",
                     "risk_score", "reasons"])
    for s in q.all():
        url = s.url
        if url[:1] in ("=", "+", "-", "@"):  # avoid CSV formula injection
            url = "'" + url
        writer.writerow([s.id, s.created_at.isoformat(sep=" ", timespec="seconds"),
                         url, s.domain, s.classification, s.score,
                         "; ".join(r["title"] for r in s.risk_reasons)])
    return Response(buffer.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=phishguard_history.csv"})


@bp.route("/history/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    scan = db.session.get(Scan, scan_id) or abort(404)
    if scan.user_id != current_user.id:
        abort(404)
    db.session.delete(scan)
    log_activity("history_delete", f"Deleted scan #{scan_id}", commit=False)
    db.session.commit()
    flash("Scan removed from your history.", "success")
    return redirect(request.referrer or url_for("main.history"))


@bp.route("/history/clear", methods=["POST"])
@login_required
def clear_history():
    n = Scan.query.filter_by(user_id=current_user.id).delete()
    log_activity("history_clear", f"Cleared {n} scans", commit=False)
    db.session.commit()
    flash(f"Cleared {n} scan(s) from your history.", "success")
    return redirect(url_for("main.history"))


@bp.route("/about")
def about():
    from ..detection.rules import PHISHING_THRESHOLD, RULES, SUSPICIOUS_THRESHOLD
    return render_template("main/about.html", rules=RULES,
                           suspicious_threshold=SUSPICIOUS_THRESHOLD,
                           phishing_threshold=PHISHING_THRESHOLD)
