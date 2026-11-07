from flask import Blueprint, abort, render_template

from ..extensions import db
from ..models import AwarenessArticle

bp = Blueprint("awareness", __name__)


@bp.route("/")
def index():
    articles = (AwarenessArticle.query.filter_by(published=True)
                .order_by(AwarenessArticle.position, AwarenessArticle.id).all())
    return render_template("awareness/index.html", articles=articles)


@bp.route("/quiz")
def quiz():
    return render_template("awareness/quiz.html")


@bp.route("/<slug>")
def article(slug):
    item = AwarenessArticle.query.filter_by(slug=slug, published=True).first() or abort(404)
    item.views = (item.views or 0) + 1
    db.session.commit()
    others = (AwarenessArticle.query.filter(AwarenessArticle.published.is_(True),
                                            AwarenessArticle.id != item.id)
              .order_by(AwarenessArticle.position).limit(4).all())
    return render_template("awareness/article.html", article=item, others=others)
