from __future__ import annotations

import re
from functools import wraps

from flask import abort, request
from flask_login import current_user
from markupsafe import Markup, escape

from .extensions import db
from .models import ActivityLog


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            from flask import redirect, url_for
            return redirect(url_for("auth.login", next=request.path))
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def client_ip() -> str:
    return (request.remote_addr or "")[:45]


def log_activity(action: str, detail: str = "", user_id: int | None = None,
                 commit: bool = True) -> None:
    if user_id is None and current_user and current_user.is_authenticated:
        user_id = current_user.id
    db.session.add(ActivityLog(user_id=user_id, action=action,
                               detail=(detail or "")[:500], ip_address=client_ip()))
    if commit:
        db.session.commit()


_NUMBERED = re.compile(r"^\s*\d+[.)] ")


def render_article(text: str) -> Markup:
    """Very small, safe formatter for awareness articles.

    The text is HTML-escaped first, so even an administrator cannot inject
    scripts; only the formatting below is produced.
    """
    html: list[str] = []
    group: list[str] = []      # consecutive lines of the same kind
    kind = None                # "p" | "ul" | "ol"

    def flush():
        nonlocal group, kind
        if group:
            if kind == "p":
                html.append("<p>" + "<br>".join(_inline(ln) for ln in group) + "</p>")
            else:
                items = "".join(f"<li>{_inline(ln)}</li>" for ln in group)
                html.append(f"<{kind}>{items}</{kind}>")
        group, kind = [], None

    for raw in (text or "").replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if not line:
            flush()
            continue
        if line.startswith("#"):
            flush()
            html.append(f"<h3>{_inline(line.lstrip('#').strip())}</h3>")
            continue
        if line.startswith(("- ", "* ")):
            this, content = "ul", line[2:]
        elif _NUMBERED.match(line):
            this, content = "ol", _NUMBERED.sub("", line)
        else:
            this, content = "p", line
        if this != kind:
            flush()
            kind = this
        group.append(content)
    flush()
    return Markup("\n".join(html))


def _inline(text: str) -> str:
    out = str(escape(text))
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"`(.+?)`", r"<code>\1</code>", out)
    return out
