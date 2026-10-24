from flask import Blueprint, g, redirect, render_template, url_for

from .db import get_db
from .security import login_required

bp = Blueprint("views", __name__)


@bp.get("/")
def index():
    if g.current_user is not None:
        return redirect(url_for("views.dashboard"))
    return redirect(url_for("auth.login"))


@bp.get("/dashboard")
@login_required
def dashboard():
    if g.current_user["role"] == "admin":
        return redirect(url_for("admin.dashboard"))
    docs = get_db().execute(
        """SELECT DISTINCT d.id, d.title, d.category, d.created_at, u.username AS owner_name
           FROM documents d JOIN users u ON u.id = d.owner_id
           LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = ?
           WHERE d.owner_id = ? OR p.user_id IS NOT NULL
           ORDER BY d.created_at DESC LIMIT 6""",
        (g.current_user["id"], g.current_user["id"]),
    ).fetchall()
    return render_template("dashboard.html", documents=docs)
