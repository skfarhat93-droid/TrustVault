from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash

from .audit import record_event
from .db import get_db, utcnow
from .limiter import limiter
from .security import login_required

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", key_func=get_remote_address, methods=["POST"])
def login():
    if g.current_user is not None:
        return redirect(url_for("views.dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE AND active = 1",
            (username,),
        ).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            record_event(
                user["id"] if user else None,
                "login",
                outcome="failure",
                context={"username": username[:40], "reason": "invalid_credentials"},
            )
            flash("Sign-in failed. Check your details and try again.", "error")
            return render_template("login.html"), 401
        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True
        record_event(user["id"], "login")
        return redirect(url_for("views.dashboard"))
    return render_template("login.html")


@bp.post("/logout")
@login_required
def logout():
    actor_id = g.current_user["id"]
    record_event(actor_id, "logout")
    session.clear()
    flash("You have signed out.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "")
        user = get_db().execute(
            "SELECT password_hash FROM users WHERE id = ?", (g.current_user["id"],)
        ).fetchone()
        if not check_password_hash(user["password_hash"], current_password):
            flash("Current password is incorrect.", "error")
        elif len(password) < 12:
            flash("Use a password with at least 12 characters.", "error")
        elif password != confirmation:
            flash("The new passwords do not match.", "error")
        else:
            get_db().execute(
                "UPDATE users SET password_hash = ?, password_change_required = 0 WHERE id = ?",
                (generate_password_hash(password), g.current_user["id"]),
            )
            record_event(g.current_user["id"], "password_changed")
            flash("Your password has been updated.", "success")
            return redirect(url_for("views.dashboard"))
    return render_template("change_password.html")
