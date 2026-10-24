import math
import sqlite3
from datetime import date

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from .audit import record_event
from .db import get_db, utcnow
from .security import roles_required, valid_username

bp = Blueprint("admin", __name__, url_prefix="/admin")
PAGE_SIZE = 25


@bp.get("/")
@roles_required("admin")
def dashboard():
    db = get_db()
    counts = {
        "users": db.execute("SELECT count(*) FROM users").fetchone()[0],
        "documents": db.execute("SELECT count(*) FROM documents").fetchone()[0],
        "permissions": db.execute("SELECT count(*) FROM permissions").fetchone()[0],
        "denied": db.execute(
            "SELECT count(*) FROM audit_logs WHERE outcome = 'denied'"
        ).fetchone()[0],
    }
    recent = db.execute(
        """SELECT a.*, u.username
           FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id
           ORDER BY a.id DESC LIMIT 12"""
    ).fetchall()
    permission_changes = db.execute(
        """SELECT a.*, u.username FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id
           WHERE a.action IN ('permission_grant', 'permission_revoke')
           ORDER BY a.id DESC LIMIT 5"""
    ).fetchall()
    denied_attempts = db.execute(
        """SELECT a.*, u.username FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id
           WHERE a.outcome = 'denied' AND a.action = 'document_access'
           ORDER BY a.id DESC LIMIT 5"""
    ).fetchall()
    return render_template(
        "admin_dashboard.html", counts=counts, recent=recent,
        permission_changes=permission_changes, denied_attempts=denied_attempts,
    )


@bp.route("/users", methods=["GET", "POST"])
@roles_required("admin")
def users():
    db = get_db()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        role = request.form.get("role", "")
        password = request.form.get("password", "")
        if not valid_username(username):
            flash("Username must be 3-40 letters, numbers, dots, underscores, or hyphens.", "error")
        elif role not in {"admin", "owner", "viewer"}:
            flash("Choose a valid account role.", "error")
        elif len(password) < 12:
            flash("Temporary passwords must be at least 12 characters.", "error")
        else:
            try:
                cursor = db.execute(
                    """INSERT INTO users
                       (username, password_hash, role, password_change_required, created_at)
                       VALUES (?, ?, ?, 1, ?)""",
                    (username, generate_password_hash(password), role, utcnow()),
                )
                record_event(
                    g.current_user["id"], "user_created",
                    context={"target_user_id": cursor.lastrowid, "role": role},
                )
                db.commit()
                flash("Account created. The new user must change the temporary password.", "success")
                return redirect(url_for("admin.users"))
            except sqlite3.IntegrityError:
                db.rollback()
                flash("That username is already in use.", "error")
    rows = db.execute(
        "SELECT id, username, role, active, password_change_required, created_at FROM users ORDER BY username"
    ).fetchall()
    return render_template("admin_users.html", users=rows)


@bp.post("/users/<int:user_id>/update")
@roles_required("admin")
def update_user(user_id):
    target = get_db().execute(
        "SELECT id, role, active FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if target is None:
        abort(404)
    role = request.form.get("role", "")
    active = request.form.get("active") == "1"
    if role not in {"admin", "owner", "viewer"}:
        flash("Choose a valid account role.", "error")
        return redirect(url_for("admin.users"))
    if user_id == g.current_user["id"] and (role != "admin" or not active):
        flash("You cannot remove your own administrator access.", "error")
        return redirect(url_for("admin.users"))
    db = get_db()
    if target["role"] == "owner" and role != "owner":
        owns_docs = db.execute(
            "SELECT 1 FROM documents WHERE owner_id = ? LIMIT 1", (user_id,)
        ).fetchone()
        if owns_docs:
            flash("Transfer or delete this user's documents before changing their owner role.", "error")
            return redirect(url_for("admin.users"))
    if target["role"] == "admin" and target["active"] and (role != "admin" or not active):
        remaining = db.execute(
            "SELECT count(*) FROM users WHERE role = 'admin' AND active = 1 AND id != ?",
            (user_id,),
        ).fetchone()[0]
        if remaining == 0:
            flash("At least one active administrator must remain.", "error")
            return redirect(url_for("admin.users"))
    if target["active"] and not active:
        revoked = db.execute(
            "SELECT document_id FROM permissions WHERE user_id = ?", (user_id,)
        ).fetchall()
        for grant in revoked:
            record_event(
                g.current_user["id"], "permission_revoke", grant["document_id"],
                context={"target_user_id": user_id, "reason": "account_disabled"},
            )
        db.execute("DELETE FROM permissions WHERE user_id = ?", (user_id,))
    db.execute("UPDATE users SET role = ?, active = ? WHERE id = ?", (role, int(active), user_id))
    record_event(
        g.current_user["id"], "user_updated",
        context={"target_user_id": user_id, "role": role, "active": active},
    )
    db.commit()
    flash("Account updated.", "success")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/reset-password")
@roles_required("admin")
def reset_password(user_id):
    password = request.form.get("password", "")
    if len(password) < 12:
        flash("Temporary passwords must be at least 12 characters.", "error")
    elif get_db().execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
        abort(404)
    else:
        get_db().execute(
            "UPDATE users SET password_hash = ?, password_change_required = 1 WHERE id = ?",
            (generate_password_hash(password), user_id),
        )
        record_event(
            g.current_user["id"], "password_reset",
            context={"target_user_id": user_id},
        )
        get_db().commit()
        flash("Temporary password set. The user must change it at next sign-in.", "success")
    return redirect(url_for("admin.users"))


@bp.get("/documents")
@roles_required("admin")
def documents():
    db = get_db()
    search = request.args.get("q", "").strip()[:100]
    owner = request.args.get("owner", "").strip()[:40]
    category = request.args.get("category", "").strip()[:80]
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    try:
        if date_from and date.fromisoformat(date_from).isoformat() != date_from:
            raise ValueError
        if date_to and date.fromisoformat(date_to).isoformat() != date_to:
            raise ValueError
    except ValueError:
        abort(400, description="Dates must use YYYY-MM-DD format.")
    query = """SELECT d.id, d.title, d.category, d.original_filename, d.content_type,
                      d.size_bytes, d.created_at, d.updated_at, u.username AS owner_name
               FROM documents d JOIN users u ON u.id = d.owner_id WHERE 1=1"""
    params = []
    if search:
        query += " AND (d.title LIKE ? OR d.category LIKE ? OR d.original_filename LIKE ? OR u.username LIKE ?)"
        params.extend([f"%{search}%"] * 4)
    if owner:
        query += " AND u.username LIKE ?"
        params.append(f"%{owner}%")
    if category:
        query += " AND d.category LIKE ?"
        params.append(f"%{category}%")
    if date_from:
        query += " AND d.created_at >= ?"
        params.append(date_from + "T00:00:00")
    if date_to:
        query += " AND d.created_at < ?"
        params.append(date_to + "T23:59:59.999999")
    query += " ORDER BY d.created_at DESC, d.id DESC"
    rows = db.execute(query, params).fetchall()
    return render_template("admin_documents.html", documents=rows, filters={
        "q": search, "owner": owner, "category": category,
        "date_from": date_from, "date_to": date_to,
    })


@bp.get("/audit")
@roles_required("admin")
def audit():
    db = get_db()
    action = request.args.get("action", "").strip()[:60]
    outcome = request.args.get("outcome", "").strip()
    actor = request.args.get("actor", "").strip()[:40]
    page = request.args.get("page", 1, type=int)
    if page is None or page < 1:
        abort(400)
    clauses = []
    params = []
    if action:
        clauses.append("a.action LIKE ?")
        params.append(f"%{action}%")
    if outcome in {"success", "denied", "failure"}:
        clauses.append("a.outcome = ?")
        params.append(outcome)
    if actor:
        clauses.append("u.username LIKE ?")
        params.append(f"%{actor}%")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    total = db.execute(
        "SELECT count(*) FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id" + where,
        params,
    ).fetchone()[0]
    total_pages = max(1, math.ceil(total / PAGE_SIZE))
    page = min(page, total_pages)
    entries = db.execute(
        """SELECT a.*, u.username
           FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id"""
        + where + " ORDER BY a.id DESC LIMIT ? OFFSET ?",
        [*params, PAGE_SIZE, (page - 1) * PAGE_SIZE],
    ).fetchall()
    return render_template(
        "admin_audit.html", entries=entries, filters={"action": action, "outcome": outcome, "actor": actor},
        page=page, total_pages=total_pages, total=total,
    )
