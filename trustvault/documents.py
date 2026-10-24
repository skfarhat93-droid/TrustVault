import re
import sqlite3
import uuid
from datetime import date
from pathlib import Path

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from .audit import record_event
from .db import get_db, utcnow
from .security import login_required

bp = Blueprint("documents", __name__, url_prefix="/documents")

ALLOWED_TYPES = {
    "pdf": ("application/pdf", {b"%PDF-"}),
    "png": ("image/png", {b"\x89PNG\r\n\x1a\n"}),
    "jpg": ("image/jpeg", {b"\xff\xd8\xff"}),
    "jpeg": ("image/jpeg", {b"\xff\xd8\xff"}),
}
MAX_FILE_SIZE = 10 * 1024 * 1024
STORAGE_NAME_RE = re.compile(r"^[a-f0-9]{32}$")


def _allowed_document(document_id, require_edit=False):
    db = get_db()
    document = db.execute(
        """SELECT d.*, u.username AS owner_name
           FROM documents d JOIN users u ON u.id = d.owner_id
           WHERE d.id = ?""",
        (document_id,),
    ).fetchone()
    permitted = False
    if document is not None:
        if document["owner_id"] == g.current_user["id"]:
            permitted = True
        else:
            row = db.execute(
                "SELECT permission FROM permissions WHERE document_id = ? AND user_id = ?",
                (document_id, g.current_user["id"]),
            ).fetchone()
            permitted = row is not None and (
                not require_edit or (
                    row["permission"] == "edit" and g.current_user["role"] != "viewer"
                )
            )
    if not permitted:
        record_event(
            g.current_user["id"],
            "document_access",
            document_id=document_id,
            outcome="denied",
            context={"operation": "edit" if require_edit else "read"},
        )
        db.commit()
        abort(404)
    return document


def _validate_upload(upload):
    original = secure_filename(upload.filename or "")
    if not original or "." not in original:
        return None, "Choose a PDF, PNG, or JPEG file with a valid filename."
    extension = original.rsplit(".", 1)[1].lower()
    if extension == "txt":
        data = upload.stream.read(MAX_FILE_SIZE + 1)
        if not data or len(data) > MAX_FILE_SIZE:
            return None, "The file is empty or exceeds the 10 MB limit."
        if (upload.mimetype or "").lower() not in {"text/plain", "application/octet-stream"}:
            return None, "The file contents do not match the selected file type."
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None, "Text files must be valid UTF-8."
        if any(ord(char) < 32 and char not in "\t\n\r" for char in text):
            return None, "The selected text file contains unsupported control characters."
        return (original, "text/plain", data), None

    file_type = ALLOWED_TYPES.get(extension)
    if file_type is None:
        return None, "Only PDF, PNG, JPEG, and UTF-8 text files are supported."
    expected_mime, signatures = file_type
    data = upload.stream.read(MAX_FILE_SIZE + 1)
    if not data or len(data) > MAX_FILE_SIZE:
        return None, "The file is empty or exceeds the 10 MB limit."
    claimed = (upload.mimetype or "").lower()
    accepted_claims = {expected_mime, "application/octet-stream"}
    if claimed not in accepted_claims or not any(data.startswith(signature) for signature in signatures):
        return None, "The file contents do not match the selected file type."
    return (original, expected_mime, data), None


def _stored_path(storage_name):
    if not STORAGE_NAME_RE.fullmatch(storage_name or ""):
        current_app.logger.error("Invalid internal document storage name.")
        abort(404)
    return Path(current_app.config["UPLOAD_FOLDER"]) / storage_name


@bp.route("/")
@login_required
def index():
    db = get_db()
    user = g.current_user
    search = request.args.get("q", "").strip()[:100]
    category = request.args.get("category", "").strip()[:80]
    owner = request.args.get("owner", "").strip()[:40]
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    try:
        if date_from and date.fromisoformat(date_from).isoformat() != date_from:
            raise ValueError
        if date_to and date.fromisoformat(date_to).isoformat() != date_to:
            raise ValueError
    except ValueError:
        abort(400, description="Dates must use YYYY-MM-DD format.")

    if user["role"] == "admin":
        query = """SELECT d.id, d.title, d.category, d.original_filename, d.content_type,
                          d.size_bytes, d.created_at, d.updated_at, u.username AS owner_name
                   FROM documents d JOIN users u ON u.id = d.owner_id WHERE 1=1"""
        params = []
    else:
        query = """SELECT DISTINCT d.id, d.title, d.category, d.original_filename, d.content_type,
                          d.size_bytes, d.created_at, d.updated_at, u.username AS owner_name
                   FROM documents d JOIN users u ON u.id = d.owner_id
                   LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = ?
                   WHERE (d.owner_id = ? OR p.user_id IS NOT NULL)"""
        params = [user["id"], user["id"]]
    if search:
        query += " AND (d.title LIKE ? OR d.original_filename LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    if category:
        query += " AND d.category LIKE ?"
        params.append(f"%{category}%")
    if owner:
        query += " AND u.username LIKE ?"
        params.append(f"%{owner}%")
    if date_from:
        query += " AND d.created_at >= ?"
        params.append(date_from + "T00:00:00")
    if date_to:
        query += " AND d.created_at < ?"
        params.append(date_to + "T23:59:59.999999")
    query += " ORDER BY d.created_at DESC, d.id DESC"
    documents = db.execute(query, params).fetchall()
    return render_template("documents.html", documents=documents, filters={
        "q": search, "category": category, "owner": owner,
        "date_from": date_from, "date_to": date_to,
    })


@bp.route("/new", methods=["GET", "POST"])
@login_required
def create():
    if g.current_user["role"] != "owner":
        abort(403)
    if request.method == "POST":
        upload = request.files.get("file")
        if upload is None:
            record_event(
                g.current_user["id"], "document_upload", outcome="failure",
                context={"reason": "missing_file"},
            )
            flash("Select a file to upload.", "error")
        else:
            validated, error = _validate_upload(upload)
            title = request.form.get("title", "").strip()[:160]
            category = request.form.get("category", "").strip()[:80] or "Uncategorized"
            if not title or len(category) < 1:
                error = "Document name and category are required."
            if error:
                record_event(
                    g.current_user["id"], "document_upload", outcome="failure",
                    context={"reason": "invalid_input"},
                )
                flash(error, "error")
            else:
                original, content_type, data = validated
                storage_name = uuid.uuid4().hex
                storage_path = Path(current_app.config["UPLOAD_FOLDER"]) / storage_name
                try:
                    with storage_path.open("xb") as stored:
                        stored.write(data)
                    now = utcnow()
                    db = get_db()
                    cursor = db.execute(
                        """INSERT INTO documents
                           (owner_id, title, category, original_filename, storage_name,
                            content_type, size_bytes, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (g.current_user["id"], title, category, original, storage_name,
                         content_type, len(data), now, now),
                    )
                    record_event(
                        g.current_user["id"], "document_upload", cursor.lastrowid,
                        context={"filename": original, "size_bytes": len(data)},
                    )
                    db.commit()
                    flash("Document uploaded securely.", "success")
                    return redirect(url_for("documents.detail", document_id=cursor.lastrowid))
                except (OSError, sqlite3.Error):
                    db = get_db()
                    db.rollback()
                    record_event(
                        g.current_user["id"], "document_upload", outcome="failure",
                        context={"reason": "storage_error"},
                    )
                    db.commit()
                    try:
                        storage_path.unlink(missing_ok=True)
                    except OSError:
                        current_app.logger.exception("Could not clean up failed upload.")
                    current_app.logger.exception("Document upload failed.")
                    flash("The document could not be saved. Please try again.", "error")
    return render_template("document_form.html", document=None)


@bp.route("/<int:document_id>")
@login_required
def detail(document_id):
    document = _allowed_document(document_id)
    record_event(g.current_user["id"], "document_view", document_id)
    get_db().commit()
    permission = get_db().execute(
        "SELECT permission FROM permissions WHERE document_id = ? AND user_id = ?",
        (document_id, g.current_user["id"]),
    ).fetchone()
    can_edit = document["owner_id"] == g.current_user["id"] or (
        permission is not None and permission["permission"] == "edit"
    )
    return render_template("document_detail.html", document=document, can_edit=can_edit)


@bp.get("/<int:document_id>/download")
@login_required
def download(document_id):
    document = _allowed_document(document_id)
    path = _stored_path(document["storage_name"])
    if not path.is_file():
        current_app.logger.error("Stored file missing for document id %s.", document_id)
        abort(404)
    record_event(g.current_user["id"], "document_download", document_id)
    get_db().commit()
    response = send_file(
        path, mimetype=document["content_type"], as_attachment=True,
        download_name=document["original_filename"], conditional=True,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/<int:document_id>/view")
@login_required
def view_file(document_id):
    document = _allowed_document(document_id)
    path = _stored_path(document["storage_name"])
    if not path.is_file():
        current_app.logger.error("Stored file missing for document id %s.", document_id)
        abort(404)
    record_event(g.current_user["id"], "document_view_file", document_id)
    get_db().commit()
    response = send_file(path, mimetype=document["content_type"], as_attachment=False)
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/<int:document_id>/edit", methods=["GET", "POST"])
@login_required
def edit(document_id):
    document = _allowed_document(document_id, require_edit=True)
    if request.method == "POST":
        title = request.form.get("title", "").strip()[:160]
        category = request.form.get("category", "").strip()[:80]
        if not title or not category:
            flash("Document name and category are required.", "error")
        else:
            get_db().execute(
                "UPDATE documents SET title = ?, category = ?, updated_at = ? WHERE id = ?",
                (title, category, utcnow(), document_id),
            )
            record_event(
                g.current_user["id"], "document_edit", document_id,
                context={"fields": ["title", "category"]},
            )
            flash("Document details updated.", "success")
            return redirect(url_for("documents.detail", document_id=document_id))
    return render_template("document_form.html", document=document)


@bp.post("/<int:document_id>/delete")
@login_required
def delete(document_id):
    document = _allowed_document(document_id, require_edit=True)
    if document["owner_id"] != g.current_user["id"]:
        abort(403)
    db = get_db()
    record_event(
        g.current_user["id"], "document_delete", document_id,
        context={"title": document["title"], "filename": document["original_filename"]},
    )
    db.execute("DELETE FROM documents WHERE id = ?", (document_id,))
    db.commit()
    path = _stored_path(document["storage_name"])
    try:
        path.unlink(missing_ok=True)
    except OSError:
        current_app.logger.exception("Could not remove stored file for deleted document id %s.", document_id)
        flash("Document record deleted, but private file cleanup failed. Contact an administrator.", "error")
    else:
        flash("Document deleted.", "success")
    return redirect(url_for("documents.index"))


@bp.route("/<int:document_id>/permissions", methods=["GET", "POST"])
@login_required
def manage_permissions(document_id):
    document = get_db().execute(
        "SELECT * FROM documents WHERE id = ?", (document_id,)
    ).fetchone()
    if document is None:
        abort(404)
    user = g.current_user
    if user["role"] != "admin" and document["owner_id"] != user["id"]:
        record_event(user["id"], "permission_manage", document_id, "denied")
        get_db().commit()
        abort(404)
    db = get_db()
    if request.method == "POST":
        target_id = request.form.get("user_id", type=int)
        permission = request.form.get("permission", "")
        target = db.execute(
            "SELECT id, role, active FROM users WHERE id = ?", (target_id,)
        ).fetchone()
        if (target is None or not target["active"] or target_id == document["owner_id"]
                or permission not in ("read", "edit")
                or (target["role"] == "viewer" and permission == "edit")):
            flash("Choose an active user other than the document owner and a valid permission.", "error")
        else:
            try:
                db.execute(
                    """INSERT INTO permissions (document_id, user_id, permission, granted_by, created_at)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(document_id, user_id) DO UPDATE SET
                         permission = excluded.permission,
                         granted_by = excluded.granted_by,
                         created_at = excluded.created_at""",
                    (document_id, target_id, permission, user["id"], utcnow()),
                )
                record_event(
                    user["id"], "permission_grant", document_id,
                    context={"target_user_id": target_id, "permission": permission},
                )
                flash("Access permission saved.", "success")
            except sqlite3.IntegrityError:
                db.rollback()
                current_app.logger.exception("Permission update failed for document id %s.", document_id)
                flash("The permission could not be saved.", "error")
            else:
                db.commit()
                return redirect(url_for("documents.manage_permissions", document_id=document_id))
    granted = db.execute(
        """SELECT p.user_id, u.username, p.permission, p.created_at
           FROM permissions p JOIN users u ON u.id = p.user_id
           WHERE p.document_id = ? ORDER BY u.username""",
        (document_id,),
    ).fetchall()
    candidates = db.execute(
        """SELECT id, username, role FROM users
           WHERE active = 1 AND id != ? ORDER BY username""",
        (document["owner_id"],),
    ).fetchall()
    return render_template(
        "permissions.html", document=document, granted=granted, candidates=candidates
    )


@bp.post("/<int:document_id>/permissions/<int:target_id>/revoke")
@login_required
def revoke_permission(document_id, target_id):
    document = get_db().execute(
        "SELECT owner_id FROM documents WHERE id = ?", (document_id,)
    ).fetchone()
    if document is None:
        abort(404)
    user = g.current_user
    if user["role"] != "admin" and document["owner_id"] != user["id"]:
        record_event(user["id"], "permission_revoke", document_id, "denied")
        get_db().commit()
        abort(404)
    db = get_db()
    cursor = db.execute(
        "DELETE FROM permissions WHERE document_id = ? AND user_id = ?",
        (document_id, target_id),
    )
    if cursor.rowcount:
        record_event(
            user["id"], "permission_revoke", document_id,
            context={"target_user_id": target_id},
        )
    db.commit()
    flash("Access revoked." if cursor.rowcount else "No matching permission was found.", "success")
    return redirect(url_for("documents.manage_permissions", document_id=document_id))
