from io import BytesIO
from pathlib import Path

from trustvault.db import get_db

from conftest import csrf_token, sign_in, upload_pdf


def test_owner_can_upload_and_view_private_document(client, app):
    sign_in(client, "owner", "OwnerDemo2026!")
    response = upload_pdf(client)
    assert response.status_code == 302
    detail = client.get(response.headers["Location"])
    assert detail.status_code == 200
    assert b"Quarterly report" in detail.data
    with app.app_context():
        row = get_db().execute("SELECT * FROM documents").fetchone()
        assert row["storage_name"] != row["original_filename"]
        stored = Path(app.config["UPLOAD_FOLDER"]) / row["storage_name"]
        assert stored.is_file()
        assert Path(app.static_folder) not in stored.parents


def test_rejects_mismatched_file_signature(client, app):
    sign_in(client, "owner", "OwnerDemo2026!")
    token = csrf_token(client, "/documents/new")
    response = client.post("/documents/new", data={
        "csrf_token": token,
        "title": "Fake PDF",
        "category": "Reports",
        "file": (BytesIO(b"<html>not a pdf</html>"), "fake.pdf", "application/pdf"),
    }, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"contents do not match" in response.data
    with app.app_context():
        assert get_db().execute("SELECT count(*) FROM documents").fetchone()[0] == 0


def test_rejects_disallowed_extension(client):
    sign_in(client, "owner", "OwnerDemo2026!")
    token = csrf_token(client, "/documents/new")
    response = client.post("/documents/new", data={
        "csrf_token": token, "title": "Script", "category": "Other",
        "file": (BytesIO(b"print('hello')"), "script.py", "text/x-python"),
    }, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"Only PDF, PNG, JPEG" in response.data


def test_file_size_limit_is_enforced_and_audited(client, app):
    sign_in(client, "owner", "OwnerDemo2026!")
    token = csrf_token(client, "/documents/new")
    response = client.post("/documents/new", data={
        "csrf_token": token, "title": "Large", "category": "Other",
        "file": (BytesIO(b"x" * (10 * 1024 * 1024 + 5)), "large.txt", "text/plain"),
    }, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"exceeds the 10 MB limit" in response.data

    response = client.post("/documents/new", data={
        "csrf_token": token, "title": "Too large", "category": "Other",
        "file": (BytesIO(b"x" * (11 * 1024 * 1024)), "too-large.txt", "text/plain"),
    }, content_type="multipart/form-data")
    assert response.status_code == 413
    with app.app_context():
        event = get_db().execute(
            "SELECT outcome, context FROM audit_logs WHERE action = 'document_upload' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert event["outcome"] == "failure"
        assert "request_too_large" in event["context"]


def test_viewer_cannot_upload_edit_or_delete(client):
    sign_in(client, "owner", "OwnerDemo2026!")
    uploaded = upload_pdf(client, title="Owner file")
    document_id = uploaded.headers["Location"].split("/")[-1]
    sign_in(client, "viewer", "ViewerDemo2026!")
    assert client.get("/documents/new").status_code == 403
    token = csrf_token(client, "/documents/")
    assert client.post(f"/documents/{document_id}/delete", data={
        "csrf_token": token,
    }).status_code == 404
    assert client.get(f"/documents/{document_id}/edit").status_code == 404
    assert client.post(f"/documents/{document_id}/permissions", data={
        "csrf_token": token, "user_id": 1, "permission": "read",
    }).status_code == 404
    assert client.get(f"/documents/{document_id}/download").status_code == 404


def test_cross_user_id_and_unauthorised_download_are_denied_and_audited(client, app):
    sign_in(client, "owner", "OwnerDemo2026!")
    uploaded = upload_pdf(client)
    document_id = uploaded.headers["Location"].split("/")[-1]
    owner = app.test_client()
    sign_in(owner, "owner", "OwnerDemo2026!")
    assert owner.get(f"/documents/{document_id}/download").status_code == 200

    sign_in(client, "viewer", "ViewerDemo2026!")
    assert client.get(f"/documents/{document_id}").status_code == 404
    assert client.get(f"/documents/{document_id}/download").status_code == 404
    with app.app_context():
        denied = get_db().execute(
            "SELECT count(*) FROM audit_logs WHERE outcome = 'denied' AND document_id = ?",
            (int(document_id),),
        ).fetchone()[0]
        assert denied >= 2


def test_viewer_is_read_only_even_if_edit_permission_is_submitted(client, app):
    sign_in(client, "owner", "OwnerDemo2026!")
    token = csrf_token(client, "/documents/new")
    client.post("/documents/new", data={
        "csrf_token": token, "title": "Shared", "category": "Reports",
        "file": (BytesIO(b"%PDF-1.7\nfile"), "shared.pdf", "application/pdf"),
    }, content_type="multipart/form-data")
    with app.app_context():
        db = get_db()
        doc_id = db.execute("SELECT id FROM documents").fetchone()["id"]
        viewer_id = db.execute("SELECT id FROM users WHERE username = 'viewer'").fetchone()["id"]
    token = csrf_token(client, f"/documents/{doc_id}/permissions")
    response = client.post(f"/documents/{doc_id}/permissions", data={
        "csrf_token": token, "user_id": viewer_id, "permission": "edit",
    })
    assert response.status_code == 200
    assert b"Choose an active user" in response.data
    with app.app_context():
        assert get_db().execute(
            "SELECT 1 FROM permissions WHERE document_id = ? AND user_id = ?",
            (doc_id, viewer_id),
        ).fetchone() is None


def test_admin_can_inspect_metadata_but_not_implicitly_download(client, app):
    sign_in(client, "owner", "OwnerDemo2026!")
    response = upload_pdf(client, title="Restricted file")
    doc_id = response.headers["Location"].split("/")[-1]
    sign_in(client, "admin", "AdminDemo2026!")
    listing = client.get("/admin/documents")
    assert listing.status_code == 200
    assert b"Restricted file" in listing.data
    assert client.get(f"/documents/{doc_id}/download").status_code == 404
