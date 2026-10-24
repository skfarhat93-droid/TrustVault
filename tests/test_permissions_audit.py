import json
import sqlite3
from io import BytesIO

import pytest

from trustvault.db import get_db

from conftest import csrf_token, sign_in


def create_pdf(client):
    token = csrf_token(client, "/documents/new")
    return client.post("/documents/new", data={
        "csrf_token": token,
        "title": "Shared agreement",
        "category": "Contracts",
        "file": (BytesIO(b"%PDF-1.7\ncontract"), "agreement.pdf", "application/pdf"),
    }, content_type="multipart/form-data")


def test_permission_grant_and_revoke_immediately_blocks_download(client, app):
    sign_in(client, "owner", "OwnerDemo2026!")
    uploaded = create_pdf(client)
    document_id = int(uploaded.headers["Location"].split("/")[-1])
    with app.app_context():
        viewer_id = get_db().execute(
            "SELECT id FROM users WHERE username = 'viewer'"
        ).fetchone()["id"]

    token = csrf_token(client, f"/documents/{document_id}/permissions")
    granted = client.post(f"/documents/{document_id}/permissions", data={
        "csrf_token": token, "user_id": viewer_id, "permission": "read",
    })
    assert granted.status_code == 302

    viewer_client = app.test_client()
    sign_in(viewer_client, "viewer", "ViewerDemo2026!")
    assert viewer_client.get(f"/documents/{document_id}/download").status_code == 200

    token = csrf_token(client, f"/documents/{document_id}/permissions")
    revoked = client.post(
        f"/documents/{document_id}/permissions/{viewer_id}/revoke",
        data={"csrf_token": token},
    )
    assert revoked.status_code == 302
    response = viewer_client.get(f"/documents/{document_id}/download")
    assert response.status_code == 404
    assert b"contract" not in response.data

    with app.app_context():
        actions = [
            row[0] for row in get_db().execute(
                "SELECT action FROM audit_logs WHERE document_id = ? ORDER BY id",
                (document_id,),
            ).fetchall()
        ]
        assert "permission_grant" in actions
        assert "permission_revoke" in actions
        assert "document_download" in actions


def test_only_owner_or_admin_can_manage_permissions(client, app):
    sign_in(client, "owner", "OwnerDemo2026!")
    uploaded = create_pdf(client)
    document_id = uploaded.headers["Location"].split("/")[-1]
    sign_in(client, "viewer", "ViewerDemo2026!")
    response = client.get(f"/documents/{document_id}/permissions")
    assert response.status_code == 404


def test_admin_can_grant_access_without_implicit_file_access(client, app):
    sign_in(client, "owner", "OwnerDemo2026!")
    uploaded = create_pdf(client)
    document_id = int(uploaded.headers["Location"].split("/")[-1])
    with app.app_context():
        viewer_id = get_db().execute(
            "SELECT id FROM users WHERE username = 'viewer'"
        ).fetchone()["id"]

    sign_in(client, "admin", "AdminDemo2026!")
    admin_access = client.get(f"/documents/{document_id}/permissions")
    assert admin_access.status_code == 200
    token = csrf_token(client, f"/documents/{document_id}/permissions")
    response = client.post(f"/documents/{document_id}/permissions", data={
        "csrf_token": token, "user_id": viewer_id, "permission": "read",
    })
    assert response.status_code == 302
    assert client.get(f"/documents/{document_id}/download").status_code == 404
    with app.app_context():
        assert get_db().execute(
            "SELECT permission FROM permissions WHERE document_id = ? AND user_id = ?",
            (document_id, viewer_id),
        ).fetchone()["permission"] == "read"


def test_audit_records_are_append_only(app):
    with app.app_context():
        db = get_db()
        assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        db.execute(
            "INSERT INTO audit_logs (action, outcome, context, created_at) VALUES ('test', 'success', '{}', 'now')"
        )
        db.commit()
        record_id = db.execute("SELECT max(id) FROM audit_logs").fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("UPDATE audit_logs SET action = 'changed' WHERE id = ?", (record_id,))
        db.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("DELETE FROM audit_logs WHERE id = ?", (record_id,))
        db.rollback()


def test_audit_context_contains_metadata_not_file_content(client, app):
    sign_in(client, "owner", "OwnerDemo2026!")
    create_pdf(client)
    with app.app_context():
        event = get_db().execute(
            "SELECT context FROM audit_logs WHERE action = 'document_upload'"
        ).fetchone()
        context = json.loads(event["context"])
        assert context["filename"] == "agreement.pdf"
        assert "contract" not in event["context"]


def test_document_deletion_keeps_its_audit_target(client, app):
    sign_in(client, "owner", "OwnerDemo2026!")
    uploaded = create_pdf(client)
    document_id = int(uploaded.headers["Location"].split("/")[-1])
    token = csrf_token(client, f"/documents/{document_id}")
    response = client.post(
        f"/documents/{document_id}/delete", data={"csrf_token": token}
    )
    assert response.status_code == 302
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT 1 FROM documents WHERE id = ?", (document_id,)).fetchone() is None
        event = db.execute(
            "SELECT action, document_id, context FROM audit_logs WHERE action = 'document_delete'"
        ).fetchone()
        assert event["document_id"] == document_id
        assert "Shared agreement" in event["context"]
