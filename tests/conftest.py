import re
import hashlib

import pytest

from trustvault import create_app


@pytest.fixture
def app(tmp_path):
    return create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-secret-key",
        "DATABASE": str(tmp_path / "test.sqlite3"),
        "UPLOAD_FOLDER": str(tmp_path / "private-uploads"),
        "WTF_CSRF_ENABLED": True,
        "TRUSTVAULT_ENV": "development",
        "SEED_DEMO_USERS": True,
        "TRUSTVAULT_ADMIN_PASSWORD": "AdminDemo2026!",
        "TRUSTVAULT_OWNER_PASSWORD": "OwnerDemo2026!",
        "TRUSTVAULT_VIEWER_PASSWORD": "ViewerDemo2026!",
    })


@pytest.fixture
def client(app, tmp_path):
    test_client = app.test_client()
    address = hashlib.sha256(str(tmp_path).encode()).digest()
    test_client.environ_base["REMOTE_ADDR"] = f"198.18.{address[0]}.{address[1]}"
    return test_client


def csrf_token(client, path):
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, f"CSRF token missing from {path}"
    return match.group(1).decode()


def sign_in(client, username, password):
    if client.get("/login").status_code == 302:
        token = csrf_token(client, "/documents/")
        client.post("/logout", data={"csrf_token": token})
    token = csrf_token(client, "/login")
    response = client.post("/login", data={
        "csrf_token": token, "username": username, "password": password,
    })
    assert response.status_code == 302
    return response


def upload_pdf(client, title="Quarterly report", filename="report.pdf"):
    from io import BytesIO

    token = csrf_token(client, "/documents/new")
    return client.post("/documents/new", data={
        "csrf_token": token,
        "title": title,
        "category": "Reports",
        "file": (BytesIO(b"%PDF-1.7\nprivate test bytes"), filename, "application/pdf"),
    }, content_type="multipart/form-data")
