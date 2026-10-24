import pytest

from trustvault.db import get_db

from conftest import csrf_token, sign_in


def test_login_uses_password_hash_and_records_success(client, app):
    response = sign_in(client, "owner", "OwnerDemo2026!")
    assert response.status_code == 302
    with app.app_context():
        db = get_db()
        owner = db.execute("SELECT password_hash FROM users WHERE username = 'owner'").fetchone()
        assert owner["password_hash"] != "OwnerDemo2026!"
        event = db.execute(
            "SELECT action, outcome FROM audit_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert tuple(event) == ("login", "success")


def test_invalid_password_is_generic_and_audited(client, app):
    token = csrf_token(client, "/login")
    response = client.post("/login", data={
        "csrf_token": token, "username": "owner", "password": "wrong",
    })
    assert response.status_code == 401
    assert b"Sign-in failed" in response.data
    assert b"incorrect password" not in response.data.lower()
    with app.app_context():
        event = get_db().execute(
            "SELECT action, outcome, context FROM audit_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert event["action"] == "login"
        assert event["outcome"] == "failure"
        assert "wrong" not in event["context"]


def test_csrf_protects_login_and_state_changes(client):
    assert client.post("/login", data={
        "username": "owner", "password": "OwnerDemo2026!",
    }).status_code == 400

    sign_in(client, "owner", "OwnerDemo2026!")
    assert client.post("/documents/new", data={
        "title": "No token", "category": "Reports",
    }).status_code == 400


def test_login_is_limited_to_five_attempts_per_minute(client, app):
    token = csrf_token(client, "/login")
    statuses = []
    for _ in range(6):
        response = client.post(
            "/login",
            data={"csrf_token": token, "username": "unknown", "password": "bad"},
        )
        statuses.append(response.status_code)
    assert statuses == [401, 401, 401, 401, 401, 429]
    with app.app_context():
        assert get_db().execute(
            "SELECT count(*) FROM audit_logs WHERE action = 'login_rate_limited'"
        ).fetchone()[0] == 1


def test_production_requires_secret_and_seed_passwords(monkeypatch):
    from trustvault import create_app

    monkeypatch.setenv("TRUSTVAULT_ENV", "production")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app()

    monkeypatch.setenv("SECRET_KEY", "test-production-secret")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "redis://localhost:6379/1")
    monkeypatch.delenv("TRUSTVAULT_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("TRUSTVAULT_OWNER_PASSWORD", raising=False)
    monkeypatch.delenv("TRUSTVAULT_VIEWER_PASSWORD", raising=False)
    with pytest.raises(RuntimeError, match="demo-account passwords"):
        create_app()


def test_required_password_change_gates_other_routes(client, app):
    from werkzeug.security import check_password_hash

    with app.app_context():
        get_db().execute(
            "UPDATE users SET password_change_required = 1 WHERE username = 'owner'"
        )
        get_db().commit()
    sign_in(client, "owner", "OwnerDemo2026!")
    redirect = client.get("/documents/")
    assert redirect.status_code == 302
    assert redirect.headers["Location"].endswith("/change-password")

    token = csrf_token(client, "/change-password")
    response = client.post("/change-password", data={
        "csrf_token": token,
        "current_password": "OwnerDemo2026!",
        "password": "a-new-strong-password",
        "confirmation": "a-new-strong-password",
    })
    assert response.status_code == 302
    with app.app_context():
        owner = get_db().execute(
            "SELECT password_hash, password_change_required FROM users WHERE username = 'owner'"
        ).fetchone()
        assert check_password_hash(owner["password_hash"], "a-new-strong-password")
        assert owner["password_change_required"] == 0
