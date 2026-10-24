import sqlite3
from datetime import datetime, timezone

import click
from flask import current_app, g
from werkzeug.security import generate_password_hash


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    password_change_required INTEGER NOT NULL DEFAULT 0 CHECK (password_change_required IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 160),
    category TEXT NOT NULL DEFAULT 'Uncategorized' CHECK (length(category) BETWEEN 1 AND 80),
    original_filename TEXT NOT NULL CHECK (length(original_filename) BETWEEN 1 AND 255),
    storage_name TEXT NOT NULL UNIQUE CHECK (length(storage_name) = 32),
    content_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 10485760),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS permissions (
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
    granted_by INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (document_id, user_id)
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY,
    actor_id INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    action TEXT NOT NULL,
    document_id INTEGER,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    context TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_created ON documents(created_at);
CREATE INDEX IF NOT EXISTS idx_permissions_user ON permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action, outcome);
CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
BEFORE UPDATE ON audit_logs BEGIN
    SELECT RAISE(ABORT, 'audit records are append-only');
END;
CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
BEFORE DELETE ON audit_logs BEGIN
    SELECT RAISE(ABORT, 'audit records are append-only');
END;
"""


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 10000")
    return g.db


def close_db(error=None):
    database = g.pop("db", None)
    if database is not None:
        if error is None:
            database.commit()
        else:
            database.rollback()
        database.close()


def init_db():
    database = get_db()
    database.executescript(SCHEMA)
    seed_demo_users(database)
    database.commit()


def init_app(app):
    app.teardown_appcontext(close_db)

    @app.cli.command("init-db")
    def init_db_command():
        init_db()
        click.echo("Initialized TrustVault database.")


def seed_demo_users(database=None):
    database = database or get_db()
    if not current_app.config["SEED_DEMO_USERS"]:
        return
    production = current_app.config["TRUSTVAULT_ENV"] == "production"
    accounts = [
        ("admin", "admin", current_app.config.get("TRUSTVAULT_ADMIN_PASSWORD") or "AdminDemo2026!"),
        ("owner", "owner", current_app.config.get("TRUSTVAULT_OWNER_PASSWORD") or "OwnerDemo2026!"),
        ("viewer", "viewer", current_app.config.get("TRUSTVAULT_VIEWER_PASSWORD") or "ViewerDemo2026!"),
    ]
    for username, role, password in accounts:
        database.execute(
            """INSERT OR IGNORE INTO users
               (username, password_hash, role, password_change_required, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (username, generate_password_hash(password), role, int(production), utcnow()),
        )
        if production:
            database.execute(
                "UPDATE users SET password_change_required = 1 WHERE username = ? COLLATE NOCASE",
                (username,),
            )


@click.command("create-user")
@click.argument("username")
@click.argument("role", type=click.Choice(["admin", "owner", "viewer"]))
@click.password_option()
def create_user_command(username, role, password):
    from .audit import record_event
    from .security import valid_username

    if not valid_username(username):
        raise click.ClickException("Username must be 3-40 letters, numbers, dots, underscores, or hyphens.")
    if len(password) < 12:
        raise click.ClickException("Password must be at least 12 characters.")
    database = get_db()
    try:
        cursor = database.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), role, utcnow()),
        )
        record_event(None, "user_created", None, "success", {"user_id": cursor.lastrowid})
        database.commit()
    except sqlite3.IntegrityError as error:
        raise click.ClickException("That username is already in use.") from error
    click.echo(f"Created {role} account {username}.")


def register_cli(app):
    app.cli.add_command(create_user_command)
