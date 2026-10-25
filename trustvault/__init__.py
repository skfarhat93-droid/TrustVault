import os
from datetime import timedelta
from pathlib import Path

from flask import Flask, redirect, request, url_for
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.exceptions import RequestEntityTooLarge, TooManyRequests

from .db import init_app as init_db, init_db as initialize_db
from .limiter import limiter

csrf = CSRFProtect()


def create_app(test_config=None):
    app = Flask(
        __name__, 
        instance_relative_config=True,
        template_folder="../templates", static_folder="../static",
    )
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    default_secret = os.environ.get("SECRET_KEY")
    production = os.environ.get("TRUSTVAULT_ENV", "development").lower() == "production"
    if production and not default_secret:
        raise RuntimeError("SECRET_KEY must be configured in production.")

    app.config.from_mapping(
        SECRET_KEY=default_secret or "local-development-key-change-before-deployment",
        DATABASE=os.path.join(app.instance_path, "trustvault.sqlite3"),
        UPLOAD_FOLDER=os.path.join(app.instance_path, "uploads"),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024 + 64 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=production or os.environ.get("TRUSTVAULT_COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        TRUSTVAULT_ENV="production" if production else "development",
        SEED_DEMO_USERS=os.environ.get("TRUSTVAULT_SEED_DEMO_USERS", "1").lower() not in {
            "0", "false", "no",
        },
        TRUSTVAULT_ADMIN_PASSWORD=os.environ.get("TRUSTVAULT_ADMIN_PASSWORD"),
        TRUSTVAULT_OWNER_PASSWORD=os.environ.get("TRUSTVAULT_OWNER_PASSWORD"),
        TRUSTVAULT_VIEWER_PASSWORD=os.environ.get("TRUSTVAULT_VIEWER_PASSWORD"),
        WTF_CSRF_TIME_LIMIT=3600,
    )
    if test_config:
        app.config.update(test_config)
    if app.config["TRUSTVAULT_ENV"] == "production":
        if not app.config["SECRET_KEY"] or app.config["SECRET_KEY"] == "local-development-key-change-before-deployment":
            raise RuntimeError("SECRET_KEY must be configured in production.")
        app.config["SESSION_COOKIE_SECURE"] = True
        if os.environ.get("RATELIMIT_STORAGE_URI", "memory://").startswith("memory://"):
            raise RuntimeError("Production requires a shared rate-limit store via RATELIMIT_STORAGE_URI.")
        missing = [
            key for key in (
                "TRUSTVAULT_ADMIN_PASSWORD",
                "TRUSTVAULT_OWNER_PASSWORD",
                "TRUSTVAULT_VIEWER_PASSWORD",
            ) if not app.config.get(key)
        ]
        if app.config["SEED_DEMO_USERS"] and missing:
            raise RuntimeError("Production demo-account passwords must be configured: " + ", ".join(missing))

    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    csrf.init_app(app)
    limiter.init_app(app)
    init_db(app)
    with app.app_context():
        initialize_db()
    from .db import register_cli
    register_cli(app)

    from .auth import bp as auth_bp
    from .documents import bp as documents_bp
    from .admin import bp as admin_bp
    from .views import bp as views_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(views_bp)

    @app.before_request
    def enforce_password_change():
        from flask import g, session
        from .db import get_db

        user_id = session.get("user_id")
        g.current_user = None
        if user_id is not None:
            g.current_user = get_db().execute(
                "SELECT id, username, role, active, password_change_required FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if g.current_user is None or not g.current_user["active"]:
                session.clear()
                g.current_user = None
            elif g.current_user["password_change_required"] and request.endpoint not in {
                "auth.change_password", "auth.logout", "static"
            }:
                return redirect(url_for("auth.change_password"))

    @app.context_processor
    def inject_user():
        from flask import g
        return {"current_user": getattr(g, "current_user", None)}

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'",
        )
        if request.endpoint != "static":
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.errorhandler(CSRFError)
    def csrf_error(error):
        return "Your form expired or was invalid. Please go back and try again.", 400

    @app.errorhandler(403)
    def forbidden(error):
        from flask import render_template
        return render_template(
            "error.html", title="Access denied",
            message="You do not have permission to perform this action.",
            status=403,
        ), 403

    @app.errorhandler(404)
    def not_found(error):
        from flask import render_template
        return render_template(
            "error.html", title="Document unavailable",
            message="This page or document is unavailable. It may have been removed or you may not have access.",
            status=404,
        ), 404

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(error):
        if request.endpoint == "documents.create":
            from .audit import record_event
            from .db import get_db
            from flask import g

            user = getattr(g, "current_user", None)
            record_event(
                user["id"] if user is not None else None,
                "document_upload", outcome="failure",
                context={"reason": "request_too_large"},
            )
            get_db().commit()
        return "That file exceeds the 10 MB upload limit.", 413

    @app.errorhandler(TooManyRequests)
    def too_many_requests(error):
        from .audit import record_event
        from .db import get_db

        record_event(
            None, "login_rate_limited", outcome="denied",
            context={"username": request.form.get("username", "")[:40]},
        )
        get_db().commit()
        return "Too many sign-in attempts. Please wait a minute before trying again.", 429

    return app
