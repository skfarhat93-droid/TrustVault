import re
from functools import wraps

from flask import abort, flash, g, redirect, url_for


USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,40}$")


def valid_username(username):
    return bool(USERNAME_RE.fullmatch(username or ""))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if getattr(g, "current_user", None) is None:
            flash("Please sign in to continue.", "info")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorate(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.current_user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorate
