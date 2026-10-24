import json

from .db import get_db, utcnow


def record_event(actor_id, action, document_id=None, outcome="success", context=None):
    """Write one structured event; never pass secrets, tokens, or document contents."""
    safe_context = context or {}
    encoded = json.dumps(safe_context, separators=(",", ":"), ensure_ascii=True)
    if len(encoded) > 2000:
        encoded = json.dumps({"context_truncated": True})
    get_db().execute(
        """INSERT INTO audit_logs (actor_id, action, document_id, outcome, context, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (actor_id, action, document_id, outcome, encoded, utcnow()),
    )
