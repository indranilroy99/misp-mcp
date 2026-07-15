"""Per-request identity, carried from the HTTP auth middleware to the
tools via context variables (proven to propagate across the streamable-
HTTP request-to-tool hop). Empty in stdio mode, where identity comes from
env instead.
"""

import contextvars

# The caller's own MISP API key for this request (http mode).
current_misp_key: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_misp_key", default=""
)
# The caller's identity for audit logs (from X-MISP-User; best-effort).
current_user: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_user", default="unknown"
)
