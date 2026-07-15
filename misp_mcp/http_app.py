"""Authenticated HTTP transport for hosting the MISP MCP server (e.g. on a
cloud VM), for org-wide per-user access with a per-request key model.

Identity model:
- Each request carries the caller's OWN MISP API key in `X-MISP-Key`
  (and optionally `X-MISP-User: <email>` for audit). The MISP key is the
  credential: MISP validates it on the actual call and attributes the
  query to that user. There is no shared key on the server.
- Requests without `X-MISP-Key` are rejected 401 before any tool runs.
- Host privately, security-group-locked (do not expose to the internet);
  the header credential is defense-in-depth on top of network isolation.
- Pure-ASGI middleware (not BaseHTTPMiddleware) so it never breaks the
  streaming MCP transport. It stashes identity in context vars that the
  tools read to build a per-request MISP client.
"""

import logging

import uvicorn

from .config import ServerConfig, allow_insecure_bind, tls_cert, tls_key
from .context import current_misp_key, current_user

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}

logger = logging.getLogger("misp_mcp")

HEALTH_PATH = "/healthz"
KEY_HEADER = b"x-misp-key"
USER_HEADER = b"x-misp-user"


def _sanitize(value: str, limit: int = 128) -> str:
    """Strip control characters (CR/LF included) and cap length, so an
    attacker-supplied header can't forge or flood log lines."""
    return "".join(c for c in value.strip() if c.isprintable())[:limit]


class MispKeyAuthMiddleware:
    """Require a per-user MISP key header; stash identity for the tools.
    HEALTH_PATH stays open for load-balancer checks."""

    def __init__(self, app):
        self._app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path == HEALTH_PATH:
            await self._send_json(send, 200, b'{"status":"ok"}')
            return

        headers = dict(scope.get("headers") or [])
        key = headers.get(KEY_HEADER, b"").decode(errors="ignore").strip()
        user = _sanitize(headers.get(USER_HEADER, b"").decode(errors="ignore")) or "unknown"
        log_path = _sanitize(path)
        if not key:
            logger.warning("auth rejected (no X-MISP-Key) user=%s path=%s", user, log_path)
            await self._send_json(
                send, 401,
                b'{"error":"missing X-MISP-Key header (your personal MISP API key)"}',
            )
            return

        # Set on the current context; propagates to the tool coroutine.
        current_misp_key.set(key)
        current_user.set(user)
        logger.info("request user=%s path=%s", user, log_path)
        await self._app(scope, receive, send)

    @staticmethod
    async def _send_json(send, status: int, body: bytes) -> None:
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})


def build_asgi_app(mcp):
    return MispKeyAuthMiddleware(mcp.streamable_http_app())


def run_http(mcp, cfg: ServerConfig) -> None:
    cert, key = tls_cert(), tls_key()
    tls = bool(cert and key)
    loopback = cfg.host in _LOOPBACK

    # X-MISP-Key is a bearer credential. Refuse to serve it over plain HTTP
    # on a non-loopback address unless TLS is configured here, or the
    # operator explicitly acknowledges TLS is terminated upstream (ALB).
    if not loopback and not tls and not allow_insecure_bind():
        raise RuntimeError(
            f"Refusing to bind {cfg.host} over plain HTTP: X-MISP-Key is a "
            "bearer credential. Provide MISP_MCP_TLS_CERT + MISP_MCP_TLS_KEY, "
            "or set MISP_MCP_ALLOW_INSECURE_BIND=true if TLS is terminated by "
            "an internal ALB in front of this process."
        )
    if not loopback and not tls:
        logger.warning(
            "binding %s over plain HTTP (MISP_MCP_ALLOW_INSECURE_BIND=true) - "
            "ensure an internal ALB terminates TLS; keys must never cross the "
            "network in cleartext.", cfg.host,
        )

    logger.info(
        "starting HTTP transport host=%s port=%s tls=%s", cfg.host, cfg.port, tls
    )
    uvicorn.run(
        build_asgi_app(mcp),
        host=cfg.host,
        port=cfg.port,
        log_level="warning",
        ssl_certfile=cert,
        ssl_keyfile=key,
    )
