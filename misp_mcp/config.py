"""Configuration from environment variables.

Two identity models, by transport:
- stdio (local): the analyst runs the server with their OWN MISP key in
  MISP_API_KEY. One user per process.
- http (hosted): each request carries the caller's own MISP key in the
  X-MISP-Key header (a per-request bearer-credential model). No shared key
  on the server; the MISP key IS the credential, and MISP attributes each
  query to that user.

Server-level settings (URL, TLS, redaction) come from env in both modes;
only the per-user MISP key differs.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ServerConfig:
    """Transport + bind for the server process (distinct from MISP identity)."""
    transport: str  # "stdio" (local, per-analyst) or "http" (hosted, per-user header)
    host: str
    port: int


def load_server_config() -> ServerConfig:
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()
    return ServerConfig(
        transport=transport,
        host=os.environ.get("MCP_HOST", "127.0.0.1"),
        port=int(os.environ.get("MCP_PORT", "8080")),
    )


def server_url() -> str:
    url = os.environ.get("MISP_URL", "").rstrip("/")
    if not url:
        raise RuntimeError("MISP_URL environment variable is required.")
    return url


def verify_tls() -> bool:
    return os.environ.get("MISP_VERIFY_TLS", "true").lower() != "false"


def submission_event_id() -> str:
    """Numeric id of the MISP event that misp_submit_ioc adds indicators to
    (a 'Community IOC Submissions' style event you create once). Required
    for the write tool; set MISP_SUBMISSION_EVENT_ID per deployment."""
    eid = os.environ.get("MISP_SUBMISSION_EVENT_ID", "").strip()
    if not eid:
        raise RuntimeError(
            "MISP_SUBMISSION_EVENT_ID is not set. Create (or choose) a MISP "
            "event for submissions and set its numeric id to enable "
            "misp_submit_ioc."
        )
    return eid


def show_restricted() -> bool:
    # Per-user model: access is governed by each caller's own MISP key, so
    # by default we show everything that key can see (no in-server TLP
    # redaction). Set MISP_MCP_SHOW_RESTRICTED=false to re-enable the
    # compensating redaction (e.g. a shared-key deployment).
    return os.environ.get("MISP_MCP_SHOW_RESTRICTED", "true").lower() != "false"


# --- write guardrail settings -------------------------------------------

def protected_domains_extra() -> set[str]:
    """Deployment-specific domains that must never be submitted as
    indicators, on top of the built-in safelist in validators."""
    raw = os.environ.get("MISP_MCP_PROTECTED_DOMAINS", "")
    return {d.strip().lower() for d in raw.split(",") if d.strip()}


def submit_rate_per_min() -> int:
    """Max IOC submissions allowed per key per minute (bounds a runaway or
    prompt-injected loop). Default 20."""
    try:
        return max(1, int(os.environ.get("MISP_MCP_SUBMIT_RATE", "20")))
    except ValueError:
        return 20


# --- hosted-transport safety --------------------------------------------

def tls_cert() -> str | None:
    return os.environ.get("MISP_MCP_TLS_CERT") or None


def tls_key() -> str | None:
    return os.environ.get("MISP_MCP_TLS_KEY") or None


def allow_insecure_bind() -> bool:
    """Acknowledge that TLS is terminated upstream (e.g. an internal ALB),
    so binding a non-loopback address over plain HTTP is intentional."""
    return os.environ.get("MISP_MCP_ALLOW_INSECURE_BIND", "false").lower() == "true"


@dataclass(frozen=True)
class Config:
    url: str
    api_key: str
    verify_tls: bool
    show_restricted: bool


def config_for_key(api_key: str) -> Config:
    """Build a MISP config for a specific per-user key (server-level URL/
    TLS/redaction from env)."""
    if not api_key:
        raise RuntimeError("No MISP API key supplied.")
    return Config(
        url=server_url(),
        api_key=api_key,
        verify_tls=verify_tls(),
        show_restricted=show_restricted(),
    )


def load_config() -> Config:
    """stdio-mode config: MISP key from env (the local analyst's own key)."""
    api_key = os.environ.get("MISP_API_KEY", "")
    if not api_key:
        raise RuntimeError(
            "MISP_API_KEY environment variable is required for stdio mode. "
            "Set it in your MCP client's server config (the env block)."
        )
    return config_for_key(api_key)
