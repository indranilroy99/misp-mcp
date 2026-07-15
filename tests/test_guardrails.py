"""Tests for the write guardrails and expanded IOC types."""

import asyncio
import json
import os

os.environ.setdefault("MISP_URL", "https://misp.example.org")
os.environ.setdefault("MISP_API_KEY", "test-key")
os.environ.setdefault("MISP_SUBMISSION_EVENT_ID", "1")

from misp_mcp import server  # noqa: E402
from misp_mcp.client import MispClient  # noqa: E402
from misp_mcp.config import load_config  # noqa: E402
from misp_mcp.validators import (  # noqa: E402
    classify_ioc,
    is_protected,
    is_public_ip,
    normalize_ioc,
)


def _run(coro):
    return asyncio.run(coro)


def _writable_client():
    """A MispClient whose add_attribute/attach_tag/whoami succeed."""
    c = MispClient(load_config())

    async def add_attribute(**kw):
        return {"id": "1", "uuid": "u-1"}

    async def attach_tag(uuid, tag):
        return True

    async def whoami():
        return {"email": "sec@example.org", "org": "Example Security"}

    c.add_attribute = add_attribute
    c.attach_tag = attach_tag
    c.whoami = whoami
    return c


def _submit(**kw):
    base = dict(
        justification="seen in phishing", reporter="a@b.com",
        last_seen="2026-07-13", tags=["tlp:clear"], to_ids=False,
    )
    base.update(kw)
    return _run(server.misp_submit_ioc(server.SubmitIocInput(**base)))


# --- expanded IOC classification ----------------------------------------

def test_classify_email():
    assert classify_ioc("attacker@evil.com") == "email"


def test_classify_ipv6():
    assert classify_ioc("2001:db8::1") == "ipv6"


def test_classify_ipv6_full():
    assert classify_ioc("2606:4700:4700::1111") == "ipv6"


def test_url_not_misread_as_ipv6():
    # URLs contain a colon but must still classify as url, not ipv6.
    assert classify_ioc("http://evil.com/path") == "url"


def test_domain_still_domain():
    assert classify_ioc("evil.com") == "domain"


def test_email_domain_is_a_domain():
    # A bare email *domain* is a domain, not an email address.
    assert classify_ioc("evil.com") == "domain"


def test_garbage_with_colon_rejected():
    assert classify_ioc("nothexbut:colons") is None


def test_refang_still_works():
    assert normalize_ioc("evil[.]com") == "evil.com"


# --- public/private IP (v4 + v6) ----------------------------------------

def test_ipv6_link_local_rejected():
    assert is_public_ip("fe80::1") is False


def test_ipv6_global_accepted():
    assert is_public_ip("2606:4700:4700::1111") is True


def test_ipv4_private_rejected():
    assert is_public_ip("10.0.0.1") is False


# --- protected safelist -------------------------------------------------

def test_protected_public_resolver():
    assert is_protected("8.8.8.8", "ipv4") is True


def test_protected_domain_exact():
    assert is_protected("github.com", "domain") is True


def test_protected_domain_subdomain():
    assert is_protected("api.github.com", "domain") is True


def test_protected_url_host():
    assert is_protected("https://accounts.google.com/login", "url") is True


def test_protected_email_domain():
    assert is_protected("someone@gmail.com", "email") is True


def test_protected_first_party_via_env():
    # Deployments add their own domains through MISP_MCP_PROTECTED_DOMAINS.
    assert is_protected("pay.acme.com", "domain", {"acme.com"}) is True


def test_protected_extra_domain_from_config():
    assert is_protected("host.acme.internal", "domain", {"acme.internal"}) is True


def test_normal_indicator_not_protected():
    assert is_protected("evil.com", "domain") is False
    assert is_protected("203.0.113.5", "ipv4") is False


# --- safelist bypass attempts (must all be caught) ----------------------

def test_protected_ip_wrapped_in_url():
    assert is_protected("http://8.8.8.8/", "url") is True


def test_protected_domain_trailing_dot():
    assert is_protected("http://google.com./", "url") is True


def test_protected_ipv6_resolver():
    assert is_protected("2606:4700:4700::1111", "ipv6") is True


def test_protected_ipv6_uncompressed_variant():
    # Same Google resolver, written without zero-compression.
    assert is_protected("2001:4860:4860:0:0:0:0:8888", "ipv6") is True


def test_protected_ipv6_bracketed_in_url():
    assert is_protected("http://[2606:4700:4700::1111]/x", "url") is True


# --- tool-level guardrails ----------------------------------------------

def test_submit_blocks_protected_indicator():
    server._get_client = lambda: _writable_client()
    out = _submit(ioc="8.8.8.8")
    assert out.startswith("Error:") and "protected safelist" in out
    assert '"submitted": true' not in out  # never reached the write


def test_submit_stamps_verified_identity_over_claim():
    server._get_client = lambda: _writable_client()
    out = json.loads(_submit(ioc="evil-domain.test", reporter="intern@example.org"))
    assert out["submitted"] is True
    assert out["submitted_by"] == "sec@example.org"       # from MISP
    assert out["reporter_claimed"] == "intern@example.org"  # self-asserted


def test_submit_blocks_url_wrapped_protected_ip():
    server._get_client = lambda: _writable_client()
    out = _submit(ioc="http://8.8.8.8/")
    assert out.startswith("Error:") and "protected safelist" in out


def test_submit_rejects_private_ip_url_host():
    server._get_client = lambda: _writable_client()
    out = _submit(ioc="http://169.254.169.254/latest/meta-data/")
    assert out.startswith("Error:") and "private/reserved" in out


def test_log_sanitizer_strips_crlf():
    from misp_mcp.http_app import _sanitize
    assert _sanitize("alice@example.org\r\nINJECTED admin=true") == \
        "alice@example.orgINJECTED admin=true"
    assert "\n" not in _sanitize("a\nb") and "\r" not in _sanitize("a\rb")


def test_submit_rate_limit_kicks_in():
    server._get_client = lambda: _writable_client()
    server._submit_times.clear()
    # Drive well past the per-minute cap; some must be refused.
    outs = [_submit(ioc="evil-domain.test") for _ in range(server.submit_rate_per_min() + 5)]
    assert any("rate limit" in o for o in outs)
    server._submit_times.clear()
