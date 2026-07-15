"""IOC validation, normalization, and submission guardrails.

Analysts routinely paste defanged indicators (1.2.3[.]4,
hxxp://evil[.]com), so inputs are refanged before validation. Anything
that doesn't match a known IOC shape is rejected before it reaches the
MISP API.

is_protected() is a write guardrail: it refuses to let first-party or
critical shared infrastructure (public DNS resolvers, our own domains,
big providers) be submitted as a malicious indicator. That blocks the
"mark our own infra malicious" poisoning path, especially when a request
is driven by prompt-injected content.
"""

import ipaddress
import re

# Order matters: hashes before domain so hex strings don't match as domains.
_IOC_PATTERNS = [
    ("sha256", re.compile(r"^[a-f0-9]{64}$", re.I)),
    ("sha1", re.compile(r"^[a-f0-9]{40}$", re.I)),
    ("md5", re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("ipv4", re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")),
    ("email", re.compile(r"^[a-z0-9._%+\-]+@(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)),
    ("url", re.compile(r"^https?://[\w.\-~:/?#\[\]@!$&'()*+,;=%]+$", re.I)),
    ("domain", re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)),
]

# IPv6 looks like nothing else (only hex + colons, and at least one colon),
# so detect it by parsing rather than a brittle regex. URLs contain a colon
# too, but also a slash / letters outside a-f, so this candidate filter keeps
# them out.
_IPV6_CANDIDATE = re.compile(r"^[0-9a-f:]+$", re.I)

# Analyst defanging, undone before validation. Order matters (hxxps first).
_REFANG = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", re.I), "."),
    (re.compile(r"hxxps", re.I), "https"),
    (re.compile(r"hxxp", re.I), "http"),
]

_HASH_TYPES = {"md5", "sha1", "sha256"}
_IP_TYPES = {"ipv4", "ipv6"}

# --- protected safelist (write guardrail) -------------------------------
# Never let these be submitted as indicators: public DNS resolvers and
# large, widely-trusted providers, so a poisoned submission can't flag
# critical infrastructure for detection/blocking. IPs are stored normalized
# so textual variants (IPv6 zero-compression) still match.
_PROTECTED_IPS_RAW = {
    "8.8.8.8", "8.8.4.4",                             # Google DNS
    "1.1.1.1", "1.0.0.1",                             # Cloudflare DNS
    "9.9.9.9", "149.112.112.112",                     # Quad9
    "208.67.222.222", "208.67.220.220",               # OpenDNS
    "2001:4860:4860::8888", "2001:4860:4860::8844",   # Google DNS (v6)
    "2606:4700:4700::1111", "2606:4700:4700::1001",   # Cloudflare DNS (v6)
    "2620:fe::fe", "2620:fe::9",                       # Quad9 (v6)
}

# Large, widely-trusted providers. Add your own first-party domains with
# MISP_MCP_PROTECTED_DOMAINS so they can never be flagged either.
_PROTECTED_DOMAINS = {
    "google.com", "gmail.com", "googleapis.com",
    "microsoft.com", "office365.com", "outlook.com", "live.com",
    "amazonaws.com", "cloudflare.com", "akamai.net", "fastly.net",
    "apple.com", "github.com",
}


def _norm_ip(value: str) -> str | None:
    """Canonical text form of an IP address, or None if not an IP."""
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return None


_PROTECTED_IPS = {_norm_ip(ip) or ip for ip in _PROTECTED_IPS_RAW}


def normalize_ioc(value: str) -> str:
    """Refang a possibly-defanged indicator and normalize hash case."""
    value = value.strip()
    for pattern, repl in _REFANG:
        value = pattern.sub(repl, value)
    if classify_ioc(value) in _HASH_TYPES:
        value = value.lower()
    return value


def classify_ioc(value: str) -> str | None:
    """Return the IOC type, or None if the value matches no accepted shape.

    Types: ipv4, ipv6, domain, url, email, md5, sha1, sha256.
    """
    if ":" in value and _IPV6_CANDIDATE.match(value):
        try:
            ipaddress.IPv6Address(value)
            return "ipv6"
        except ValueError:
            return None
    for ioc_type, pattern in _IOC_PATTERNS:
        if pattern.match(value):
            return ioc_type
    return None


def is_public_ip(value: str) -> bool:
    """True if the value is a globally routable IP (v4 or v6). A private,
    reserved, loopback, or link-local address returns False. A value that
    is not an IP at all returns True (the check does not apply)."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return True


def _strip_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")          # trailing dot: google.com.
    if host.startswith("[") and "]" in host:         # bracketed IPv6 in a URL
        host = host[1:host.index("]")]
    return host


def host_of(value: str, ioc_type: str) -> str:
    """The host/domain part of an indicator, lowercased and de-dotted."""
    if ioc_type == "url":
        m = re.match(r"^https?://(\[[^\]]+\]|[^/:?#]+)", value, re.I)
        return _strip_host(m.group(1)) if m else ""
    if ioc_type == "email":
        return _strip_host(value.rsplit("@", 1)[-1])
    return _strip_host(value)


def _domain_protected(host: str, extra_domains) -> bool:
    if not host:
        return False
    for d in _PROTECTED_DOMAINS.union(extra_domains):
        if host == d or host.endswith("." + d):
            return True
    return False


def is_protected(value: str, ioc_type: str, extra_domains=()) -> bool:
    """True if this indicator is well-known or first-party infrastructure
    that must never be submitted as malicious. Handles the value wrapped as
    a URL or email host, IPv6, and trailing-dot forms so the safelist can't
    be side-stepped. extra_domains lets a deployment add its own protected
    domains (MISP_MCP_PROTECTED_DOMAINS)."""
    if ioc_type in _IP_TYPES:
        return (_norm_ip(value) or "") in _PROTECTED_IPS
    if ioc_type in ("domain", "url", "email"):
        host = host_of(value, ioc_type)
        norm = _norm_ip(host)
        if norm is not None:                          # host is an IP literal
            return norm in _PROTECTED_IPS
        return _domain_protected(host, extra_domains)
    return False
