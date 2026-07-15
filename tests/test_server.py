"""Offline test suite for misp-mcp. No network or live MISP required —
the MISP client is mocked. Run:  python tests/test_server.py

Covers: IOC validation/refang, TLP fail-closed redaction (the security
core), concurrency/dedup, defensive handling of malformed API responses,
the batch tool's partial-failure behavior, and error-message mapping.
Live behavior against a real MISP still needs a manual smoke test with a
personal key (see README) — that is the one thing mocks cannot prove.
"""

import asyncio
import json
import os
import sys

import httpx

os.environ.setdefault("MISP_URL", "https://misp.example.org")
os.environ.setdefault("MISP_API_KEY", "test-key")
os.environ.setdefault("MISP_SUBMISSION_EVENT_ID", "1")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from misp_mcp import server  # noqa: E402
from misp_mcp.client import MispClient  # noqa: E402
from misp_mcp.config import load_config  # noqa: E402
from misp_mcp.validators import classify_ioc, is_public_ip, normalize_ioc  # noqa: E402

PUBLIC_EVENT = {
    "id": "16989", "info": "Tor exit nodes feed", "date": "2024-10-24",
    "threat_level_id": "4", "Orgc": {"name": "Example CERT"}, "Tag": [{"name": "osint"}],
    "Attribute": [{"type": "ip-dst", "value": "102.130.113.9",
                   "category": "Network activity", "to_ids": True}],
}
RESTRICTED_EVENT = {
    "id": "35476", "info": "Partner amber feed", "date": "2026-07-08",
    "threat_level_id": "2", "Orgc": {"name": "Partner ISAC"}, "Tag": [{"name": "tlp:amber"}],
    "Attribute": [{"type": "domain", "value": "secret.example",
                   "category": "Network activity", "to_ids": True}],
}


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


def _fake_client(get=None, post=None):
    c = MispClient(load_config())

    # Intercept at the single request seam that _request() uses, so the
    # retry/backoff wrapper is exercised too. Dispatch by HTTP method.
    async def _request(method, path, *a, **k):
        return FakeResponse(get if method.upper() == "GET" else post)

    c._client.request = _request
    return c


def run(coro):
    return asyncio.run(coro)


def test_validators():
    assert normalize_ioc("1.2.3[.]4") == "1.2.3.4"
    assert normalize_ioc("hxxps://evil[.]com/x") == "https://evil.com/x"
    assert normalize_ioc("D41D8CD98F00B204E9800998ECF8427E") == "d41d8cd98f00b204e9800998ecf8427e"
    assert classify_ioc("8.8.8.8") == "ipv4"
    assert classify_ioc("999.1.1.1") is None
    assert classify_ioc("evil.example.com") == "domain"
    assert not is_public_ip("10.0.0.1") and is_public_ip("8.8.8.8")


def test_tools_registered():
    tools = run(server.mcp.list_tools())
    by = {t.name: t for t in tools}
    assert set(by) == {
        "misp_lookup_ioc", "misp_lookup_iocs", "misp_correlate_ioc",
        "misp_get_event", "misp_search_events", "misp_feed_stats",
        "misp_instance_status", "misp_review_submissions",
        "misp_submit_ioc", "misp_submit_iocs",
    }, sorted(by)
    # All read tools are read-only; only the submit tools write. Nothing destructive.
    write_tools = {"misp_submit_ioc", "misp_submit_iocs"}
    read_tools = [n for n in by if n not in write_tools]
    assert all(by[n].annotations.readOnlyHint for n in read_tools)
    assert all(by[n].annotations.readOnlyHint is False for n in write_tools)
    assert all(not t.annotations.destructiveHint for t in tools)


def test_submit_ioc_adds_and_tags():
    c = _fake_client()
    added = {}

    async def add_attribute(**kw):
        added.update(kw)
        return {"id": "999", "uuid": "u-123"}

    tag_calls = []

    async def attach_tag(uuid, tag):
        tag_calls.append((uuid, tag))
        return tag != "bad:tag"  # simulate one tag failing

    c.add_attribute = add_attribute
    c.attach_tag = attach_tag
    server._get_client = lambda: c

    out = json.loads(run(server.misp_submit_ioc(server.SubmitIocInput(
        ioc="evil.example.com", justification="seen in phishing",
        reporter="analyst@example.org", last_seen="2026-07-13",
        tags=["tlp:amber", "bad:tag"], to_ids=False))))

    assert out["submitted"] is True and out["type"] == "domain"
    assert out["tags_applied"] == ["tlp:amber"] and out["tags_failed"] == ["bad:tag"]
    assert added["attr_type"] == "domain" and added["category"] == "Network activity"
    assert added["to_ids"] is False and added["last_seen"] == "2026-07-13"
    assert "reporter_claimed=analyst@example.org" in added["comment"] and "phishing" in added["comment"]
    assert "submitted_by=" in added["comment"]  # verified identity stamped in
    # hash -> Payload delivery category
    out2 = json.loads(run(server.misp_submit_ioc(server.SubmitIocInput(
        ioc="d41d8cd98f00b204e9800998ecf8427e", justification="x",
        reporter="k@example.org", last_seen="2026-07-13", tags=["tlp:clear"], to_ids=True))))
    assert out2["type"] == "md5" and added["category"] == "Payload delivery"


def test_submit_ioc_requires_all_fields():
    import pydantic
    # missing tags / bad email / bad date -> validation error before any call
    for bad in [
        dict(ioc="8.8.8.8", justification="x", reporter="a@b.com", last_seen="2026-07-13", to_ids=False),  # no tags
        dict(ioc="8.8.8.8", justification="x", reporter="not-an-email", last_seen="2026-07-13", tags=["t"], to_ids=False),
        dict(ioc="8.8.8.8", justification="x", reporter="a@b.com", last_seen="13-07-2026", tags=["t"], to_ids=False),
        dict(ioc="8.8.8.8", justification="x", reporter="a@b.com", last_seen="2026-07-13", tags=[], to_ids=False),  # empty tags
    ]:
        try:
            server.SubmitIocInput(**bad)
            raise AssertionError(f"should have rejected: {bad}")
        except pydantic.ValidationError:
            pass


def test_submit_ioc_rejects_invalid_and_maps_write_error():
    c = _fake_client()
    server._get_client = lambda: c
    # invalid IOC blocked before any write
    out = run(server.misp_submit_ioc(server.SubmitIocInput(
        ioc="garbage!!", justification="x", reporter="a@b.com",
        last_seen="2026-07-13", tags=["tlp:clear"], to_ids=False)))
    assert "not a recognized IOC" in out

    # a 403 from MISP (read-only key) -> actionable message
    async def add_attribute(**kw):
        r = httpx.Response(403, request=httpx.Request("POST", "https://x"))
        raise httpx.HTTPStatusError("forbidden", request=r.request, response=r)

    c.add_attribute = add_attribute
    out = run(server.misp_submit_ioc(server.SubmitIocInput(
        ioc="45.9.148.1", justification="x", reporter="a@b.com",
        last_seen="2026-07-13", tags=["tlp:clear"], to_ids=False)))
    assert "rejected your API key" in out or "403" in out


def test_submit_iocs_dry_run_previews_without_writing():
    c = _fake_client()
    added = []

    async def add_attribute(**kw):
        added.append(kw)
        return {"id": "1", "uuid": "u"}

    c.add_attribute = add_attribute
    server._get_client = lambda: c
    out = json.loads(run(server.misp_submit_iocs(server.SubmitIocsInput(
        iocs=["evil-a.com", "8.8.8.8", "10.0.0.1", "evil-a.com", "garbage!!"],
        reporter="a@b.com", justification="report", last_seen="2026-07-14",
        tags=["tlp:clear"], to_ids=False))))  # dry_run defaults True
    assert out["dry_run"] is True and added == []            # nothing written
    st = {r["ioc"]: r["status"] for r in out["results"]}
    assert st["evil-a.com"] == "would_add"                   # first occurrence
    assert st["8.8.8.8"] == "protected"                      # safelist
    assert st["10.0.0.1"] == "rejected"                      # private IP
    assert st["garbage!!"] == "rejected"                     # not an IOC
    assert out["counts"].get("duplicate_in_batch") == 1      # second evil-a.com


def test_submit_iocs_adds_when_not_dry_run():
    c = _fake_client()
    added = []

    async def add_attribute(**kw):
        added.append(kw["value"])
        return {"id": "9", "uuid": "u-9"}

    async def attach_tag(uuid, tag):
        return True

    async def whoami():
        return {"email": "sec@example.org", "org": "Example"}

    c.add_attribute = add_attribute
    c.attach_tag = attach_tag
    c.whoami = whoami
    server._get_client = lambda: c
    server._submit_times.clear()
    out = json.loads(run(server.misp_submit_iocs(server.SubmitIocsInput(
        iocs=["evil-b.com", "evil-c.com"], reporter="a@b.com",
        justification="report", last_seen="2026-07-14", tags=["tlp:clear"],
        to_ids=False, dry_run=False))))
    assert out["dry_run"] is False and out["submitted_by"] == "sec@example.org"
    assert out["counts"].get("added") == 2 and set(added) == {"evil-b.com", "evil-c.com"}
    server._submit_times.clear()


def test_review_submissions_parses_filters_and_counts():
    attrs = {"response": {"Attribute": [
        {"id": "1", "type": "domain", "value": "a.com", "category": "Network activity",
         "to_ids": True, "timestamp": "1700000000",
         "comment": "submitted_by=alice@x; reporter_claimed=bob@x; justification=phish"},
        {"id": "2", "type": "ip-dst", "value": "1.2.3.4", "category": "Network activity",
         "to_ids": False, "timestamp": "1700000100",
         "comment": "submitted_by=alice@x; reporter_claimed=alice@x; justification=test"},
        {"id": "3", "type": "domain", "value": "ui.com", "category": "Network activity",
         "to_ids": False, "timestamp": "1700000200", "comment": "added directly in the UI"},
    ]}}
    c = _fake_client(post=attrs)
    server._get_client = lambda: c

    out = json.loads(run(server.misp_review_submissions(server.ReviewSubmissionsInput())))
    assert out["total"] == 3 and out["detection_flagged"] == 1
    assert out["by_submitter"].get("alice@x") == 2 and out["by_submitter"].get("unknown") == 1
    # newest first
    assert out["submissions"][0]["value"] == "ui.com"

    out2 = json.loads(run(server.misp_review_submissions(
        server.ReviewSubmissionsInput(submitted_by="bob@x"))))
    assert out2["total"] == 1 and out2["submissions"][0]["value"] == "a.com"

    out3 = json.loads(run(server.misp_review_submissions(
        server.ReviewSubmissionsInput(only_to_ids=True))))
    assert out3["total"] == 1 and out3["submissions"][0]["to_ids"] is True


def test_events_by_id_dedupes_and_skips_none():
    c = _fake_client()
    calls = []

    async def fake_get_event(eid):
        calls.append(eid)
        return {"id": eid, "Tag": []}

    c.get_event = fake_get_event
    res = run(c._events_by_id(["1", "1", "2", None, "2", "3"]))
    assert set(res) == {"1", "2", "3"}
    assert calls.count("1") == 1


def test_malformed_api_responses_do_not_crash():
    c = _fake_client(get={"errors": "nope"}, post={"errors": "nope"})
    assert run(c.feeds()) == []
    assert run(c.search_events(keyword="x")) == []
    c2 = _fake_client(post={"response": {}})
    assert run(c2.search_attributes("8.8.8.8")) == []


def test_show_all_skips_event_fetch():
    """Default (show_restricted=True): search_attributes returns everything
    and does NOT do the per-event tag fetch (1 request, not 1+N)."""
    c = _fake_client(post={"response": {"Attribute": [
        {"event_id": "1", "value": "8.8.8.8"},
        {"event_id": "2", "value": "8.8.8.8"},
    ]}})
    c.show_restricted = True
    fetched = []

    async def spy(eid):
        fetched.append(eid)
        return {"Tag": []}

    c.get_event = spy
    attrs = run(c.search_attributes("8.8.8.8"))
    assert len(attrs) == 2 and all(a["is_restricted"] is False for a in attrs)
    assert fetched == [], "should not fetch any events when showing all"


def test_lookup_redacts_restricted_by_default():
    fake = _fake_client()

    async def sa(value, limit=20):
        return [
            {"event_id": "1", "type": "ip-dst", "value": "8.8.8.8",
             "category": "Network activity", "to_ids": True,
             "Event": {"info": "Public"}, "is_restricted": False},
            {"event_id": "2", "type": "domain", "value": "secret.example",
             "Event": {"info": "Partner amber feed"}, "is_restricted": True},
        ]

    fake.search_attributes = sa
    fake.show_restricted = False
    server._get_client = lambda: fake
    out = json.loads(run(server.misp_lookup_ioc(server.IocInput(ioc="8.8.8.8"))))
    assert out["total_hits"] == 2
    assert out["hits"][0]["value"] == "8.8.8.8"
    assert out["hits"][1] == {"event_id": "2", "restricted": True, "note": server.REDACTION_NOTE}
    assert "secret.example" not in json.dumps(out)


def test_lookup_rejects_invalid_and_private_iocs():
    _c = _fake_client()
    server._get_client = lambda: _c
    out = run(server.misp_lookup_ioc(server.IocInput(ioc="not_an_ioc!!")))
    assert out.startswith("Error:") and "not a recognized IOC" in out
    out = run(server.misp_lookup_ioc(server.IocInput(ioc="192.168.1.1")))
    assert "private/reserved" in out


def test_get_event_redaction_and_detail():
    c = _fake_client()
    c.show_restricted = False
    server._get_client = lambda: c

    async def gv(eid):
        return {"35476": RESTRICTED_EVENT, "16989": PUBLIC_EVENT}.get(eid)

    c.get_event = gv
    redacted = json.loads(run(server.misp_get_event(server.EventInput(event_id="35476"))))
    assert redacted == {"id": "35476", "restricted": True, "note": server.REDACTION_NOTE}
    assert "secret.example" not in json.dumps(redacted)

    full = json.loads(run(server.misp_get_event(server.EventInput(event_id="16989"))))
    assert full["info"] == "Tor exit nodes feed"
    assert full["creator_org"] == "Example CERT"
    assert full["attributes"][0]["value"] == "102.130.113.9"

    async def none(eid):
        return None

    c.get_event = none
    assert "not found" in run(server.misp_get_event(server.EventInput(event_id="99999")))


def test_get_event_opt_in_reveals_detail():
    c = _fake_client()
    c.show_restricted = True

    async def gv(eid):
        return RESTRICTED_EVENT

    c.get_event = gv
    server._get_client = lambda: c
    out = json.loads(run(server.misp_get_event(server.EventInput(event_id="35476"))))
    assert out["attributes"][0]["value"] == "secret.example"


def test_search_events_redaction_and_filter_requirement():
    fake = _fake_client()
    fake.show_restricted = False

    async def se(**kwargs):
        return [
            {"Event": {"id": "35476"}, "is_restricted": True},
            {"Event": {"id": "16989", "info": "Tor exit nodes feed",
                       "date": "2024-10-24", "attribute_count": 2229},
             "is_restricted": False},
        ]

    fake.search_events = se
    server._get_client = lambda: fake
    out = json.loads(run(server.misp_search_events(server.EventSearchInput(keyword="tor"))))
    assert out["events"][0] == {"id": "35476", "restricted": True}
    assert out["events"][1]["info"] == "Tor exit nodes feed"
    assert "at least one filter" in run(server.misp_search_events(server.EventSearchInput()))


def test_batch_partial_failure_isolation():
    fake = _fake_client()
    fake.show_restricted = False

    async def sa(value, limit=5):
        if value == "8.8.8.8":
            return [{"event_id": "10", "is_restricted": False}]
        if value == "evil.com":
            return [{"event_id": "20", "is_restricted": True},
                    {"event_id": "21", "is_restricted": False}]
        return []

    fake.search_attributes = sa
    server._get_client = lambda: fake
    out = json.loads(run(server.misp_lookup_iocs(
        server.BatchIocInput(iocs=["8.8.8.8", "evil.com", "1.1.1.1", "garbage!!", "10.0.0.1"]))))
    by = {r["ioc"]: r for r in out["results"]}
    assert by["8.8.8.8"]["total_hits"] == 1 and by["8.8.8.8"]["has_restricted_hits"] is False
    assert by["evil.com"]["has_restricted_hits"] is True
    assert by["evil.com"]["top_event_ids"] == ["20", "21"]
    assert by["1.1.1.1"]["total_hits"] == 0
    assert "error" in by["garbage!!"] and "error" in by["10.0.0.1"]


def test_error_messages_are_actionable():
    assert "cannot reach MISP" in server._error(httpx.ConnectError("x"))
    r = httpx.Response(403, request=httpx.Request("GET", "https://x"))
    assert "Read Only" in server._error(httpx.HTTPStatusError("x", request=r.request, response=r))
    assert "timed out" in server._error(httpx.TimeoutException("x"))


def test_request_retries_transient_then_succeeds():
    """A transient ConnectError is retried and can succeed; a 4xx is not
    retried (raised immediately)."""
    client = MispClient(load_config())
    calls = {"n": 0}

    class _Resp:
        def raise_for_status(self):
            pass

    async def flaky(method, path, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("transient")
        return _Resp()

    client._client.request = flaky
    resp = asyncio.run(client._request("GET", "/x"))
    assert calls["n"] == 2 and resp is not None  # retried once, then ok

    # 4xx raises immediately, no retry
    calls["n"] = 0

    async def hard_fail(method, path, **kw):
        calls["n"] += 1
        r = httpx.Response(404, request=httpx.Request(method, "https://x"))
        raise httpx.HTTPStatusError("nf", request=r.request, response=r)

    client._client.request = hard_fail
    try:
        asyncio.run(client._request("GET", "/x"))
        raise AssertionError("should have raised")
    except httpx.HTTPStatusError:
        assert calls["n"] == 1  # not retried


def test_server_config_transport_default():
    """stdio is default; http/host/port read from env. No shared tokens
    anymore — per-user MISP key is the credential."""
    from misp_mcp.config import load_server_config

    for k in ("MCP_TRANSPORT", "MCP_HOST", "MCP_PORT"):
        os.environ.pop(k, None)
    assert load_server_config().transport == "stdio"

    os.environ["MCP_TRANSPORT"] = "http"
    os.environ["MCP_PORT"] = "9001"
    cfg = load_server_config()
    assert cfg.transport == "http" and cfg.port == 9001
    for k in ("MCP_TRANSPORT", "MCP_PORT"):
        os.environ.pop(k, None)


def test_misp_key_auth_middleware():
    """Pure-ASGI gate: healthz open; missing X-MISP-Key -> 401; a present
    key -> passthrough with identity stashed in the context var."""
    from misp_mcp.http_app import MispKeyAuthMiddleware
    from misp_mcp.context import current_misp_key, current_user

    seen = {}

    async def downstream(scope, receive, send):
        seen["key"] = current_misp_key.get()
        seen["user"] = current_user.get()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = MispKeyAuthMiddleware(downstream)

    async def call(path, headers):
        sent = []
        scope = {"type": "http", "path": path, "headers": headers or []}

        async def send(m):
            sent.append(m)

        async def receive():
            return {"type": "http.request", "body": b""}

        await mw(scope, receive, send)
        return sent[0]["status"]

    assert run(call("/healthz", None)) == 200  # open
    assert run(call("/mcp", None)) == 401  # no key header
    assert run(call("/mcp", [(b"x-misp-key", b"")])) == 401  # empty key
    status = run(call("/mcp", [(b"x-misp-key", b"KEY-abc"), (b"x-misp-user", b"a@x.com")]))
    assert status == 200 and seen["key"] == "KEY-abc" and seen["user"] == "a@x.com"


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
