#!/usr/bin/env python3
"""End-to-end live smoke test — exercises the read tools against a REAL
MISP instance. Unlike tests/test_server.py (mocked, offline), this proves
the server actually works against a live instance, including that TLP
redaction fires on genuinely restricted data (when redaction is enabled).

Run from a machine that can reach your MISP instance, with your own
read-only key:

    MISP_URL=https://misp.example.org \\
    MISP_API_KEY=<your-read-only-key> \\
    .venv/bin/python scripts/live_smoke_test.py

Exit code 0 = all checks passed. Prints a per-tool report. Never prints
restricted values (it calls the redacting tools, not MISP directly).

The fixture ids below are examples; set the SMOKE_* env vars to indicators
and events that exist on your own instance.
"""

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from misp_mcp import server  # noqa: E402

# Example fixtures (a public feed indicator + a TLP:AMBER event). Override
# via env to match indicators/events that exist on your own instance.
PUBLIC_IP = os.environ.get("SMOKE_PUBLIC_IP", "102.130.113.9")
PUBLIC_EVENT_ID = os.environ.get("SMOKE_PUBLIC_EVENT", "16989")
RESTRICTED_EVENT_ID = os.environ.get("SMOKE_RESTRICTED_EVENT", "35476")
MISS_IP = "203.0.113.77"  # TEST-NET-3, guaranteed no real hits


def _check(name: str, ok: bool, detail: str) -> bool:
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")
    return ok


async def run() -> int:
    ok = True

    status = json.loads(await server.misp_instance_status())
    ok &= _check("instance_status", status.get("reachable") is True,
                 f"MISP {status.get('misp_version')} / server {status.get('server_version')}")

    hit = json.loads(await server.misp_lookup_ioc(server.IocInput(ioc=PUBLIC_IP)))
    ok &= _check("lookup_ioc (public hit)", hit.get("total_hits", 0) > 0,
                 f"{hit.get('total_hits')} hits, none restricted="
                 f"{all(not h.get('restricted') for h in hit.get('hits', []))}")

    miss = json.loads(await server.misp_lookup_ioc(server.IocInput(ioc=MISS_IP)))
    ok &= _check("lookup_ioc (miss)", miss.get("total_hits") == 0, "0 hits as expected")

    batch = json.loads(await server.misp_lookup_iocs(
        server.BatchIocInput(iocs=[PUBLIC_IP, MISS_IP, "garbage!!"])))
    results = {r.get("ioc"): r for r in batch.get("results", [])}
    ok &= _check("lookup_iocs (batch)", len(batch.get("results", [])) == 3,
                 f"{len(batch.get('results', []))} results, invalid handled inline="
                 f"{'error' in results.get('garbage!!', {})}")

    corr = json.loads(await server.misp_correlate_ioc(server.IocInput(ioc=PUBLIC_IP)))
    ok &= _check("correlate_ioc", "related" in corr,
                 f"{len(corr.get('related', []))} related indicators")

    pub = json.loads(await server.misp_get_event(
        server.EventInput(event_id=PUBLIC_EVENT_ID)))
    ok &= _check("get_event (public)", pub.get("info") is not None,
                 f"'{pub.get('info')}'")

    restricted = json.loads(await server.misp_get_event(
        server.EventInput(event_id=RESTRICTED_EVENT_ID)))
    redacted = restricted.get("restricted") is True and "attributes" not in restricted
    ok &= _check("get_event (restricted REDACTION)", redacted,
                 "restricted event withheld, no attributes leaked" if redacted
                 else "WARNING: restricted event was NOT redacted!")

    search = json.loads(await server.misp_search_events(
        server.EventSearchInput(keyword="tor")))
    ok &= _check("search_events", "events" in search,
                 f"{search.get('total')} events matched 'tor'")

    feeds = json.loads(await server.misp_feed_stats())
    ok &= _check("feed_stats", feeds.get("total", 0) > 0,
                 f"{feeds.get('enabled')} enabled of {feeds.get('total')}")

    print(f"\n{'ALL CHECKS PASSED' if ok else 'SOME CHECKS FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
