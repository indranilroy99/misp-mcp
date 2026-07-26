#!/usr/bin/env python3
"""Live smoke test for the v1.3/v1.4 tools against a RUNNING hosted server
(galaxy / taxonomy / tags / warninglist / attribute search / worker / jobs).

  MCP_URL=http://127.0.0.1:8091/mcp \\
  MISP_KEY=<your key> MISP_USER=you@example.org \\
    .venv/bin/python scripts/new_tools_test.py

Read-only throughout; the admin-only tools (worker/jobs) report a permission
error on a non-admin key, which counts as PASS (the error is the contract).
"""

import asyncio
import json
import os
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = os.environ.get("MCP_URL", "http://127.0.0.1:8091/mcp")
KEY = os.environ.get("MISP_KEY", "")
USER = os.environ.get("MISP_USER", "test@local")

# (tool, args, admin_ok) — admin_ok tools may return a clean permission error.
CASES = [
    ("misp_lookup_galaxy", {"params": {"query": "APT29"}}, False),
    ("misp_list_galaxies", {}, False),
    ("misp_list_taxonomies", {}, False),
    ("misp_get_taxonomy", {"params": {"taxonomy": "tlp"}}, False),
    ("misp_search_tags", {"params": {"query": "tlp"}}, False),
    ("misp_check_warninglist", {"params": {"iocs": ["8.8.8.8", "102.130.113.9"]}}, False),
    ("misp_search_attributes", {"params": {"type": "ip-dst", "days": 7, "limit": 5, "page": 1}}, False),
    ("misp_worker_status", {}, True),
    ("misp_jobs", {"params": {"limit": 5, "only_failed": True}}, True),
]


def summarize(name: str, text: str) -> str:
    if text.startswith("Error:"):
        return text[:160]
    try:
        d = json.loads(text)
    except ValueError:
        return text[:160]
    keys = ("total", "count", "flagged", "enabled", "failed", "has_more", "namespace", "raw_ok")
    picked = {k: d[k] for k in keys if k in d}
    for listkey in ("clusters", "galaxies", "taxonomies", "tags", "results", "hits", "entries", "queues", "jobs"):
        if isinstance(d.get(listkey), list):
            picked[listkey] = f"{len(d[listkey])} items"
    return json.dumps(picked)


async def main() -> int:
    failures = 0
    async with streamablehttp_client(URL, headers={"X-MISP-Key": KEY, "X-MISP-User": USER}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = {t.name for t in (await s.list_tools()).tools}
            print(f"handshake OK, {len(tools)} tools")
            for name, args, admin_ok in CASES:
                if name not in tools:
                    print(f"FAIL  {name}: not registered")
                    failures += 1
                    continue
                out = (await s.call_tool(name, args)).content[0].text
                is_err = out.startswith("Error:")
                if is_err and admin_ok and ("rejected your API key" in out or "403" in out or "401" in out):
                    print(f"PASS  {name}: permission error as expected on non-admin key")
                elif is_err:
                    print(f"FAIL  {name}: {out[:200]}")
                    failures += 1
                else:
                    print(f"PASS  {name}: {summarize(name, out)}")
    print(f"\nnew-tools smoke: {'OK' if failures == 0 else f'{failures} FAILURES'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
