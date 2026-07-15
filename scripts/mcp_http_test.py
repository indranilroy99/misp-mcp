#!/usr/bin/env python3
"""HTTP-mode integration test — connects to a RUNNING hosted server over
the MCP streamable-HTTP protocol, passing a per-user MISP key in the
X-MISP-Key header, exactly as an org caller will. This validates the exact
configuration a hosted deployment will run, locally, before deploy.

Two terminals (or background the server):

  # terminal 1 — start the hosted server (no MISP key on the server!)
  MISP_URL=https://misp.example.org \\
  MCP_TRANSPORT=http MCP_HOST=127.0.0.1 MCP_PORT=8137 \\
    .venv/bin/misp-mcp

  # terminal 2 — hit it as a user, passing YOUR own MISP key
  MCP_URL=http://127.0.0.1:8137/mcp \\
  MISP_KEY=<your-read-only-key> MISP_USER=you@example.org \\
    .venv/bin/python scripts/mcp_http_test.py

Also verifies a request with NO X-MISP-Key is rejected (401).
"""

import asyncio
import os
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = os.environ.get("MCP_URL", "http://127.0.0.1:8137/mcp")
KEY = os.environ.get("MISP_KEY", "")
USER = os.environ.get("MISP_USER", "test@local")


async def session_with_headers(headers):
    async with streamablehttp_client(URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            print(f"handshake OK, {len(tools)} tools")
            r = await session.call_tool("misp_instance_status", {})
            print("instance_status:", r.content[0].text)
            r = await session.call_tool(
                "misp_lookup_ioc", {"params": {"ioc": "102.130.113.9"}}
            )
            print("lookup:", r.content[0].text[:400])


async def main() -> int:
    print("=== with X-MISP-Key (should work) ===")
    await session_with_headers({"X-MISP-Key": KEY, "X-MISP-User": USER})

    print("\n=== no X-MISP-Key (should be rejected 401) ===")
    try:
        await session_with_headers({})
        print("FAIL: request without a key was NOT rejected")
        return 1
    except Exception as e:
        print(f"rejected as expected ({type(e).__name__})")

    print("\nHTTP integration: OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
