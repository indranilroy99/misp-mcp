#!/usr/bin/env python3
"""MCP PROTOCOL integration test — spawns the server as a real subprocess
and talks to it over the actual MCP stdio protocol (handshake, list_tools,
call_tool), exactly like an MCP client does. This is different from
tests/test_server.py (which calls tool functions directly) and from
live_smoke_test.py (which calls them in-process): this proves the server
works as a real MCP server a client can connect to.

Run with your read-only key (real data) or without (proves the protocol
path even though tools return an auth/config error):

    MISP_URL=https://misp.example.org \\
    MISP_API_KEY=<your-read-only-key> \\
    .venv/bin/python scripts/mcp_protocol_test.py
"""

import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


async def main() -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "misp_mcp"],
        cwd=HERE,
        env={**os.environ, "MCP_TRANSPORT": "stdio"},
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("handshake: OK")

            tools = (await session.list_tools()).tools
            names = sorted(t.name for t in tools)
            print(f"tools ({len(names)}): {', '.join(names)}")
            assert len(names) == 10, f"expected 10 tools, got {len(names)}"

            print("\n--- misp_instance_status ---")
            r = await session.call_tool("misp_instance_status", {})
            print(r.content[0].text)

            print("\n--- misp_lookup_ioc 102.130.113.9 ---")
            r = await session.call_tool(
                "misp_lookup_ioc", {"params": {"ioc": "102.130.113.9"}}
            )
            print(r.content[0].text[:600])

    print("\nMCP protocol integration: OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
