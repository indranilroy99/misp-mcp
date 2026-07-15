# misp-mcp — local setup

Run misp-mcp in your MCP client (Claude Desktop, Claude Code, Cursor, Continue,
or any other) in about ten minutes. You use your own MISP key, so your queries
are attributed to you in MISP's logs. With a read-only key every tool is
read-only; the write tool (`misp_submit_ioc`) needs a write-capable key and
returns a permission error otherwise.

> **In a hurry?** From the repo, run `./install.sh`. It does everything below
> (Python check, virtualenv, install, key prompt, and writing your client's
> config) automatically. The steps here are the manual version.

## 1. Create a personal MISP key

Do this once. In MISP:

1. Top-right menu → **My Profile → Auth Keys** (or ask an admin to add one for
   your user).
2. Comment: `misp-mcp <your-name>`. Tick **read only** if the option is offered.
   Set an expiry.
3. Copy the key. MISP shows it only once.

Do not share the key or paste it into chat or docs. It can read threat intel,
which may include restricted or partner data.

## 2. Install

```bash
git clone https://github.com/indranilroy99/misp-mcp.git
cd misp-mcp
python3 -m venv .venv
.venv/bin/pip install -e .        # installs deps + the `misp-mcp` binary
```

## 3. Check it works (before wiring it into a client)

```bash
MISP_URL=https://misp.example.org \
MISP_API_KEY=<your-key> \
  .venv/bin/python scripts/live_smoke_test.py
```

All checks should print `PASS`. If `instance_status` fails, it is almost always
the network (you may need a VPN) or the key, not the server.

## 4. Register it with your MCP client

Point your client at the `misp-mcp` binary that the install created, with two
env vars (`MISP_URL`, `MISP_API_KEY`). Then restart the client.

Most clients (Claude Desktop, Cursor, and others) use a JSON config with an
`mcpServers` block:

```json
{
  "mcpServers": {
    "misp": {
      "command": "/ABSOLUTE/PATH/misp-mcp/.venv/bin/misp-mcp",
      "args": [],
      "env": {
        "MISP_URL": "https://misp.example.org",
        "MISP_API_KEY": "<your-key>"
      }
    }
  }
}
```

Claude Code (CLI):

```bash
claude mcp add misp \
  --env MISP_URL=https://misp.example.org \
  --env MISP_API_KEY=<your-key> \
  -- /ABSOLUTE/PATH/misp-mcp/.venv/bin/misp-mcp
```

## 5. Try it

Ask your assistant things like:

- "Look up 102.130.113.9 in MISP."
- "Triage these IOCs against MISP: <paste a list>."
- "What other indicators appear alongside <domain> in MISP?"
- "Is MISP healthy? How many feeds are enabled?"

## Good to know

- **Restricted intel.** By default the server shows whatever your key can see.
  If your deployment turned on server-side hiding, TLP:AMBER/RED events come
  back redacted.
- **Read-only for you.** With a read-only key nothing can change MISP; the write
  tool is refused with a permission error. Safe to explore.
- **Logs.** The server logs to stderr (visible in your client's MCP logs). It
  never logs your key or IOC values.
