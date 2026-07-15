# Hosting misp-mcp

This is the guide for running misp-mcp as a shared server that a whole team or
automation can call. For one person on a laptop, see [ONBOARDING.md](ONBOARDING.md)
instead. For the cloud-specific setup on AWS, GCP, or Azure (VM, load balancer,
firewall), see [CLOUD.md](CLOUD.md); it points back here for the app itself.
Everything uses the same code; a single setting (`MCP_TRANSPORT`) picks the mode.

## How identity works

- Each request carries the caller's own MISP key in an `X-MISP-Key` header, and
  optionally `X-MISP-User: <email>` for logging. MISP validates the key and
  attributes the query to that user.
- There is **no shared key on the server**. It stores nothing secret. `MISP_URL`
  is the only MISP setting it needs.
- A request with no key is rejected with `401` before any tool runs.
- `/healthz` is open (no key) so a load balancer can health-check it.

## Environment

| Variable | Example | Notes |
|---|---|---|
| `MCP_TRANSPORT` | `http` | switch from local (`stdio`) to hosted |
| `MCP_HOST` | `0.0.0.0` | bind address |
| `MCP_PORT` | `8080` | listening port |
| `MISP_URL` | `https://misp.example.org` | your MISP base URL |
| `MISP_VERIFY_TLS` | `true` | leave `true`; `false` only for a self-signed lab |
| `MISP_SUBMISSION_EVENT_ID` | `1234` | event `misp_submit_ioc` writes to (required for writes) |
| `MISP_MCP_SHOW_RESTRICTED` | `false` | `false` turns ON server-side TLP hiding; unset shows what each key can see |
| `MISP_MCP_PROTECTED_DOMAINS` | `pay.acme.com,acme.com` | your domains that can never be submitted as indicators |
| `MISP_MCP_SUBMIT_RATE` | `20` | max IOC submissions per key per minute |
| `MISP_MCP_TLS_CERT` / `MISP_MCP_TLS_KEY` | (paths) | serve HTTPS directly (see below) |
| `MISP_MCP_ALLOW_INSECURE_BIND` | `true` | required for a public plain-HTTP bind when TLS is on a proxy |

## TLS is required in practice

`X-MISP-Key` is a bearer credential. It must never cross the network in
cleartext. The server enforces this: it refuses to start on a non-loopback
address over plain HTTP. You have two supported options.

**Option A — TLS on a proxy or load balancer (common).**
Put a reverse proxy or load balancer in front that terminates TLS, and keep the
hop from proxy to this process inside a trusted network. Then tell the server
that is intentional:

```
MISP_MCP_ALLOW_INSECURE_BIND=true
```

**Option B — TLS on the server directly.**
Give the process a certificate and key; no proxy needed for encryption:

```
MISP_MCP_TLS_CERT=/etc/misp-mcp/cert.pem
MISP_MCP_TLS_KEY=/etc/misp-mcp/key.pem
```

## Network hardening

- Do not expose the port to the public internet. Allow inbound only from the
  callers that need it (their security groups, subnets, or the load balancer).
- Allow the server outbound access to your MISP instance (HTTPS, plus DNS).
- Prefer a private/internal load balancer over an internet-facing one.

## Install on the machine

```bash
git clone https://github.com/indranilroy99/misp-mcp.git
sudo cp -r misp-mcp /opt/misp-mcp && cd /opt/misp-mcp
python3 -m venv .venv
.venv/bin/pip install -e .        # installs deps + the `misp-mcp` binary
```

## Run it manually (start, status, stop, restart)

Use this to run the HTTP server by hand, without systemd — handy for testing
hosted mode locally or a quick shared instance. (In local/stdio mode you do not
do any of this: your MCP client starts and stops the server for you.)

On `127.0.0.1` (localhost) no TLS is needed — the examples below bind there.
When you bind a public address, add `MISP_MCP_TLS_CERT` / `MISP_MCP_TLS_KEY`
(or put TLS on a proxy); see "TLS is required in practice" above.

**Start (foreground — logs print to the terminal, Ctrl-C stops it):**

```bash
MISP_URL=https://misp.example.org \
MCP_TRANSPORT=http MCP_HOST=127.0.0.1 MCP_PORT=8080 \
  .venv/bin/misp-mcp
```

**Start (background — keeps running after you close the terminal):**

```bash
MISP_URL=https://misp.example.org \
MCP_TRANSPORT=http MCP_HOST=127.0.0.1 MCP_PORT=8080 \
  nohup .venv/bin/misp-mcp > misp-mcp.log 2>&1 &
echo $! > misp-mcp.pid          # save the process id for later
```

**Check status:**

```bash
.venv/bin/misp-mcp --version                       # prints the version
curl -s http://127.0.0.1:8080/healthz              # {"status":"ok"} means it is up
ps -p "$(cat misp-mcp.pid)" >/dev/null && echo running || echo not running
tail -f misp-mcp.log                               # watch the logs (background mode)
```

**Stop:**

```bash
kill "$(cat misp-mcp.pid)"      # background mode; or press Ctrl-C in the foreground terminal
```

**Restart:** stop it, then run the start command again.

For anything long-lived, use the systemd service below instead — it restarts on
crash and on reboot, and gives you `start` / `status` / `stop` / `restart` for free.

## Run it as a service (systemd example)

`/etc/systemd/system/misp-mcp.service`:

```ini
[Unit]
Description=misp-mcp (MISP MCP server)
After=network-online.target

[Service]
WorkingDirectory=/opt/misp-mcp
Environment=MCP_TRANSPORT=http
Environment=MCP_HOST=0.0.0.0
Environment=MCP_PORT=8080
Environment=MISP_URL=https://misp.example.org
Environment=MISP_SUBMISSION_EVENT_ID=1234
Environment=MISP_MCP_ALLOW_INSECURE_BIND=true
ExecStart=/opt/misp-mcp/.venv/bin/misp-mcp
Restart=on-failure
User=misp-mcp

[Install]
WantedBy=multi-user.target
```

Manage it:

```bash
sudo systemctl enable --now misp-mcp    # start now + on every boot
sudo systemctl status misp-mcp          # is it running?
sudo systemctl restart misp-mcp         # after a config or code change
sudo systemctl stop misp-mcp            # stop it
sudo journalctl -u misp-mcp -f          # follow the logs
```

Verify:

```bash
/opt/misp-mcp/.venv/bin/misp-mcp --version                                 # prints the version
curl -s http://localhost:8080/healthz                                      # {"status":"ok"}
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/mcp # 401 (no key)
```

## Caller configuration

Each user or service points its MCP client at the endpoint with its own key:

```json
{
  "misp": {
    "type": "http",
    "url": "https://misp-mcp.example.org/mcp",
    "headers": {
      "X-MISP-User": "you@example.org",
      "X-MISP-Key": "your-personal-MISP-key"
    }
  }
}
```

Give read-only keys to most people. Only the team that curates indicators needs
write-capable keys.

## Before going live

- Confirm TLS terminates in front of (or on) the server and the port is not
  publicly reachable.
- Set `MISP_SUBMISSION_EVENT_ID` and add your own domains to
  `MISP_MCP_PROTECTED_DOMAINS`.
- Run `scripts/mcp_http_test.py` against the running server with a real key to
  confirm the full path works end to end.
