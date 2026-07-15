# Security Policy

## Reporting a vulnerability

Do **not** open a public issue for security problems.

Report them privately to the maintainers (the security team that owns this
repository) so the issue can be fixed before disclosure. Include steps to
reproduce, affected versions, and impact if you can.

You can expect an acknowledgement within a few business days and a coordinated
fix and disclosure timeline.

## Scope

misp-mcp exposes a MISP instance to MCP clients. Security-relevant areas:

- The hosted HTTP transport and its `X-MISP-Key` header authentication.
- The write tool (`misp_submit_ioc`) and its guardrails (protected safelist,
  submission rate limit, MISP-verified submitter).
- Handling of untrusted MISP content (event text is data, never instructions).
- Secret handling: MISP keys must never be logged or written to world-readable
  files.

## Good to know

- The server holds no shared MISP key; every request is authorized by the
  caller's own key, which MISP validates.
- `X-MISP-Key` is a bearer credential. The server refuses to serve a
  non-loopback address over plain HTTP unless TLS is configured or explicitly
  acknowledged (`MISP_MCP_ALLOW_INSECURE_BIND=true`).
- The test suite is offline and mocks MISP; never commit a real key or host.
