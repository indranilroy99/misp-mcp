# Contributing

Thanks for helping improve misp-mcp.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'   # runtime deps + pytest, pytest-asyncio
```

## Before you open a PR

- Run the tests: `.venv/bin/python -m pytest tests/ -q`. Add tests for any
  behavior you change, especially anything on the write path or the
  submission guardrails (`misp_mcp/validators.py`, `misp_mcp/server.py`).
- Keep the code style of the surrounding file.
- Never commit a real MISP key, hostname, or other secret. The test suite is
  fully offline and mocks MISP; keep it that way.

## Releasing

`misp_mcp/__init__.py` is the single source of truth for the version (pyproject
reads it dynamically; `misp-mcp --version` and `misp_instance_status` read it at
runtime). To bump it and keep the static surfaces (banner SVGs, README badge) in
sync, run:

```bash
python scripts/bump_version.py 1.1.0
```

Then add a `## [1.1.0]` entry to `CHANGELOG.md`, commit, and tag
(`git tag v1.1.0 && git push --tags`).

## Security

If you find a security issue, do not open a public issue. Report it privately
to the maintainers so it can be fixed before disclosure.

## Scope

misp-mcp exposes MISP to MCP clients: read tools plus one gated write tool. New
tools should be small, validated, and read-only unless there is a clear reason
otherwise. Write paths must keep the existing guardrails (safelist, rate limit,
verified submitter, explicit `to_ids`).
