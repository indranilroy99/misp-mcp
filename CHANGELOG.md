# Changelog

All notable changes to misp-mcp are documented here. This project follows
[Semantic Versioning](https://semver.org/) and the format of
[Keep a Changelog](https://keepachangelog.com/).

## [1.2.0] — 2026-07-14

### Added
- `misp_submit_iocs` bulk tool: validate and add many indicators (up to 50) in
  one call, sharing reporter/justification/last_seen/tags/to_ids. `dry_run`
  (default true) validates, classifies, and runs the protected safelist without
  writing — preview the batch, then re-run with `dry_run=false` to add. Per-IOC
  status: would_add / added / rejected / protected / duplicate_in_batch /
  rate_limited / error. Same guardrails as the single submit.

## [1.1.0] — 2026-07-14

### Added
- `misp_review_submissions` tool: audit recent additions to the submissions
  event — what indicators were added, by whom (verified submitter), when, and
  which are detection-flagged (`to_ids=true`). Filter by submitter/reporter,
  date window, or detection-flagged only. Lets curators spot bad or unwanted
  IOCs and who submitted them.

## [1.0.0] — 2026-07-14

First public release.

### Added
- MCP server exposing MISP over two transports: local `stdio` (per-analyst) and
  hosted `http` (per-user `X-MISP-Key` header).
- Seven read tools: `misp_lookup_ioc`, `misp_lookup_iocs`, `misp_correlate_ioc`,
  `misp_get_event`, `misp_search_events`, `misp_feed_stats`,
  `misp_instance_status`.
- One gated write tool, `misp_submit_ioc`, with mandatory attribution fields and
  explicit `to_ids`.
- Write guardrails: protected-infrastructure safelist (public resolvers, big
  providers, and `MISP_MCP_PROTECTED_DOMAINS`), per-key submission rate limit,
  and a MISP-verified submitter identity.
- Input validation and refanging for IPv4, IPv6, domains, URLs, email addresses,
  and MD5/SHA1/SHA256 hashes; private/reserved addresses rejected.
- Optional app-layer TLP redaction (`MISP_MCP_SHOW_RESTRICTED`), fail-closed.
- Hosted-transport safety: refuses a public plain-HTTP bind unless TLS certs are
  provided or `MISP_MCP_ALLOW_INSECURE_BIND=true`.
- `install.sh`: OS/dependency check, virtualenv setup, credential prompt, and
  automatic MCP-client configuration (Claude Desktop, Claude Code, Cursor,
  Windsurf) with a manual fallback.
- Documentation: README, ONBOARDING (local), DEPLOY (self-host), CLOUD
  (AWS/GCP/Azure).

[1.0.0]: https://github.com/indranilroy99/misp-mcp
