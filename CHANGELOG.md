# Changelog

All notable changes to misp-mcp are documented here. This project follows
[Semantic Versioning](https://semver.org/) and the format of
[Keep a Changelog](https://keepachangelog.com/).

## [1.3.1] — 2026-07-15

### Security
- Fix submitter-attribution forgery in `misp_review_submissions` (comment
  injection). The audit comment is now built and parsed with a prefix-anchored
  format so free text in `justification`/`reporter` can no longer inject a
  second `submitted_by=` that overrides the MISP-verified submitter. Control
  characters are stripped from all fields; structured fields have `;`/`=`
  neutralized. Applies to `misp_submit_ioc` and `misp_submit_iocs`.

### Changed
- CI: least-privilege `permissions: contents: read`, added a `pip-audit`
  dependency-vulnerability job, added CodeQL (`security-extended`) SAST, and
  Dependabot for pip + GitHub Actions.
- Terraform: `allowed_cidrs` now rejects `0.0.0.0/0` and `::/0` via a variable
  validation, so the bearer-credential endpoint can't be opened to the
  internet by a careless `.tfvars` (fargate and ec2 roots).
- Documented that the per-key submit rate limit is per-process (run one replica
  or use a shared store for a hard org-wide cap).

## [1.3.0] — 2026-07-15

### Added
- Knowledge-base and direct-access read tools, bringing full-client read
  breadth under the same per-user-auth and TLP-redaction model:
  - `misp_lookup_galaxy`: search galaxy clusters (threat actors, malware,
    tools, ATT&CK techniques) by name or synonym — attribution and technique
    lookup.
  - `misp_list_galaxies`: list the galaxy types on the instance.
  - `misp_list_taxonomies`: list taxonomies (TLP, kill-chain, PAP, ...) with
    enabled state and tag counts.
  - `misp_get_taxonomy`: one taxonomy's tags and meanings, by namespace or id.
  - `misp_search_tags`: find tag definitions by name.
  - `misp_get_object`: one MISP object (grouped attributes), redacted for
    restricted events.
  - `misp_get_attribute`: one attribute by id with its event, redacted for
    restricted events.
  - `misp_search_attributes`: attribute search by type / category / tag /
    to_ids / event / recency (at least one filter required).
- 18 tools total (16 read, 2 write). 60 tests.

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
