# OWASP ZAP MCP Server

A production-grade [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server that exposes [OWASP ZAP](https://www.zaproxy.org/) to LLM clients
(Claude Desktop, Cursor, etc.) for **authorized penetration testing and
bug-bounty** workflows.

It provides a curated surface of **67 tools** across crawling, active/passive
scanning, authenticated scanning, findings triage, imports, automation, and
reporting — built directly against the official
[ZAP API](https://www.zaproxy.org/docs/api/), with a server-side target
authorization policy so an LLM cannot direct attack traffic at unauthorized or
internal infrastructure.

> ⚠️ **Authorized use only.** Active scanning is an attack. Only run it against
> systems you have explicit, written permission to test. See
> [Responsible use](#responsible-use).

---

## Highlights

- **67 curated tools** — not a raw 1:1 mirror of ZAP's hundreds of endpoints.
  High-risk/desktop-only components (script engine, break/intercept, HUD,
  Selenium launch, autoupdate) are intentionally excluded.
- **Full authenticated-scan workflow** — context → authentication method →
  logged-in/out indicators → user credentials → forced-user → `scan_as_user`
  for spider, AJAX spider, and active scan.
- **Target authorization policy** — cloud metadata endpoints are always refused;
  optional scope allowlist and private-range blocking.
- **Reliable by design** — one pooled async HTTP client with lifecycle
  management, bounded retries with backoff, typed errors, and a uniform result
  envelope so a single tool call can never crash the server.
- **Fail-closed configuration** — refuses to start without an API key (unless
  explicitly opted out), validates all settings, and never logs secrets.
- **Hardened containers** — pinned image, non-root user, healthchecks,
  health-gated startup, secrets via `.env`.
- **Tested** — unit test suite covering the security boundary, config
  validation, error handling, and tool behavior.

---

## Architecture

```text
[ LLM client / AI assistant ]
        │  MCP over Streamable HTTP (port 8000)
        ▼
[ zap-mcp-server ]  Python 3.12 · MCPServer · target policy · pooled ZAP client
        │  internal Docker network (zapnet)
        ▼
[ zap-daemon ]      OWASP ZAP 2.17.0 headless daemon (API on 8080)
```

- The MCP server reaches ZAP over the internal Docker network at
  `http://zap:8080`.
- The ZAP API/proxy port is published only on `127.0.0.1:8080` (not on all host
  interfaces).
- All state-changing ZAP `action` endpoints require the API key.

---

## Security model

| Control | Behavior |
|---|---|
| **API key** | Required. The server fails to start if `ZAP_API_KEY` is unset (override with `ZAP_ALLOW_INSECURE=true` for local dev only). Never logged. |
| **Metadata block** | `169.254.169.254`, `metadata.google.internal`, and equivalents are **always** refused for attack tools. Not configurable. |
| **Scope allowlist** | `ZAP_TARGET_ALLOWLIST` (comma-separated host suffixes) pins the engagement scope. When set, only matching hosts may be crawled/attacked. |
| **Private-range block** | `ZAP_BLOCK_PRIVATE_TARGETS=true` refuses private/loopback/link-local targets (keep off for local labs). |
| **Report path safety** | Report filenames are reduced to a basename to prevent path traversal; output is confined to `ZAP_REPORT_DIR`. |
| **Secret hygiene** | The API key lives only in request headers/query params and is never included in logs or error messages. |

Read-only view tools (version, sites, alerts) are intentionally **not** gated —
they observe existing state and generate no traffic to the target.

---

## Quick start

### 1. Configure secrets

```bash
cp .env.example .env
# Edit .env and set ZAP_API_KEY to a long, random value.
```

`.env` is git-ignored. The same key is used by both the ZAP daemon and the MCP
server (wired automatically in `docker-compose.yml`).

### 2. Launch the stack

```bash
docker compose up -d --build
```

Compose starts ZAP, waits for it to become **healthy**, then starts the MCP
server (health-gated startup).

### 3. Verify

```bash
docker compose ps                     # both services should be "healthy"
docker compose logs -f mcp-server     # expect: "Registered 67 MCP tools"
```

---

## Configuration

All settings are environment variables (see `.env.example`). Validated at
startup — invalid values fail fast.

| Variable | Default | Description |
|---|---|---|
| `ZAP_API_KEY` | *(required)* | ZAP API key. Server refuses to start if unset. |
| `ZAP_BASE_URL` | `http://zap:8080` | ZAP API base URL. |
| `ZAP_TARGET_ALLOWLIST` | *(empty)* | Comma-separated host suffixes allowed for attack tools. Empty = any (metadata still blocked). |
| `ZAP_BLOCK_PRIVATE_TARGETS` | `false` | Refuse private/loopback targets for attack tools. |
| `ZAP_REPORT_DIR` | `/zap/wrk` | Directory (inside ZAP) reports are written to. |
| `REQUEST_TIMEOUT` / `CONNECT_TIMEOUT` | `60` / `10` | HTTP timeouts (seconds). |
| `ZAP_MAX_RETRIES` / `ZAP_RETRY_BACKOFF` | `2` / `0.5` | Transient-error retry policy. |
| `MCP_HOST` / `MCP_PORT` | `0.0.0.0` / `8000` | MCP server bind address. |
| `ZAP_ALLOW_INSECURE` | `false` | Allow start without an API key (dev only). |

---

## Tool catalogue (67 tools)

**Core & health** — `zap_get_version`, `zap_access_url`\*, `zap_get_sites`,
`zap_get_urls`, `zap_new_session`

**Crawling** — `zap_spider_scan`\*, `zap_spider_scan_as_user`\*,
`zap_spider_status`, `zap_spider_results`, `zap_spider_stop`,
`zap_ajax_spider_scan`\*, `zap_ajax_spider_scan_as_user`\*,
`zap_ajax_spider_status`, `zap_ajax_spider_results`, `zap_ajax_spider_stop`

**Scanners** — `zap_active_scan`\*, `zap_active_scan_as_user`\*,
`zap_active_scan_status`, `zap_active_scan_progress`, `zap_active_scan_stop`,
`zap_active_scan_pause`, `zap_active_scan_resume`, `zap_list_scan_policies`,
`zap_passive_scan_status`, `zap_passive_scan_set_enabled`,
`zap_passive_scan_clear_queue`

**Findings & triage** — `zap_get_alerts`, `zap_get_alerts_summary`,
`zap_get_alert_details`, `zap_get_number_of_alerts`, `zap_delete_all_alerts`,
`zap_add_alert_filter`, `zap_list_alert_filters`, `zap_apply_alert_filters`,
`zap_retest_alerts`

**Context & scope** — `zap_create_context`, `zap_include_in_context`,
`zap_exclude_from_context`, `zap_list_contexts`, `zap_get_context`,
`zap_export_context`, `zap_import_context`

**Imports & automation** — `zap_import_openapi_url`, `zap_import_openapi_file`,
`zap_import_graphql_url`, `zap_import_har`, `zap_import_urls`,
`zap_run_automation_plan`, `zap_automation_plan_progress`

**Authentication** — `zap_get_auth_methods`,
`zap_get_auth_method_config_params`, `zap_set_authentication_method`,
`zap_get_authentication_method`, `zap_set_logged_in_indicator`,
`zap_set_logged_out_indicator`

**Users** — `zap_new_user`, `zap_set_user_credentials`, `zap_set_user_enabled`,
`zap_list_users`, `zap_get_user`

**Forced user** — `zap_set_forced_user`, `zap_set_forced_user_mode`,
`zap_get_forced_user`, `zap_is_forced_user_mode_enabled`

**Reports** — `zap_list_report_templates`, `zap_report_template_details`,
`zap_generate_report`

\* = gated by the target authorization policy.

Every tool returns a uniform envelope:

```json
{ "status": "success", "...": "payload" }
{ "status": "error", "code": "zap_timeout", "message": "...", "retryable": true }
```

---

## Authenticated scanning

The recommended workflow (mirrors ZAP's official "Getting Authenticated" guide):

1. `zap_create_context` → get a context ID; scope it with
   `zap_include_in_context` / `zap_exclude_from_context` (exclude logout URLs).
2. `zap_set_authentication_method` (e.g. `formBasedAuthentication`) — use
   `zap_get_auth_method_config_params` to discover the required parameters.
3. `zap_set_logged_in_indicator` and/or `zap_set_logged_out_indicator`.
4. `zap_new_user` → `zap_set_user_credentials` → `zap_set_user_enabled`.
5. Optionally `zap_set_forced_user` + `zap_set_forced_user_mode` to keep the
   session alive during long scans.
6. Crawl and scan authenticated: `zap_spider_scan_as_user`,
   `zap_ajax_spider_scan_as_user`, `zap_active_scan_as_user`.

For repeatable engagements, drive the whole pipeline with an
[Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
plan via `zap_run_automation_plan`.

---

## Connecting an MCP client

Add to your MCP client configuration (e.g. `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "owasp-zap": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

---

## Development & testing

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

The suite covers the target-authorization policy (metadata block, allowlist,
private-range), fail-closed config validation, the error/result envelope, the
auth-methods fix, and per-tool target enforcement.

---

## Responsible use

Active scanning sends attack payloads. In most jurisdictions, testing systems
without permission is illegal. Before scanning:

- Confirm the target is **in scope** for an engagement you are authorized to run.
- Set `ZAP_TARGET_ALLOWLIST` to pin scope, and consider
  `ZAP_BLOCK_PRIVATE_TARGETS=true` for internet-only engagements.
- Rotate `ZAP_API_KEY` to a long random value; never commit `.env`.

Cloud metadata endpoints are always refused and this cannot be overridden.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Server won't start, "ZAP_API_KEY is not set" | Set `ZAP_API_KEY` in `.env` (or `ZAP_ALLOW_INSECURE=true` for dev). |
| `{"code": "zap_unreachable"}` | ZAP not up/healthy, or `ZAP_BASE_URL` wrong. Check `docker compose ps`. |
| `{"code": "target_not_allowed"}` | Target failed the policy — add it to `ZAP_TARGET_ALLOWLIST`, or it's a blocked metadata/private host. |
| `no_implementor` from ZAP | The relevant ZAP add-on isn't installed (e.g. AJAX Spider, Retest). |
| Auth methods list empty | Fixed in this build (reads `supportedMethods`); ensure you're on the current image. |
