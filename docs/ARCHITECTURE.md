# Architecture

## The problem

UniFi exposes three API surfaces, none of which alone is enough for full agentic control:

- The **official Integration API** (`/proxy/network/integration/v1`, `X-API-KEY`) is clean
  and stable but does not expose radio tuning, client block/kick, speedtest, events,
  historical reports, or backups.
- The **classic controller API** (`/proxy/network/api/s/<site>`, cookie + CSRF) covers
  everything but is unofficial and needs a local admin login.
- The **cloud Site Manager API** (`api.ui.com`) is read-only for most data.

An API key does **not** reliably authenticate the classic endpoints, so a single-auth tool
either misses capabilities or misses the official surface. `unifi-agent` is a deliberate
**hybrid**: it uses each API for what it does best and labels the provenance and risk of
every operation.

Full endpoint map, payloads, and the disruption matrix are in
[`API_REFERENCE.md`](./API_REFERENCE.md).

## Layers

```
        CLI  (cli.py)            MCP server  (mcp/server.py, stdio only)
             \                        /
              \                      /
               v                    v
                UniFiAgent  (facade.py)
        high-level ops · safety guard · API routing · normalization
                 |                         |
         SafetyGuard (safety.py)     models.py (normalize_*)
         · read-only mode                  |
         · blast-radius ceiling            |
         · confirm / dry-run        operations.py (blast-radius catalog)
         · audit log (JSONL)
                 |                         |
        +--------+-------------------------+--------+
        |                                           |
  IntegrationClient (api/integration.py)   ClassicClient (api/classic.py)
   X-API-KEY, stateless, paginated          cookie + CSRF, re-login on stale
        |                                           |
        +---------------------+---------------------+
                              |
                        Auth (auth.py)
                   ApiKeyAuth · SessionAuth
                              |
                     Transport (transport.py)
              TLS-pinned httpx · retry/backoff · 429 handling
                              |
                        Config + Secrets
              config.py (Settings) · secrets.py (keyring + redaction)
```

## Key decisions

- **Integration API for reads it covers; classic for depth and the gaps.** The facade
  prefers whichever surface gives the richest correct answer and falls back gracefully when
  only one credential is configured (`capabilities()` reports what's available).
- **Read-modify-write with a pre-write re-fetch** for radio and WLAN edits. The API has no
  ETags/revision IDs, so concurrent edits are last-write-wins; re-fetching immediately
  before the PUT and sending the complete object shrinks the race window.
- **Blast-radius classification drives safety, not guesswork.** Every mutation is declared
  in `operations.py` with a radius and a provisioning flag. The guard compares against a
  configurable ceiling and warns when a change will reprovision APs (the ~30-60s
  client-drop cycle) or risk the WAN/management session.
- **Disruption awareness.** Most UniFi changes reprovision every affected AP at once (there
  is no rolling/staggered provisioning). The tool surfaces this in previews so an agent can
  choose to change one AP at a time and schedule risky batches after hours.
- **stdio-only MCP + outbound-only LAN.** No listening port anywhere. Remote access is via
  the gateway's existing VPN back into the LAN, not by exposing the tool. See
  [`../SECURITY.md`](../SECURITY.md).

## Extending

- Uncovered classic endpoints: call `agent.classic.get/post/put/delete` directly — the
  session, CSRF, and re-login are handled for you.
- New guarded mutation: add an `Operation` to `operations.py`, a facade method that routes
  through `_guarded(...)`, and (optionally) an MCP tool + CLI command.
- New Integration endpoints: add a method to `IntegrationClient`; pagination and the API
  key header are handled by `_paginate` / `_request`.
