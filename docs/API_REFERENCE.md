# UniFi API Reference & Design Inputs (researched 2026-07-10)

Target: UCG-Max (UniFi OS), Network application 9.x+ (73-endpoint Integration surface requires Network 10.x), local LAN HTTPS, MCP server + CLI on macOS. Sources: developer.ui.com official specs, ubntwiki classic API reference, library source code (UnPoller, Art of WiFi, aiounifi, node-unifiapi), and the 2026 OSS MCP landscape. URLs cited inline.

---

## 1. Which API to use for what

Three surfaces exist:

- **Network Integration API (local, official):** `https://<gateway>/proxy/network/integration/v1/...`, `X-API-KEY` auth, stateless. OpenAPI ground truth: https://developer.ui.com/network/v10.3.58/openapi.json (root index: https://developer.ui.com/llms.txt).
- **Classic controller API (local, unofficial but stable):** `https://<gateway>/proxy/network/api/s/<site>/...`, cookie + CSRF auth. Reference: https://ubntwiki.com/products/software/unifi-controller/api and https://github.com/uchkunr/unifi-best-practices.
- **Site Manager API (cloud):** `https://api.ui.com/v1/...`, `X-API-KEY`, read-only data plus a cloud-to-local connector proxy. Spec: https://developer.ui.com/site-manager/v1.0.0/openapi.json.

Rule of thumb (uchkunr, Art of WiFi): prefer the official Integration API for everything it covers; drop to the classic API only for the gaps.

| Capability | Integration API (X-API-KEY) | Classic API (cookie+CSRF) | Winner |
|---|---|---|---|
| App version / detection | `GET /v1/info` | `GET /stat/sysinfo` | Integration |
| Sites, devices, clients (list/detail) | Yes (UUID-keyed) | Yes (`_id`/MAC-keyed) | Integration |
| Device restart | `POST .../devices/{id}/actions` `{"action":"RESTART"}` | `/cmd/devmgr` `restart` | Integration |
| PoE port power-cycle | `POST .../ports/{portIdx}/actions` `{"action":"POWER_CYCLE"}` | `/cmd/devmgr` `power-cycle` | Integration |
| Guest authorize/unauthorize | Yes (with time/data/rate limits) | `/cmd/stamgr` | Integration |
| Networks/VLANs CRUD | Yes (Network 10.0+) | `/rest/networkconf` | Integration on 10.x; classic on 9.x |
| WLANs/SSIDs CRUD | WiFi Broadcasts CRUD (10.0+) | `/rest/wlanconf` | Integration on 10.x; classic on 9.x |
| Firewall zones/policies, ACL rules, DNS policies | Yes (10.0/10.1+) | `/rest/firewallrule` (legacy rules) | Integration |
| Latest device stats | `statistics/latest` (snapshot only) | `/stat/device` (richer) | Either; classic for depth |
| **Client block/unblock/kick/forget** | **Not exposed** | `/cmd/stamgr` `block-sta` etc. | **Classic only** |
| **Radio config (channel/width/tx power)** | **Not exposed** (read-only radio info) | `PUT /rest/device/<id>` `radio_table` | **Classic only** |
| **Speedtest trigger + results** | Not exposed (ISP metrics only in cloud Site Manager) | `/cmd/devmgr` `speedtest` / `speedtest-status` | **Classic only** |
| **Historical stats/reports** | Not exposed | `/stat/report/<interval>.<scope>` | **Classic only** |
| **Events / alarms / site health** | Not exposed | `/stat/event`, `/stat/alarm`, `/stat/health` | **Classic only** |
| **Backups (.unf)** | Not exposed | `/cmd/backup` + `/dl/backup/...` | **Classic only** |
| DPI stats, rogue APs, port forwards, static routes, traffic rules, port profiles, firmware upgrade, LED locate, client fixed IP/name | Not exposed | Yes | **Classic only** |
| WebSocket live events | None (Protect API has one; Network does not) | `wss://<gateway>/proxy/network/wss/s/<site>/events` | **Classic only** |
| Cross-site fleet view, ISP metrics | n/a | n/a | Site Manager (cloud) |

**Version gate (critical for UCG-Max):** Network 9.x exposes only **15 Integration endpoints** (info, sites, devices, restart, power-cycle, clients, guest auth, vouchers). Networks/WLAN/firewall CRUD arrives at 10.0.162 (50 endpoints), firewall policies/DNS/adopt at 10.1.84 (67), switching reads at 10.3.58 (73). Detect at runtime via `GET /proxy/network/integration/v1/info` and pin schemas to the matching versioned spec at `https://developer.ui.com/network/{version}/openapi.json` (https://developer.ui.com/network/v9.1.120/llms.txt through v10.3.58).

**Site Manager cloud keys are read-only** as of mid-2026; writes only happen locally or via the connector proxy to local Integration APIs (https://developer.ui.com/site-manager-api/gettingstarted).

---

## 2. Auth flows exactly

### 2a. API key (Integration API, local)

- Header: `X-API-KEY: <key>` on every request. Stateless, no cookie, no CSRF, no login/logout.
- Key creation: UniFi Network app → **Settings → Control Plane → Integrations → Create New API Key** (older path) or **Integrations** bottom-left nav (UniFi OS 5.0.x+). Shown once; optional expiry or "Never Expires" (https://docs2.hubitat.com/en/apps/unifi-network-integration).
- **No per-key scoping.** The key inherits the creating admin's role. Least privilege = create the key from a least-privileged local admin (View Only for read-only keys) (https://artofwifi.net/blog/unifi-api-authentication-local-admin-vs-api-key-vs-site-manager, https://github.com/uchkunr/unifi-best-practices).
- Cloud key (Site Manager): unifi.ui.com → Settings → API Keys (https://unifi.ui.com/settings/api-keys).

### 2b. Cookie + CSRF (classic API, UniFi OS)

```
POST https://<gateway>/api/auth/login
{ "username": "localadmin", "password": "...", "remember": true }
```

- Success: 200, `Set-Cookie: TOKEN=<JWT>` (HttpOnly), response headers `x-csrf-token` (sometimes `x-updated-csrf-token`) and `x-token-expire-time`. Capture all; some responses rotate the CSRF token, update it per response.
- If no CSRF header: base64url-decode the TOKEN JWT middle segment and read the `csrfToken` claim.
- Every POST/PUT/DELETE must send `X-CSRF-Token` + the TOKEN cookie; missing CSRF = silent 403 (https://github.com/inverse-inc/packetfence/issues/9107). GETs need only the cookie.
- **Local account required.** Cloud/SSO accounts return 401 (https://github.com/sirkirby/unifi-mcp/issues/33).
- 2FA: HTTP 499 with `meta.msg = "api.err.Ubic2faTokenRequired"`; resubmit with `"token": "123456"`. Service accounts should skip 2FA or use API keys.
- Session lifecycle: verify with `GET /api/self`; logout `POST /api/auth/logout`. Stale session returns 401 with `{"meta":{"rc":"error","msg":"api.err.LoginRequired"}}`: re-login once and replay. **Never log in per request**: UniFi OS rate-limits `/api/auth/login` (429, `AUTHENTICATION_FAILED_LIMIT_REACHED`, lockout of a few minutes to ~30, triggered by frequency alone, https://github.com/home-assistant/core/issues/123015). Reuse the cookie until `x-token-expire-time`, exponential backoff on 429.
- Response envelope everywhere: `{"meta":{"rc":"ok"},"data":[...]}`. Error `meta.msg` values: `api.err.Invalid`, `api.err.LoginRequired`, `api.err.NoPermission`, `api.err.Ubic2faTokenRequired`, `api.err.NoSiteContext`.

### 2c. Verdict: does X-API-KEY work on classic endpoints?

**No, not reliably. Do not depend on it.** The weight of evidence says the classic `/proxy/network/api/...` surface authenticates via cookie + CSRF only:

- uchkunr/unifi-best-practices lists them as separate rows with separate auth (Integration = X-API-KEY; Classic = cookie session) (https://github.com/uchkunr/unifi-best-practices).
- UnPoller's Go library sends `X-API-Key` OR cookie+CSRF, never both, and built dedicated `/integration/v1/` fetchers hard-gated on the key (`ErrAPIKeyRequired`); it does physically attempt the key on classic GET paths, which is undocumented, version-dependent, and reported flaky (https://github.com/unpoller/unifi/blob/master/unifi.go, https://github.com/unpoller/unpoller/issues/765).
- Art of WiFi: legacy Network Application does not support API key auth; keys only exist for the admin surface (https://artofwifi.net/blog/unifi-api-authentication-local-admin-vs-api-key-vs-site-manager).
- gethomepage fixed its widget with cookie login + `/proxy/network` prefix, not keys (https://github.com/gethomepage/homepage/discussions/4753).

**Implementation decision:** cookie+CSRF is the required auth for all classic endpoints (especially writes). X-API-KEY is the auth for `/proxy/network/integration/v1/...`. Optionally probe the key on classic GETs with cookie fallback; never assume it for POST/PUT/DELETE.

---

## 3. Endpoint map with payload examples

Classic prefix on UniFi OS: `https://<gateway>/proxy/network/api/s/<site>/` (site default = `default`, MACs lowercase, objects keyed by Mongo `_id`). Integration prefix: `https://<gateway>/proxy/network/integration/v1/` (UUIDs everywhere). Full classic reference: https://ubntwiki.com/products/software/unifi-controller/api; Integration index: https://developer.ui.com/network/v10.3.58/llms.txt.

### Reads

| What | Endpoint |
|---|---|
| Site health (wan/lan/wlan/www/vpn subsystems) | `GET /stat/health` (classic) |
| Controller sysinfo | `GET /stat/sysinfo` |
| App version (Integration) | `GET /v1/info` |
| All devices, full (radio_table, port_table, stats) | `GET /stat/device`; by MAC `GET /stat/device/<mac>`; light `GET /stat/device-basic` |
| Devices (Integration) | `GET /v1/sites/{siteId}/devices`, `.../devices/{deviceId}`, `.../statistics/latest` (cpuUtilizationPct, memoryUtilizationPct, uptimeSec, load avgs, uplink tx/rxRateBps, per-radio frequencyGHz + txRetriesPct) |
| Active clients | `GET /stat/sta` (classic) or `GET /v1/sites/{siteId}/clients` (Integration) |
| All/historical clients | `GET /stat/alluser`; detail `GET /stat/user/<mac>`; known clients `GET /rest/user` |
| Gateway stats (incl. speedtest results) | `GET /stat/gateway` |
| Events (capped ~3000, newest first) | `GET /stat/event` |
| Alarms | `GET /stat/alarm` (some builds `GET /list/alarm`) |
| Rogue APs | `GET /stat/rogueap` (optional POST `{"within": <hours>}`) |
| DPI | `GET /stat/dpi` or `/stat/sitedpi`; per-client `GET /stat/stadpi` |
| Historical reports | `POST /stat/report/<interval>.<scope>` with intervals `5minutes|hourly|daily|monthly`, scopes `site|user|ap|gw|sw`. Body (epoch **ms**): `{"attrs":["bytes","wan-tx_bytes","wan-rx_bytes","wlan_bytes","num_sta","time"],"start":1720000000000,"end":1720600000000,"macs":["<mac>"]}` |
| Live events | `wss://<gateway>/proxy/network/wss/s/<site>/events` (cookie-authenticated upgrade) |

Classic query params on `stat/*`: `_limit`, `_start`, `_sort` (`-` prefix = desc), `attrs`, `within`, e.g. `/stat/sta?_limit=50&_sort=-last_seen&attrs=mac,hostname,ip,signal,tx_bytes,rx_bytes`. Integration pagination: `offset`/`limit` (max 200) + `filter` DSL (`and(name.isNull(), createdAt.gt(2025-01-01))`, functions `eq,ne,gt,ge,lt,le,like,in,notIn,isNull,isNotNull,isEmpty,contains,containsAny,containsAll,containsExactly`) (https://developer.ui.com/network/v10.3.58/filtering). Integration error schema: `{code, message, statusCode, statusName, timestamp, requestId, requestPath}` (https://developer.ui.com/network/v10.3.58/error-handling).

### Writes

**Radio config (classic only): AP channel / width / TX power.** Read-modify-write: `GET /stat/device`, mutate the matching radio objects, then `PUT /rest/device/<device_id>` with the **full `radio_table` array** (all radios present; single-band sends can throw `api.err.Invalid`):

```json
{
  "radio_table": [
    { "radio": "ng", "name": "wifi0", "channel": 6,  "ht": 20, "tx_power_mode": "custom", "tx_power": 20, "antenna_gain": 0, "min_rssi_enabled": false, "min_rssi": -80 },
    { "radio": "na", "name": "wifi1", "channel": 44, "ht": 80, "tx_power_mode": "high", "tx_power": 0 }
  ]
}
```

`radio`: `ng`=2.4GHz, `na`=5GHz, `6e`/`ax`=6GHz. `channel`: int or `"auto"`. `ht`: 20/40/80/160 (320 on 6GHz WiFi 7, inferred). `tx_power_mode`: `auto|low|medium|high|custom` (`tx_power` dBm only with `custom`). Verified against delian/node-unifiapi `set_ap_wireless` (https://github.com/delian/node-unifiapi) and Art of WiFi Client.php (legacy form POSTs a single flattened object to `/upd/device/<ap_id>`).

**WLAN (SSID):**
- Integration (10.0+): `GET/POST /v1/sites/{siteId}/wifi/broadcasts`, `GET/PUT/DELETE .../wifi/broadcasts/{wifiBroadcastId}`. Schema covers security config, enabled/hideName, client isolation, band steering, broadcastingFrequenciesGHz, MLO, hotspot config, blackout schedule.
- Classic: `GET/POST /rest/wlanconf`, `GET/PUT/DELETE /rest/wlanconf/<_id>`. Key fields: `name`, `x_passphrase`, `enabled`, `hide_ssid`, `security` (`open|wpapsk|wpaeap`), `wpa_mode` (`wpa2|wpa3`), `wpa_enc` (`ccmp`), `usergroup_id`, `wlangroup_id`, `networkconf_id`, `ap_group_ids`, `is_guest`. Update = fetch whole object, mutate, PUT back.

**Networks/VLANs:** Integration `GET/POST /v1/sites/{siteId}/networks`, `GET/PUT/DELETE .../networks/{networkId}`, `GET .../references` (10.0+). Classic `/rest/networkconf` with `name`, `purpose` (`corporate|guest|wan|vlan-only`), `vlan_enabled`, `vlan`, `ip_subnet`, `dhcpd_enabled`, `dhcpd_start`, `dhcpd_stop`, `networkgroup`, `enabled`.

**Client actions (classic `POST /cmd/stamgr`):**
```json
{"cmd":"block-sta","mac":"aa:bb:cc:dd:ee:ff"}
{"cmd":"unblock-sta","mac":"..."}
{"cmd":"kick-sta","mac":"..."}
{"cmd":"forget-sta","macs":["..."]}
{"cmd":"authorize-guest","mac":"...","minutes":60,"up":2000,"down":5000,"bytes":1024}
{"cmd":"unauthorize-guest","mac":"..."}
```
Integration equivalent (guest auth only): `POST /v1/sites/{siteId}/clients/{clientId}/actions` with `AUTHORIZE_GUEST_ACCESS` (optional `timeLimitMinutes` 1-1,000,000, `dataUsageLimitMBytes` 1-1,048,576, `rxRateLimitKbps`/`txRateLimitKbps` 2-100,000; returns `grantedAuthorization`) / `UNAUTHORIZE_GUEST_ACCESS`. Client config (fixed IP, name, notes): classic `PUT /rest/user/<client_id>`.

**Speedtest (classic `POST /cmd/devmgr`):**
```json
{"cmd":"speedtest"}
{"cmd":"speedtest-status"}
```
Status returns `rundate`, `latency`, `xput_download`, `xput_upload`, `status_download/upload/ping`; results also land in `GET /stat/gateway`.

**Device restart / other devmgr commands:**
- Integration: `POST /v1/sites/{siteId}/devices/{deviceId}/actions` body `{"action":"RESTART"}`; port: `POST .../interfaces/ports/{portIdx}/actions` `{"action":"POWER_CYCLE"}`; adopt `POST /v1/sites/{siteId}/devices` / unadopt `DELETE .../devices/{deviceId}` (10.1+).
- Classic `POST /cmd/devmgr`: `{"cmd":"restart","mac":"<mac>"}` (also `{"cmd":"restart","macs":["<mac>"],"reboot_type":"soft"}`), `adopt`, `force-provision`, `upgrade`, `{"cmd":"upgrade-external","mac":"...","url":"<fw_url>"}`, `set-locate`/`unset-locate`, `spectrum-scan`, `{"cmd":"power-cycle","mac":"<sw_mac>","port_idx":<n>}`.

**Backup (classic `POST /cmd/backup`):**
```json
{"cmd":"backup","days":"-1"}
{"cmd":"async-backup","days":0}
{"cmd":"list-backups"}
{"cmd":"delete-backup","filename":"<name.unf>"}
```
Response includes a download path; fetch raw via `GET /dl/backup/<filename>` (autobackups at `dl/autobackup/autobackup_<ver>_<date>_<ts>.unf`). **No API restore path**: restore is a manual web-UI, Super-Admin, fully disruptive flow. Treat the .unf download as the pre-change snapshot artifact and restore as break-glass only (https://help.ui.com/hc/en-us/articles/360008976393-Backups-and-Migration-in-UniFi, https://gist.github.com/corny/3cf7af0f6cb7a00adeb3). **.unf files are unencrypted and contain WiFi passphrases and RADIUS secrets**: chmod 600 and treat like credentials.

**Other classic-only config:** firewall rules `/rest/firewallrule[/<_id>]`, firewall groups `/rest/firewallgroup`, port forwards `/rest/portforward[/<rule_id>]`, port profiles `/rest/portconf`, static routes `/rest/routing`, traffic rules/routes `/rest/trafficrule`, `/rest/trafficroute`, site settings `/rest/setting[/<key>/<_id>]`, IPS `/rest/setting/ips`, site/admin mgmt `/cmd/sitemgr` (`add-site`, `delete-site`, `invite-admin`, `revoke-admin`), vouchers `/stat/voucher` + `/cmd/hotspot`.

**Integration-only extras (10.x):** firewall zones/policies CRUD + `/v1/sites/{siteId}/firewall/policies/ordering`, ACL rules CRUD + ordering, DNS policies CRUD, traffic matching lists CRUD, hotspot vouchers CRUD, switching reads (`/v1/sites/{siteId}/switching/lags`, `mc-lag-domains`, `switch-stacks`), plus read-only `/v1/countries`, `/v1/dpi/applications`, `/v1/sites/{siteId}/radius/profiles`, `/vpn/servers`, `/vpn/site-to-site-tunnels`, `/wans`, `/device-tags`.

**Site Manager (cloud):** `GET /v1/hosts[/{id}]`, `GET /v1/sites`, `GET /v1/devices`, `GET /v1/isp-metrics/{5m|1h}` (`duration` 24h for 5m; 7d/30d for 1h), `POST /v1/isp-metrics/{type}/query`, `GET /v1/sd-wan-configs[/{id}][/status]`. Connector proxy: `GET|POST|PUT|PATCH|DELETE /v1/connector/consoles/{id}/{*path}` (firmware >= 5.0.3; 100 req/min per console; 25s timeout; 10MB cap; org keys reach all org consoles). Rate limits: Site Manager v1 10,000 req/min with 429 + `Retry-After`; local Integration API has no documented limit.

---

## 4. Disruption matrix

Core mechanic: most site-wide or WLAN-scoped changes trigger simultaneous re-provisioning of every affected AP; radios restart and all wireless clients drop for ~30-60s. There is **no staggered/rolling provisioning and no maintenance window feature** (Ubiquiti staff, https://community.ui.com/questions/Which-Controller-Settings-Disconnect-All-Clients/17133e0e-c5d4-4869-b2b1-85224014cc2b).

| Mutation | Blast radius | Disruption |
|---|---|---|
| Client block/unblock/kick, guest auth | One client | That client only |
| Client fixed IP / name / notes | One client | Reconnect for IP change |
| LED locate, spectrum-scan | One device | Spectrum scan takes the AP's radios offline for the scan |
| Radio config change (channel/width/power) | One AP | That AP's radio restarts; its clients drop (~30-60s). Fleet changes: do one AP at a time |
| Device restart, PoE power-cycle | One device (+ downstream PoE) | Full outage on that device |
| Firmware upgrade | One device | Full reboot, minutes |
| WLAN/SSID edit (any field, incl. passphrase, VLAN, band) | **All APs broadcasting that WLAN group** | Simultaneous reprovision, all wireless clients drop. Mitigate with non-default WLAN groups scoping subsets of APs |
| Network/VLAN edits, port profiles | Switches/gateway | Reprovision; wired disruption possible |
| Site-wide services (syslog, NTP) | All APs | Full reprovision |
| Firewall/ACL/DNS policy changes | Gateway | Usually non-disruptive to WiFi, but can sever flows |
| WAN settings, some IDS/IPS toggles | **Whole network incl. your API session** | Gateway restart; risk of self-lockout mid-change |
| Speedtest | Gateway WAN | Saturates the WAN link during the test |
| Backup create | None | Safe |
| Backup restore | Everything | Controller restarts, all devices reprovision; manual only |
| Nightly Channel Optimization (Auto-Optimize) | All APs, midnight-3am | Known mystery-disconnect source; surface/disable deliberately (https://community.ui.com/questions/Nightly-Channel-Optimization/eb4278f5-74f4-4ad8-8899-548bbea61bac) |

Design implications: classify every tool by blast radius (per-client < per-device < per-WLAN-group < site-wide < gateway/WAN); warn before provisioning-triggering calls; **coalesce N sequential edits into one provision cycle** (each discrete change fires another cycle); schedule disruptive batches after hours. Precedent footgun: a wrong `network_group` via Terraform destroyed the WAN (https://github.com/paultyng/terraform-provider-unifi/issues/107).

---

## 5. Security requirements

**Credentials & least privilege**
- Dedicated **local-only** service admin (Restrict to Local Access Only, no ui.com account; Network app → Admins → add → toggle off Remote Management) (https://help.ui.com/hc/en-us/articles/28692158912279-Adding-Admins-in-UniFi). Viewer role for read-only tooling; Site Admin scoped to the Network app for mutations; never Super Admin/Owner ("Super Admins should be considered equivalent to Owners").
- API keys inherit the creator's role (no per-key scopes), so mint keys from least-privileged admins; consider two keys (read-only Viewer key, separate mutation key). Set expiry rather than Never Expires; keys are revocable individually.
- Store secrets outside the repo (macOS Keychain or a 600-permission env file). Never log the key, the TOKEN cookie, or `x_passphrase` fields. Scrub secrets from all tool output and logs (pattern: field names matching api_key/passphrase/password/secret/token → `***REDACTED***`).
- No 2FA on the service account (non-interactive) or use API keys which bypass login entirely.

**TLS**
- The console ships a self-signed cert; `verify=False` defeats MITM protection. Default posture: verify-on; offer **pin-on-first-use** (fetch cert once, verify identical cert thereafter, like unificontrol, https://unificontrol.readthedocs.io/en/latest/ssl_self_signed.html) with a re-pin path for cert rotation (firmware updates or custom certs break pins, https://github.com/nickovs/unificontrol/issues/25); make any insecure mode loud and explicit.
- Clean alternative: UniFi OS 4.1+ supports custom cert upload via WebUI, so a real hostname + Let's Encrypt cert enables normal CA verification (https://www.stevenz.blog/unifi-os-custom-ssl-tls-certificates/).

**Session & rate-limit hygiene**
- One long-lived session, cached until `x-token-expire-time`; re-login only on 401 `api.err.LoginRequired`; exponential backoff honoring `Retry-After` on 429; never login-per-request (lockout precedent: https://github.com/ep1cman/unifi-protect-backup/issues/171).

**Audit & safety patterns (adopt all)**
- Read-only by default; every mutation requires explicit `confirm=True`; `dry_run=True` returning the predicted change set and taking precedence over confirm (pete-builds, enuno patterns).
- Append-only JSONL audit log of ALL calls (dry-run and real) with secrets scrubbed; pre-change `.unf` snapshot before risky batches; composite ops capture pre-state and roll back on partial failure.
- Use UniFi's own audit surface as the independent record: Network 9.x Activity Logs plus **Settings → Control Plane → Integrations → Activity Logging (Syslog)** streaming CEF to a SIEM, keyed to the service account username (another reason for a dedicated admin per tool) (https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration).
- Concurrency: the API has no etags/revision IDs, so read-modify-write races last-write-wins; mitigate by re-fetching and diffing immediately before PUT.
- Prompt injection: client hostnames, SSIDs, and device names are attacker-controllable strings fed to the LLM; treat as untrusted data.

---

## 6. OSS landscape summary + differentiation

**No official Ubiquiti MCP server exists** as of mid-2026; cloud API keys still don't ship write access (https://github.com/us-all/unifi-mcp-server). The field:

| Project | API | Auth | Coverage | Safety | Traction |
|---|---|---|---|---|---|
| sirkirby/unifi-mcp (market leader) | Classic/private | user/pass local admin | 273+ tools (Network 180) | Preview-then-confirm, redaction, lazy loading | 509 stars, active |
| pete-builds/mcp-unifi (safety reference) | Official Integration | API key | 86 tools | dry_run everywhere, JSONL audit, replay CLI, composite rollback, signed containers | 13 stars |
| enuno/unifi-mcp-server | Official (3 modes) | API key | ~220 tools | confirm=True, tool profiles; dry-run/RBAC "planned" | v0.2.6 |
| us-all/unifi-mcp-server | Site Manager cloud only | cloud keys | 54 read-only tools | Severity verdicts, MSP prompts | active |
| claytono/go-unifi-mcp | go-unifi codegen | key or user/pass | 242 tools | Documents last-write-wins race; no read-only mode | early |
| ry-ops/unifi-mcp-server | Dual w/ fallback | key | 30+ tools, A2A | Safety levels, confirmations | 12 stars |
| Ruashots/unifi-network-mcp | Official Integration | key | Full CRUD | **None** | early |
| Libraries | aiounifi (HA engine, websocket, v92 July 2026), unpoller (2.7k stars, read-only metrics), Art of WiFi PHP client (1.3k stars, best private-API docs), node-unifi; unificontrol (archived, but had TLS pinning), pyunifi (abandoned) | | | | |

(https://github.com/sirkirby/unifi-mcp, https://github.com/pete-builds/mcp-unifi, https://github.com/enuno/unifi-mcp-server, https://github.com/Kane610/aiounifi, https://github.com/unpoller/unpoller, https://github.com/Art-of-WiFi/UniFi-API-client)

**Our differentiation (uncontested gaps):**
1. **Clearly-labeled hybrid**: official Integration API first, classic API only for the gaps (block/kick, radio config, speedtest, events, reports, backups), with per-tool API-provenance and risk/blast-radius labels. Nobody does this; everyone picks one side.
2. **CLI + MCP combo**: every existing project is MCP-only; a human-auditable CLI sharing the same core doesn't exist.
3. **TLS pinning for self-signed gateways**: ignored by every current MCP (only the archived unificontrol did it).
4. **Disruption-aware mutations**: blast-radius classification, change coalescing into one provision cycle, after-hours scheduling. No project models provisioning disruption.
5. **Concurrency mitigation**: pre-write re-fetch + diff (only claytono even documents the race).
6. **Prompt-injection posture** on attacker-controllable network strings (only DataKnifeAI mentions it).
7. Table stakes to match: dry_run + confirm + JSONL audit + secret redaction + read-only default + lazy tool loading (pete-builds/sirkirby set the bar; pete-builds has 13 stars, so the safety-first niche is validated but uncontested).

---

## 7. Open questions to verify live against the real gateway

1. **Installed Network app version**: `GET /proxy/network/integration/v1/info`. If 9.x, only the 15-endpoint Integration surface exists (no networks/WLAN/firewall CRUD); decide whether to update to 10.x or lean harder on classic.
2. **Does X-API-KEY work on any classic GET endpoints** on this exact build (e.g. `GET /proxy/network/api/s/default/stat/health` with only the key)? Probe read-only; expect no, but confirm before ruling out the hybrid convenience path.
3. **TOKEN JWT lifetime**: read `x-token-expire-time` and cookie `expires` at runtime; no documented default exists.
4. **Login lockout threshold/duration** on UniFi OS (undocumented; observed few minutes to ~30): do not probe destructively, but instrument for the 429 `AUTHENTICATION_FAILED_LIMIT_REACHED`.
5. **radio_table PUT semantics on this build**: confirm full-array requirement, whether `"auto"` channel round-trips, whether `ht: 320` is accepted on 6GHz radios (inferred, not spec-confirmed), and exact `reboot_type` enum values for `restart`.
6. **Speedtest on UCG-Max**: confirm `{"cmd":"speedtest"}` works on this gateway model and where results surface (`speedtest-status` vs `/stat/gateway` fields).
7. **Backup**: confirm `{"cmd":"backup","days":"-1"}` response shape and `/dl/backup/...` download with cookie auth; check whether any API can trigger the UniFi OS System Config (console-level) backup (none documented, Network-app .unf only).
8. **WebSocket feed**: confirm `wss://<gateway>/proxy/network/wss/s/default/events` upgrades with the TOKEN cookie and enumerate event types emitted.
9. **API key dialog expiry presets** in this Network version (named periods + Never Expires confirmed; exact list not enumerated anywhere).
10. **Viewer-role API key behavior**: verify a key minted by a View Only admin is actually rejected on Integration write endpoints (permission inheritance is documented but unverified in practice; watch for the Protect-style full-access bypass, https://github.com/home-assistant/core/issues/149762).
11. **CSRF rotation**: confirm whether this build rotates `x-updated-csrf-token` per response and whether stale tokens 403.
12. **Provisioning blast radius empirically**: time actual client drop during a single-AP radio change vs a WLAN edit, to calibrate the disruption matrix warnings.
13. **Classic error surface**: capture real payloads for `api.err.Invalid` on malformed radio_table to build actionable error messages.