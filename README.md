# unifi-agent

**Agentic command and control for UniFi networks.** A safety-first hybrid API client, MCP
server, and CLI that lets an LLM (or a cron job, or you) manage a UniFi network end to end
over the LAN: read full performance telemetry, tune AP radios, run speedtests, block
clients, toggle SSIDs, restart devices, take backups, and run unattended diagnostic loops
that surface optimization recommendations.

Built local-first and security-first: **no new inbound attack surface**, TLS certificate
pinning for the console's self-signed cert, secrets in the OS keyring (never in the repo or
the agent's context), and every mutation gated by a blast-radius-aware safety layer with
dry-run previews and an audit log.

> Not affiliated with Ubiquiti Inc. "UniFi" and "Ubiquiti" are trademarks of their owner.

## Why

UniFi has three partial APIs and no official MCP. The clean official Integration API can't
tune radios, run speedtests, or read events; the powerful classic API is unofficial and
needs a local login; and an API key doesn't reliably authenticate the classic endpoints.
Most tools pick one side and lose capability. `unifi-agent` uses **both** — the official
API for what it covers, the classic API for the gaps — and labels the provenance and risk
of every operation. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Features

- **Full visibility:** device/client inventory, per-subsystem health, per-AP radio status,
  events, historical reports, last speedtest — normalized into compact, LLM-friendly shapes.
- **Full control (guarded):** set radio channel/width/TX-power, enable/disable WLANs,
  block/unblock/kick clients, authorize guests, restart devices, power-cycle PoE ports,
  run speedtests, create backups.
- **Two front ends, one core:** a stdio **MCP server** (17 tools) and a **CLI** that share
  the same safety-guarded facade.
- **Diagnostic loops:** `diagnose` / `watch` run read-only passes that flag offline
  devices, weak clients, subsystem warnings, and co-channel interference, and emit JSONL for
  cron/launchd or an LLM loop.
- **Safety by construction:** read-only mode, blast-radius ceiling, mandatory `confirm`,
  dry-run previews, pre-change backups, race-mitigating read-modify-write, redacted audit
  log. See [`SECURITY.md`](SECURITY.md).

## Quickstart

```bash
uv venv && source .venv/bin/activate && uv pip install -e ".[dev]"
unifi-agent setup      # stores API key / local admin in the OS keyring, pins the TLS cert
unifi-agent doctor     # verifies connectivity + each API surface
unifi-agent overview
```

(Not activating the venv? Prefix commands with `uv run`, e.g. `uv run unifi-agent doctor`.)

Full provisioning (creating the API key and a dedicated local admin) is in
[`docs/SETUP.md`](docs/SETUP.md).

## CLI examples

```bash
unifi-agent devices                     # inventory
unifi-agent radios                      # per-AP channel/width/power
unifi-agent diagnose                    # findings + optimization recommendations
unifi-agent speedtest-last              # most recent ISP test

# Every write previews first; add --confirm to apply.
unifi-agent set-radio "Main Floor U6+" 5GHz --channel 44 --width 80 --dry-run
unifi-agent set-radio "Main Floor U6+" 5GHz --channel 44 --width 80 --confirm
unifi-agent speedtest --confirm
unifi-agent block aa:bb:cc:dd:ee:ff --confirm

unifi-agent watch --interval 300        # unattended diagnostic loop (JSONL)
```

## MCP

```json
{
  "mcpServers": {
    "unifi": {
      "command": "/absolute/path/to/repo/.venv/bin/unifi-mcp",
      "env": { "UNIFI_HOST": "192.168.1.1" }
    }
  }
}
```

Use the absolute path to the venv's `unifi-mcp` (or `uv run --directory /path/to/repo
unifi-mcp`); `unifi-mcp` is not on the MCP client's PATH. Read tools are always safe. Write tools return a preview (`applied: false`) with the blast
radius and predicted change unless called with `confirm=true`; the model must preview,
show you, and confirm. The server is **stdio only** — it opens no port.

## Safety model (short version)

| Control | Default | Effect |
|---|---|---|
| `UNIFI_READ_ONLY` | `false` | `true` refuses all writes |
| `UNIFI_MAX_BLAST_RADIUS` | `device` | refuses mutations above this radius |
| `confirm` on writes | required | without it, writes only preview |
| `UNIFI_BACKUP_BEFORE_RISKY` | `true` | snapshot before `wlan_group`+ changes |
| TLS | `pin` | trust-on-first-use pinning of the self-signed cert |

Blast radii: `none < client < device < wlan_group < site < gateway`. WLAN edits and radio
changes reprovision APs and drop their wireless clients for ~30-60s; the tool warns before
these and encourages one-AP-at-a-time changes.

## Remote access

Don't expose the tool or the console to the internet. To manage on the go, VPN back into
the LAN (the gateway already runs a WireGuard server) and use the same commands. Same
security properties, zero new surface.

## Development

```bash
uv venv && source .venv/bin/activate && uv pip install -e ".[dev]"
python -m pytest -q          # 47 tests: safety, radio logic, redaction, auth/CSRF, TLS pinning, facade, loops
ruff check src tests
```

## License

MIT — see [`LICENSE`](LICENSE).
