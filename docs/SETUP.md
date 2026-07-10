# Setup

One-time provisioning. Two credentials unlock the full surface; you can start with just the
API key. Secrets go into your OS keyring and are never seen by the agent or written to the
repo.

## 0. Install

```bash
git clone <your-fork> unifi-agent && cd unifi-agent
uv venv && source .venv/bin/activate && uv pip install -e ".[dev]"
# or: python -m venv .venv && source .venv/bin/activate && pip install -e .
```

Activate the venv (as above) before running `unifi-agent`, or prefix each command with
`uv run` (e.g. `uv run unifi-agent doctor`).

## 1. Create an Integration API key (covers most reads and writes)

This key drives the official Integration API: devices, clients, networks, WLANs, firewall,
guest auth, device restart, port power-cycle.

1. Open your UniFi console (`https://<gateway-ip>` on the LAN, or unifi.ui.com).
2. Go to **Settings → Control Plane → Integrations**.
3. Click **Create API Key**, name it `unifi-agent`, and copy the value (shown once).
   - For a read-only agent, create the key from a **View Only** admin (keys inherit the
     creator's role).

## 2. (Optional but recommended) Create a dedicated local admin

The classic API — needed for **AP radio tuning, client block/kick, speedtest, events,
historical reports, and backups** — authenticates with a local admin login. Use a
dedicated, least-privilege, local-only account. Never your owner account.

1. **Settings → Admins & Users → Admins → Add Admin.**
2. Choose **Restrict to Local Access Only** (no ui.com account, no remote management).
3. Give it a role scoped to the Network application. Use **View Only** for a read-only
   agent, or **Site Admin** (Network) if you want it to make changes. Avoid Super Admin.
4. Set a strong unique password. Do **not** enable 2FA on this service account (it is
   non-interactive).

## 3. Store the secrets

```bash
unifi-agent setup
```

This prompts for the gateway address, then stores the API key and (optionally) the local
admin login in your OS keyring, writes non-secret settings to
`~/.config/unifi-agent/.env`, and pins the gateway's TLS certificate. It never echoes a
secret.

Prefer environment variables (CI, containers)? Set `UNIFI_HOST`, `UNIFI_API_KEY`,
`UNIFI_USERNAME`, `UNIFI_PASSWORD` instead — they take precedence over the keyring.

## 4. Verify

```bash
unifi-agent doctor
```

You should see TLS reachable (matches pin), and `ok` for each API surface you configured.
Then try:

```bash
unifi-agent overview
unifi-agent radios
unifi-agent diagnose
```

## 5. Wire up the MCP server

Point your MCP client at the stdio server. Example `claude_desktop_config.json` /
Claude Code MCP entry:

```json
{
  "mcpServers": {
    "unifi": {
      "command": "/absolute/path/to/unifi-agent/.venv/bin/unifi-mcp",
      "env": { "UNIFI_HOST": "192.168.1.1" }
    }
  }
}
```

Use the **absolute path** to the venv's `unifi-mcp` — the MCP client does not inherit your
shell PATH, so a bare `unifi-mcp` fails to launch. Alternatively use
`"command": "uv", "args": ["run", "--directory", "/path/to/unifi-agent", "unifi-mcp"]`.

Secrets are read from the keyring, so they do not go in the MCP config. Restart the client
and ask it to "give me a UniFi overview" or "preview setting the 5GHz radio on Main Floor
to channel 44." Writes always preview first and require an explicit confirm.

## Tuning safety

Environment variables (or `~/.config/unifi-agent/.env`):

- `UNIFI_READ_ONLY=true` — refuse all writes (great for an always-on monitoring agent).
- `UNIFI_MAX_BLAST_RADIUS=client|device|wlan_group|site|gateway` — refuse mutations above
  this (default `device`).
- `UNIFI_BACKUP_BEFORE_RISKY=true` — snapshot before `wlan_group`+ changes (default on).
- `UNIFI_TIMEOUT=30` — HTTP request timeout in seconds.
- `UNIFI_ENV_FILE=/path/to/my.env` — load an extra env file (opt-in; a cwd `.env` is not
  auto-loaded, by design).

These non-secret settings can also live in `~/.config/unifi-agent/.env` (which `setup`
writes and preserves across re-runs).
