"""Command-line interface: the human- and cron-facing twin of the MCP server.

Every capability the MCP exposes is here too, plus setup/doctor/trust for provisioning and
diagnostics. Reads print rich tables (or ``--json``); writes honor ``--confirm`` /
``--dry-run`` and print the guard's preview when not applied.
"""

from __future__ import annotations

import asyncio
import json as jsonlib
import logging
from typing import Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .config import KR_API_KEY, KR_PASSWORD, KR_USERNAME, default_config_dir, load_settings
from .errors import UniFiAgentError
from .facade import UniFiAgent
from .loops import diagnostics_once, monitor
from .secrets import SecretStore, redact
from .transport import certificate_fingerprint, fetch_peer_certificate, pin_certificate

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Agentic command and control for UniFi networks (safety-first).",
)
console = Console()
err_console = Console(stderr=True)


def _run(coro: Any) -> Any:
    try:
        return asyncio.run(coro)
    except UniFiAgentError as exc:
        err_console.print(f"[red]{type(exc).__name__}:[/red] {exc}")
        raise typer.Exit(1) from exc


def _emit(data: Any, as_json: bool) -> None:
    # Scrub secrets (WiFi passphrases, device auth keys, tokens) before any output — write
    # results echo full config objects. Mirrors the MCP server's redaction.
    safe = redact(data)
    if as_json:
        console.print_json(jsonlib.dumps(safe, default=str))
    else:
        console.print(safe)


def _cell(value: Any) -> str:
    """Render an untrusted value as a rich table cell with markup escaped.

    Device/client names and SSIDs are LAN-controlled strings; without escaping, a hostname
    like ``[red]evil[/red]`` or ``[link=...]`` would inject terminal markup.
    """
    return escape(str(value))


# --- provisioning -------------------------------------------------------------

@app.command()
def setup() -> None:
    """Interactively store connection settings and secrets (secrets go to the OS keyring)."""
    cfg_dir = default_config_dir()
    cfg_dir.mkdir(parents=True, exist_ok=True)
    console.print("[bold]unifi-agent setup[/bold] — secrets are stored in your OS keyring, "
                  "never in plaintext files.\n")

    host = typer.prompt("Gateway LAN address", default="192.168.1.1")
    site = typer.prompt("Site name", default="default")

    # Non-secret settings -> config-dir .env. Merge with any existing file so re-running
    # setup does not wipe safety settings (UNIFI_READ_ONLY, UNIFI_MAX_BLAST_RADIUS, ...).
    from .secrets import _load_dotenv  # local import: internal helper

    env_path = cfg_dir / ".env"
    values = _load_dotenv(env_path)
    values.update({"UNIFI_HOST": host, "UNIFI_SITE": site})
    values.setdefault("UNIFI_TLS", "pin")
    env_path.write_text("\n".join(f"{k}={v}" for k, v in values.items()) + "\n")
    env_path.chmod(0o600)

    store = SecretStore(cfg_dir)
    try:
        if typer.confirm("Store an Integration API key? (covers most reads/writes)", default=True):
            key = typer.prompt("  API key", hide_input=True)
            store.set(KR_API_KEY, key.strip())
            console.print("  [green]stored API key in keyring[/green]")
        if typer.confirm(
            "Store a LOCAL admin login? (needed for radios, speedtest, events, backups)",
            default=False,
        ):
            console.print("  [yellow]Use a dedicated local-only, least-privilege admin — "
                          "not your owner account.[/yellow]")
            user = typer.prompt("  Local admin username")
            pw = typer.prompt("  Local admin password", hide_input=True)
            store.set(KR_USERNAME, user.strip())
            store.set(KR_PASSWORD, pw)
            console.print("  [green]stored local admin credentials in keyring[/green]")
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]Keyring error:[/red] {exc}\n"
                          "Install a keyring backend, or set UNIFI_* env vars instead.")
        raise typer.Exit(1) from exc

    console.print("\nPinning the gateway certificate…")
    try:
        settings = load_settings()
        fp = pin_certificate(settings, repin=True)
        console.print(f"  [green]pinned[/green] {fp}")
        console.print("  Compare this against Settings → Control Plane → Console in the UI.")
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"  [yellow]Could not pin now:[/yellow] {exc} (will pin on first use)")

    console.print("\n[bold green]Setup complete.[/bold green] Run `unifi-agent doctor` to verify.")


@app.command()
def trust(repin: bool = typer.Option(False, "--repin", help="Replace an existing pin.")) -> None:
    """Pin (or re-pin) the gateway's TLS certificate and print its fingerprint."""
    settings = load_settings()
    host = settings.base_url.split("://", 1)[-1]
    seen = certificate_fingerprint(fetch_peer_certificate(host.split(":")[0]))
    console.print(f"Gateway certificate fingerprint (SHA-256):\n  [cyan]{seen}[/cyan]")
    fp = pin_certificate(settings, repin=repin)
    console.print(f"[green]Pinned:[/green] {fp}")


@app.command()
def doctor() -> None:
    """Verify configuration, TLS pin, and each configured API surface."""
    _run(_doctor())


async def _doctor() -> None:
    settings = load_settings()
    table = Table(title="unifi-agent doctor", show_header=True, header_style="bold")
    table.add_column("Check")
    table.add_column("Result")
    table.add_row("Host", settings.base_url)
    table.add_row("Site", settings.site)
    table.add_row("TLS mode", settings.tls_mode)
    table.add_row("Read-only", str(settings.read_only))
    table.add_row("Max blast radius", settings.max_blast_radius.label)

    # TLS
    try:
        host = settings.base_url.split("://", 1)[-1].split(":")[0]
        fp = certificate_fingerprint(fetch_peer_certificate(host))
        pinned = settings.pinned_cert_path
        state = "matches pin" if (pinned.is_file()
                                  and certificate_fingerprint(pinned.read_text()) == fp) \
            else ("no pin yet" if not pinned.is_file() else "MISMATCH")
        table.add_row("TLS reachable", f"[green]yes[/green] ({state})")
    except Exception as exc:  # noqa: BLE001
        table.add_row("TLS reachable", f"[red]no[/red] ({exc})")

    async with UniFiAgent(settings) as agent:
        # Integration API
        if settings.has_integration_auth():
            try:
                info = await agent.integration.info()
                ver = info.get("applicationVersion") or info.get("version") or info
                table.add_row("Integration API", f"[green]ok[/green] (Network {ver})")
            except Exception as exc:  # noqa: BLE001
                table.add_row("Integration API", f"[red]fail[/red] ({exc})")
        else:
            table.add_row("Integration API", "[dim]not configured[/dim]")

        # Classic API
        if settings.has_classic_auth():
            try:
                health = await agent.classic.health()
                subs = ", ".join(h.get("subsystem", "?") for h in health)
                table.add_row("Classic API", f"[green]ok[/green] ({subs})")
            except Exception as exc:  # noqa: BLE001
                table.add_row("Classic API", f"[red]fail[/red] ({exc})")
        else:
            table.add_row("Classic API", "[dim]not configured[/dim]")

    console.print(table)


# --- reads --------------------------------------------------------------------

@app.command()
def overview(json: bool = typer.Option(False, "--json")) -> None:
    """Network snapshot: health, device/client counts, APs, gateway."""
    data = _run(_with(lambda a: a.overview()))
    _emit(data, json)


@app.command()
def devices(json: bool = typer.Option(False, "--json")) -> None:
    """List UniFi devices."""
    data = _run(_with(lambda a: a.list_devices()))
    if json:
        _emit(data, True)
        return
    t = Table("Name", "Model", "Type", "Online", "Clients", "Version")
    for d in data:
        t.add_row(_cell(d.get("name")), _cell(d.get("model")), _cell(d.get("type")),
                  "●" if d.get("online") else "○", _cell(d.get("clients")),
                  _cell(d.get("version")))
    console.print(t)


@app.command()
def clients(json: bool = typer.Option(False, "--json")) -> None:
    """List connected clients."""
    data = _run(_with(lambda a: a.list_clients()))
    if json:
        _emit(data, True)
        return
    t = Table("Name", "IP", "Band", "Ch", "Signal", "AP")
    for c in sorted(data, key=lambda x: (x.get("signal_dbm") or 0)):
        t.add_row(_cell(c.get("name")), _cell(c.get("ip")), _cell(c.get("band") or "wired"),
                  _cell(c.get("channel") or ""), _cell(c.get("signal_dbm") or ""),
                  _cell(c.get("ap_mac") or ""))
    console.print(t)


@app.command()
def health(json: bool = typer.Option(False, "--json")) -> None:
    """Per-subsystem health."""
    _emit(_run(_with(lambda a: a.health())), bool(json))


@app.command()
def events(limit: int = 50, hours: int = 24, json: bool = typer.Option(False, "--json")) -> None:
    """Recent controller events."""
    _emit(_run(_with(lambda a: a.events(limit=limit, within_hours=hours))), bool(json))


@app.command()
def radios(json: bool = typer.Option(False, "--json")) -> None:
    """Per-AP radio configuration."""
    data = _run(_with(lambda a: a.radio_status()))
    if json:
        _emit(data, True)
        return
    t = Table("AP", "Online", "Clients", "Band", "Channel", "Width", "TX power")
    for ap in data:
        for r in ap.get("radios", []):
            t.add_row(_cell(ap.get("name")), "●" if ap.get("online") else "○",
                      _cell(ap.get("clients")), _cell(r.get("band")), _cell(r.get("channel")),
                      _cell(r.get("width_mhz")), _cell(r.get("tx_power_mode")))
    console.print(t)


@app.command(name="speedtest-last")
def speedtest_last(json: bool = typer.Option(False, "--json")) -> None:
    """Show the most recent ISP speedtest result."""
    _emit(_run(_with(lambda a: a.speedtest_last())), bool(json))


# --- writes -------------------------------------------------------------------

_confirm_opt = typer.Option(False, "--confirm", help="Actually apply the change.")
_dry_opt = typer.Option(False, "--dry-run", help="Preview only.")


@app.command()
def speedtest(confirm: bool = _confirm_opt, dry_run: bool = _dry_opt) -> None:
    """Run an ISP speedtest (saturates WAN ~20-30s)."""
    _emit(_run(_with(lambda a: a.run_speedtest(confirm=confirm, dry_run=dry_run))), True)


@app.command(name="set-radio")
def set_radio(
    ap: str,
    band: str,
    channel: str | None = typer.Option(None),
    width: int | None = typer.Option(None, help="Channel width MHz"),
    tx_power_mode: str | None = typer.Option(None),
    tx_power: int | None = typer.Option(None),
    confirm: bool = _confirm_opt,
    dry_run: bool = _dry_opt,
) -> None:
    """Set channel/width/TX-power for one band on one AP. Reprovisions that AP."""
    ch: Any = channel
    if channel is not None and channel.isdigit():
        ch = int(channel)
    _emit(_run(_with(lambda a: a.set_radio(
        ap, band, channel=ch, width_mhz=width, tx_power_mode=tx_power_mode,
        tx_power=tx_power, confirm=confirm, dry_run=dry_run))), True)


@app.command()
def restart(mac: str, confirm: bool = _confirm_opt, dry_run: bool = _dry_opt) -> None:
    """Reboot a device by MAC or name."""
    _emit(_run(_with(lambda a: a.restart_device(mac, confirm=confirm, dry_run=dry_run))), True)


@app.command()
def block(mac: str, confirm: bool = _confirm_opt, dry_run: bool = _dry_opt) -> None:
    """Block a client by MAC."""
    _emit(_run(_with(lambda a: a.block_client(mac, confirm=confirm, dry_run=dry_run))), True)


@app.command()
def unblock(mac: str, confirm: bool = _confirm_opt, dry_run: bool = _dry_opt) -> None:
    """Unblock a client by MAC."""
    _emit(_run(_with(lambda a: a.unblock_client(mac, confirm=confirm, dry_run=dry_run))), True)


@app.command()
def kick(mac: str, confirm: bool = _confirm_opt, dry_run: bool = _dry_opt) -> None:
    """Force a client to reconnect."""
    _emit(_run(_with(lambda a: a.kick_client(mac, confirm=confirm, dry_run=dry_run))), True)


@app.command(name="authorize-guest")
def authorize_guest(mac: str, minutes: int = 60, confirm: bool = _confirm_opt,
                    dry_run: bool = _dry_opt) -> None:
    """Authorize a guest client for a time window."""
    _emit(_run(_with(lambda a: a.authorize_guest(mac, minutes=minutes, confirm=confirm,
                                                 dry_run=dry_run))), True)


@app.command(name="unauthorize-guest")
def unauthorize_guest(mac: str, confirm: bool = _confirm_opt, dry_run: bool = _dry_opt) -> None:
    """Revoke a guest client's access."""
    _emit(_run(_with(lambda a: a.unauthorize_guest(mac, confirm=confirm, dry_run=dry_run))), True)


@app.command(name="power-cycle")
def power_cycle(switch: str, port: int, confirm: bool = _confirm_opt,
                dry_run: bool = _dry_opt) -> None:
    """Power-cycle a PoE port on a switch (by switch MAC/name and port index)."""
    _emit(_run(_with(lambda a: a.power_cycle_port(switch, port, confirm=confirm,
                                                  dry_run=dry_run))), True)


@app.command()
def locate(mac: str, off: bool = typer.Option(False, "--off"), confirm: bool = _confirm_opt,
           dry_run: bool = _dry_opt) -> None:
    """Toggle a device's locate LED."""
    _emit(_run(_with(lambda a: a.set_locate(mac, not off, confirm=confirm, dry_run=dry_run))), True)


@app.command(name="toggle-wlan")
def toggle_wlan(wlan: str, enable: bool = typer.Option(..., "--enable/--disable"),
                confirm: bool = _confirm_opt, dry_run: bool = _dry_opt) -> None:
    """Enable or disable a WLAN (SSID). Reprovisions all APs broadcasting it."""
    _emit(_run(_with(lambda a: a.toggle_wlan(wlan, enable, confirm=confirm, dry_run=dry_run))), True)


@app.command()
def backup() -> None:
    """Create a configuration backup (.unf) on the console."""
    _emit(_run(_with(lambda a: a.create_backup())), True)


# --- diagnostics & loops ------------------------------------------------------

@app.command()
def diagnose(json: bool = typer.Option(False, "--json")) -> None:
    """Run one diagnostic pass with findings and optimization recommendations."""
    report = _run(_with(lambda a: diagnostics_once(a)))
    if json:
        _emit(report, True)
        return
    console.print(f"[bold]Summary:[/bold] {_cell(report['summary'])}")
    if report["findings"]:
        console.print("\n[bold]Findings[/bold]")
        for f in report["findings"]:
            # detail may embed LAN-controlled device/client names -> escape markup.
            console.print(f"  ({_cell(f['severity'])}) {_cell(f['area'])}: {_cell(f['detail'])}")
    if report["recommendations"]:
        console.print("\n[bold]Recommendations[/bold]")
        for r in report["recommendations"]:
            console.print(
                f"  ({_cell(r.get('priority',''))}) {_cell(r['area'])}: {_cell(r['detail'])}")
    if not report["findings"] and not report["recommendations"]:
        console.print("[green]No issues found.[/green]")


@app.command()
def watch(interval: int = 300, iterations: int | None = None) -> None:
    """Run the diagnostic loop, emitting one JSONL report per pass (Ctrl-C to stop)."""
    _run(_with(lambda a: monitor(a, interval_s=interval, iterations=iterations)))


@app.command()
def capabilities(json: bool = typer.Option(False, "--json")) -> None:
    """Show which APIs are configured and current safety settings."""
    _emit(_run(_with(lambda a: a.capabilities())), bool(json))


@app.command(name="mcp")
def mcp_server() -> None:
    """Launch the stdio MCP server (equivalent to the `unifi-mcp` command)."""
    from .mcp.server import main as mcp_main
    mcp_main()


async def _with(fn: Any) -> Any:
    settings = load_settings()
    async with UniFiAgent(settings) as agent:
        return await fn(agent)


def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    app()


if __name__ == "__main__":
    main()
