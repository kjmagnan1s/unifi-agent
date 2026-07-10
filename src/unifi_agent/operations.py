"""The catalog of mutating operations with their blast-radius classification.

Keeping this in one place makes the safety posture auditable at a glance and lets the
CLI/MCP surface consistent risk labels. Blast radius drives the guard's ceiling check;
``provisions`` drives the "clients will drop" warning.
"""

from __future__ import annotations

from .safety import BlastRadius, Operation

OPERATIONS: dict[str, Operation] = {
    "create_backup": Operation(
        "create_backup", BlastRadius.NONE,
        disruption="No service impact. Produces a .unf snapshot.",
    ),
    "set_locate": Operation(
        "set_locate", BlastRadius.NONE,
        disruption="Toggles a device's locate LED. No service impact.",
    ),
    "set_client_name": Operation(
        "set_client_name", BlastRadius.NONE,
        disruption="Renames a client. No service impact.",
    ),
    "block_client": Operation(
        "block_client", BlastRadius.CLIENT,
        disruption="Disconnects and blocks one client.",
    ),
    "unblock_client": Operation(
        "unblock_client", BlastRadius.CLIENT,
        disruption="Unblocks one client.",
    ),
    "kick_client": Operation(
        "kick_client", BlastRadius.CLIENT,
        disruption="Forces one client to reconnect.",
    ),
    "authorize_guest": Operation(
        "authorize_guest", BlastRadius.CLIENT,
        disruption="Grants guest access to one client.",
    ),
    "unauthorize_guest": Operation(
        "unauthorize_guest", BlastRadius.CLIENT,
        disruption="Revokes guest access from one client.",
    ),
    "run_speedtest": Operation(
        "run_speedtest", BlastRadius.DEVICE,
        disruption="Saturates the WAN uplink for ~20-30s; other users see slower "
                   "internet during the test. No disconnects.",
    ),
    "restart_device": Operation(
        "restart_device", BlastRadius.DEVICE,
        disruption="Reboots one device; it and anything downstream go offline for the "
                   "reboot (~1-2 min).",
    ),
    "restart_gateway": Operation(
        "restart_gateway", BlastRadius.GATEWAY,
        disruption="Reboots the gateway itself; the ENTIRE network (WAN + all clients) goes "
                   "down for 1-2 min, including this management session.",
    ),
    "power_cycle_port": Operation(
        "power_cycle_port", BlastRadius.DEVICE,
        disruption="Power-cycles one PoE port; the device on it reboots.",
    ),
    "set_radio": Operation(
        "set_radio", BlastRadius.DEVICE, provisions=True,
        disruption="Reprovisions one AP; its wireless clients drop for ~30-60s.",
    ),
    "toggle_wlan": Operation(
        "toggle_wlan", BlastRadius.WLAN_GROUP, provisions=True,
        disruption="Reprovisions every AP broadcasting this WLAN group; all their "
                   "wireless clients drop for ~30-60s.",
    ),
    "update_wlan": Operation(
        "update_wlan", BlastRadius.WLAN_GROUP, provisions=True,
        disruption="Reprovisions every AP broadcasting this WLAN group; all their "
                   "wireless clients drop for ~30-60s.",
    ),
}
