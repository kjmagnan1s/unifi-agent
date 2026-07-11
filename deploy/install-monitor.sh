#!/usr/bin/env bash
# Install the unifi-agent monitoring LaunchAgent on macOS.
# Renders the template with your paths, loads it, and triggers one run to verify.
#
# Usage: deploy/install-monitor.sh [UNIFI_HOST]
#   UNIFI_HOST defaults to 192.168.1.1.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/.venv/bin/unifi-agent"
HOST="${1:-192.168.1.1}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/unifi-agent"
LABEL="com.unifi-agent.monitor"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

[ -x "$BIN" ] || { echo "error: $BIN not found. Install the project first (uv pip install -e .)." >&2; exit 1; }
mkdir -p "$CONFIG_DIR" "$HOME/Library/LaunchAgents"

sed -e "s#__UNIFI_AGENT_BIN__#$BIN#g" \
    -e "s#__UNIFI_HOST__#$HOST#g" \
    -e "s#__CONFIG_DIR__#$CONFIG_DIR#g" \
    "$REPO/deploy/com.unifi-agent.monitor.plist.template" > "$PLIST"

# Reload cleanly (bootout may fail if not loaded; ignore).
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
launchctl kickstart "gui/$(id -u)/$LABEL"

echo "Installed $LABEL"
echo "  plist:  $PLIST"
echo "  log:    $CONFIG_DIR/monitor.jsonl"
echo "  errors: $CONFIG_DIR/monitor.err"
echo "Tail the log with:  tail -f \"$CONFIG_DIR/monitor.jsonl\""
echo "Uninstall with:     launchctl bootout gui/$(id -u)/$LABEL && rm \"$PLIST\""
