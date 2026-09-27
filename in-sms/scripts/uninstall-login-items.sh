#!/bin/bash
# Reverses install-login-items.sh: stops and unregisters both LaunchAgents
# and removes the installed binaries + plists.
#
# Does NOT touch ~/Library/Application Support/OTPForwarder/{identity.json,
# messages.enc,config.json} — your pairing and history are left alone. Pass
# --purge-data to also wipe that (you'd need to re-pair afterward).
set -euo pipefail

DATA_DIR="$HOME/Library/Application Support/OTPForwarder"
BIN_DIR="$DATA_DIR/bin"
AGENTS_DIR="$HOME/Library/LaunchAgents"
APP_BUNDLE="$HOME/Applications/OTPForwarder.app"
UID_NUM="$(id -u)"

OTPD_LABEL="com.otpforwarder.otpd"
APP_LABEL="com.otpforwarder.app"

echo "==> Stopping LaunchAgents"
for label in "$OTPD_LABEL" "$APP_LABEL"; do
	launchctl bootout "gui/$UID_NUM/$label" 2>/dev/null || true
	rm -f "$AGENTS_DIR/$label.plist"
done

echo "==> Removing installed binaries"
rm -rf "$BIN_DIR" "$APP_BUNDLE"

if [[ "${1:-}" == "--purge-data" ]]; then
	echo "==> Purging pairing/history data (you will need to re-pair)"
	rm -rf "$DATA_DIR"
fi

echo "==> Done. otpd and OTPForwarder will no longer start at login."
echo "    (Your existing pairing/history was kept — rerun with --purge-data to wipe it too.)"
