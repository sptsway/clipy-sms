#!/bin/bash
# Builds otpd and the SwiftUI app in release mode, installs them under
# ~/Library/Application Support/OTPForwarder/bin/, and registers two
# LaunchAgents so both start automatically at login.
#
# This is the "quick" autostart path (no .app bundle, no code signing) — see
# docs/ARCHITECTURE.md §6 for the alternative (a real .app + SMAppService),
# which is more work but makes the Settings window's "Launch at Login"
# toggle functional. Until that exists, that toggle is a no-op; use this
# script (and uninstall-login-items.sh) to manage autostart instead.
#
# Re-running this script after rebuilding is safe and expected — it
# reinstalls the binaries and reloads the LaunchAgents.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$HOME/Library/Application Support/OTPForwarder"
BIN_DIR="$DATA_DIR/bin"
LOG_DIR="$HOME/Library/Logs/OTPForwarder"
AGENTS_DIR="$HOME/Library/LaunchAgents"
UID_NUM="$(id -u)"

OTPD_LABEL="com.otpforwarder.otpd"
APP_LABEL="com.otpforwarder.app"

echo "==> Building otpd"
(cd "$REPO_ROOT/daemon" && go build -o "/tmp/otpd.$$" ./cmd/otpd)

echo "==> Building OTPForwarder (release)"
(cd "$REPO_ROOT/app" && swift build -c release)
APP_BIN="$(cd "$REPO_ROOT/app" && swift build -c release --show-bin-path)/OTPForwarder"

mkdir -p "$BIN_DIR" "$LOG_DIR" "$AGENTS_DIR"
mv "/tmp/otpd.$$" "$BIN_DIR/otpd"
chmod +x "$BIN_DIR/otpd"
cp "$APP_BIN" "$BIN_DIR/OTPForwarder"
chmod +x "$BIN_DIR/OTPForwarder"

echo "==> Writing LaunchAgent plists"
cat > "$AGENTS_DIR/$OTPD_LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$OTPD_LABEL</string>
	<key>ProgramArguments</key>
	<array>
		<string>$BIN_DIR/otpd</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>$LOG_DIR/otpd.log</string>
	<key>StandardErrorPath</key>
	<string>$LOG_DIR/otpd.log</string>
</dict>
</plist>
EOF

cat > "$AGENTS_DIR/$APP_LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$APP_LABEL</string>
	<key>ProgramArguments</key>
	<array>
		<string>$BIN_DIR/OTPForwarder</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
	<key>StandardOutPath</key>
	<string>$LOG_DIR/app.log</string>
	<key>StandardErrorPath</key>
	<string>$LOG_DIR/app.log</string>
</dict>
</plist>
EOF
# KeepAlive is false for the app so the menu's "Quit" action actually quits
# it instead of launchd immediately relaunching it. otpd has no "Quit" of
# its own, so KeepAlive=true there just means "restart it if it ever
# crashes" — stop it deliberately with `launchctl bootout`, not `kill`.

echo "==> Activating LaunchAgents"
for label in "$OTPD_LABEL" "$APP_LABEL"; do
	launchctl bootout "gui/$UID_NUM/$label" 2>/dev/null || true
	launchctl bootstrap "gui/$UID_NUM" "$AGENTS_DIR/$label.plist"
done

echo "==> Done. otpd and OTPForwarder will now start automatically at login."
echo "    Logs: $LOG_DIR/"
echo "    To stop autostart: scripts/uninstall-login-items.sh"
