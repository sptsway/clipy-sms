#!/bin/bash
# Builds otpd and the SwiftUI app in release mode, wraps the app in a real
# (ad-hoc signed) .app bundle at ~/Applications/OTPForwarder.app, installs
# otpd under ~/Library/Application Support/OTPForwarder/bin/, and registers
# two LaunchAgents so both start automatically at login.
#
# The .app wrapper exists so you have a normal, UI-only way to relaunch the
# menu bar app if you ever quit it: double-click OTPForwarder.app in
# ~/Applications (or find it via Spotlight/Launchpad) — no Terminal needed.
# It's still unsigned by a real Developer ID, so macOS will show an
# "unidentified developer" prompt the first time; right-click → Open once to
# clear it.
#
# This is still the "quick" autostart path (no universal binary, no
# SMAppService) — see docs/ARCHITECTURE.md §6 for the fuller alternative.
# Until that exists, the Settings window's "Launch at Login" toggle is a
# no-op; use this script (and uninstall-login-items.sh) to manage autostart.
#
# Re-running this script after rebuilding is safe and expected — it
# reinstalls everything and reloads the LaunchAgents.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$HOME/Library/Application Support/OTPForwarder"
BIN_DIR="$DATA_DIR/bin"
LOG_DIR="$HOME/Library/Logs/OTPForwarder"
AGENTS_DIR="$HOME/Library/LaunchAgents"
APPS_DIR="$HOME/Applications"
APP_BUNDLE="$APPS_DIR/OTPForwarder.app"
UID_NUM="$(id -u)"

OTPD_LABEL="com.otpforwarder.otpd"
APP_LABEL="com.otpforwarder.app"

echo "==> Building otpd"
(cd "$REPO_ROOT/daemon" && go build -o "/tmp/otpd.$$" ./cmd/otpd)

echo "==> Building OTPForwarder (release)"
(cd "$REPO_ROOT/app" && swift build -c release)
APP_BIN="$(cd "$REPO_ROOT/app" && swift build -c release --show-bin-path)/OTPForwarder"

mkdir -p "$BIN_DIR" "$LOG_DIR" "$AGENTS_DIR" "$APPS_DIR"
mv "/tmp/otpd.$$" "$BIN_DIR/otpd"
chmod +x "$BIN_DIR/otpd"

echo "==> Building OTPForwarder.app bundle"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
cp "$APP_BIN" "$APP_BUNDLE/Contents/MacOS/OTPForwarder"
chmod +x "$APP_BUNDLE/Contents/MacOS/OTPForwarder"

cat > "$APP_BUNDLE/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>OTPForwarder</string>
	<key>CFBundleIdentifier</key>
	<string>com.otpforwarder.app</string>
	<key>CFBundleName</key>
	<string>OTPForwarder</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>0.1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>LSUIElement</key>
	<true/>
	<key>LSMinimumSystemVersion</key>
	<string>13.0</string>
</dict>
</plist>
EOF

echo "==> Ad-hoc signing the bundle"
codesign --force --sign - "$APP_BUNDLE"

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
		<string>$APP_BUNDLE/Contents/MacOS/OTPForwarder</string>
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
# KeepAlive is false for the app so both the menu's "Quit" action AND
# manually quitting actually quit it, instead of launchd immediately
# relaunching it — restart it yourself via OTPForwarder.app when you want it
# back. otpd has no "Quit" of its own, so KeepAlive=true there just means
# "restart it if it ever crashes" — stop it deliberately with
# `launchctl bootout`, not `kill`.

echo "==> Activating LaunchAgents"
for label in "$OTPD_LABEL" "$APP_LABEL"; do
	launchctl bootout "gui/$UID_NUM/$label" 2>/dev/null || true
	sleep 1 # bootout tears down asynchronously; an immediate bootstrap can race it and fail
	launchctl bootstrap "gui/$UID_NUM" "$AGENTS_DIR/$label.plist"
done

echo "==> Done."
echo "    otpd and OTPForwarder will now start automatically at login."
echo "    To restart the menu bar app yourself: open ~/Applications/OTPForwarder.app"
echo "    (first launch needs a right-click → Open, since it's not signed by a real Developer ID)"
echo "    Logs: $LOG_DIR/"
echo "    To stop autostart: scripts/uninstall-login-items.sh"
