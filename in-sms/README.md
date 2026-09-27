# OTP Forwarder — Mac receiver

Go daemon (`daemon/`) + SwiftUI menu bar app (`app/`) that receives forwarded SMS from a paired
Android phone over the LAN. See `docs/PROTOCOL.md` and `docs/ARCHITECTURE.md` for the design;
this file is just the practical "how do I run/debug/reset this" reference.

## Using the menu

Each row shows `OTP:<code-or-nil>  SMS preview…  —  Sender · HH:mm`. The OTP code is a
display-only best-effort guess (keyword-proximity regex, client-side) — the daemon always stores
and forwards the full, untouched body regardless of whether a code was guessed. The preview is
length-capped because macOS sizes the *whole* dropdown menu to its widest row, so an uncapped
long SMS would stretch every item in the menu, not just that one row.

**Click** a row to open a small borderless popup near the click, with the full message as
selectable text and a Copy button. It behaves like a normal window (not always on top, doesn't
follow you across Spaces) but has no title bar and won't show in Mission Control. (An earlier
version tried keeping this fully inside the dropdown via a submenu — NSMenu items can never
support text selection, so that traded selection away entirely; this popup gets selection back
at the cost of being a separate — if minimal — window.)

## Where everything lives

```
~/Library/Application Support/OTPForwarder/
  identity.json    pairing keys + storage key (0600, no Keychain — by design)
  messages.enc     encrypted SMS history (0600)
  config.json      settings (max messages, port, clipboard delay, ...)
  otpd.sock        Unix socket the menu bar app talks to
  bin/otpd         installed daemon binary (only if autostart is installed)

~/Applications/OTPForwarder.app   the menu bar app, as a real double-clickable bundle
                                   (only if autostart is installed)

~/Library/Logs/OTPForwarder/
  otpd.log         daemon stdout/stderr (only if autostart is installed)
  app.log          menu bar app stdout/stderr (only if autostart is installed)

~/Library/LaunchAgents/
  com.otpforwarder.otpd.plist
  com.otpforwarder.app.plist
```

`messages.enc` is encrypted — don't expect to read it directly. Use the IPC socket (below) to
actually inspect message history.

## Running in dev mode

Two terminals, from `in-sms/`:

```
cd daemon && go run ./cmd/otpd
cd app && swift run
```

The app auto-connects to the daemon over the Unix socket. If it can't connect, it shows "Daemon
not running" in the menu — it never fabricates fake data (that used to be true of a `MockIPCClient`
that's since been deleted).

## Autostart at login

```
scripts/install-login-items.sh     # builds release binaries, installs 2 LaunchAgents
scripts/uninstall-login-items.sh   # stops + removes them (pass --purge-data to also wipe pairing/history)
```

`install-login-items.sh` builds `otpd` and a release build of the app, wraps the app in a real
(ad-hoc signed) `.app` bundle at `~/Applications/OTPForwarder.app`, and registers two
`~/Library/LaunchAgents` plists so both start automatically at every login. Re-running it after
pulling new code is safe and expected — it rebuilds and reloads both cleanly.

The Settings window's "Launch at Login" toggle is still a no-op (it calls `SMAppService`, which
needs a proper Developer-ID-signed bundle registered through the App Store/notarization path,
not an ad-hoc one) — manage autostart with these scripts instead of that toggle.

## Starting, quitting, restarting

The daemon (`otpd`) and the UI (`OTPForwarder`) are two independent processes with two
independent LaunchAgents. Quitting one never affects the other.

- **Quit the UI**: use its menu's "Quit" item (or `⌘Q`/Force Quit if needed). The daemon keeps
  running — pairing and message forwarding are unaffected, you just lose the menu bar icon.
- **Restart the UI, no Terminal needed**: open `~/Applications/OTPForwarder.app` again —
  double-click it in Finder, find it in Spotlight (`⌘Space`, type "OTPForwarder"), or Launchpad.
  The very first time, macOS will refuse with "unidentified developer" since it's only ad-hoc
  signed — right-click → Open once to clear that; every launch after works normally, including
  double-click.
- **The daemon should never need manual restarting**: it has `RunAtLoad` (starts at every login)
  and `KeepAlive: true` (auto-restarts if it ever crashes) — nothing in the UI can stop it, and a
  reboot brings it back on its own. If you ever do need to stop it deliberately, use
  `scripts/uninstall-login-items.sh` or `launchctl bootout gui/$(id -u)/com.otpforwarder.otpd`,
  not `kill` (which `KeepAlive` would just immediately undo).
- **Pairing survives all of the above.** It's persisted to `identity.json`, not held in memory —
  restarting either process, or both, never requires re-pairing the phone. Only "Unpair" or
  deleting `identity.json` does.
- **The UI can't accidentally run twice.** An `flock`-based single-instance guard makes a
  duplicate launch (e.g. LaunchAgent + a manual `open` racing each other) a silent no-op instead
  of a second menu bar icon.

## Debugging via the IPC socket

The menu bar app talks to `otpd` over `~/Library/Application Support/OTPForwarder/otpd.sock`
with newline-delimited JSON. You can talk to it directly with `nc`:

```bash
SOCK=~/"Library/Application Support/OTPForwarder/otpd.sock"

# Recent messages
echo '{"id":"1","method":"messages.list","params":{"offset":0,"limit":10}}' | nc -U "$SOCK" -w 2

# Pairing / device status
echo '{"id":"2","method":"pair.status"}'    | nc -U "$SOCK" -w 2
echo '{"id":"3","method":"device.status"}'  | nc -U "$SOCK" -w 2

# Start a new pairing window (prints the QR URI — parse it or feed it to fakephone, see below)
echo '{"id":"4","method":"pair.start"}' | nc -U "$SOCK" -w 2

# Settings
echo '{"id":"5","method":"settings.get"}' | nc -U "$SOCK" -w 2

# Wipe history / unpair
echo '{"id":"6","method":"history.clear"}'  | nc -U "$SOCK" -w 2
echo '{"id":"7","method":"device.unpair"}'  | nc -U "$SOCK" -w 2
```

Full method/event list is in `docs/ARCHITECTURE.md` §3.6.

## Testing without a phone: `fakephone`

`daemon/cmd/fakephone` behaves like the Android app for testing — pairs against a real `otpd`
and sends messages, including deliberately-invalid ones.

```bash
cd daemon

# 1. Get a pairing URI (e.g. via pair.start above, or from the app's Pair window)
go run ./cmd/fakephone pair -state /tmp/fakephone-state.json "otpfwd://pair?..."

# 2. Send a real message
go run ./cmd/fakephone send -state /tmp/fakephone-state.json -sender "38221" -body "Your OTP is 482913"

# Negative-test flags (each should be rejected with HTTP 400):
go run ./cmd/fakephone send -state /tmp/fakephone-state.json -tamper                 # tampered ciphertext
go run ./cmd/fakephone send -state /tmp/fakephone-state.json -ts-offset -300         # stale timestamp
go run ./cmd/fakephone send -state /tmp/fakephone-state.json -id "some-existing-id"  # replay
go run ./cmd/fakephone send -state /tmp/fakephone-state.json -ctr 0                  # reused/old counter
```

## Running the test suite

```bash
cd daemon && go build ./... && go vet ./... && go test ./...
cd app && swift build
```

## Troubleshooting

- **"address already in use" / pairing suddenly breaks for someone else testing**: something is
  already bound to port 47820 or the IPC socket. Check before starting a second `otpd`:
  ```bash
  ps aux | grep otpd
  lsof -nP -iTCP:47820 -sTCP:LISTEN
  ```
  Starting a second `otpd` against the same `~/Library/Application Support/OTPForwarder/` removes
  and replaces the live one's socket file — it will break whatever the first instance was doing.
  Only ever run one `otpd` at a time against that directory.
- **Phone needs to re-pair unexpectedly**: `identity.json` was deleted, wiped (`--purge-data`), or
  you hit "Unpair." Pairing otherwise survives daemon restarts fine — see above.
- **QR code says "doesn't look like an OTP Forwarder pairing QR code" on the phone**: almost
  certainly a base64url-vs-standard-base64 encoding mismatch somewhere upstream of the QR, not a
  daemon bug — the real daemon's `pair.start` always uses base64url-without-padding
  (`base64.RawURLEncoding` in `daemon/internal/daemon/handler.go`).
- **Notifications don't show / crash the app**: `UNUserNotificationCenter` requires a real,
  LaunchServices-registered `.app` bundle — it isn't just a nice-to-have, calling it from a bare
  executable actually *crashes* the process (`bundleProxyForCurrentProcess is nil`). Running via
  `swift run`/`swift build` debug binaries disables notifications gracefully instead of crashing
  (checked via `Bundle.main.bundlePath.hasSuffix(".app")`). The `~/Applications/OTPForwarder.app`
  bundle `install-login-items.sh` creates satisfies this, so notifications work normally for the
  installed/autostart version, launched either via the LaunchAgent or manually.
