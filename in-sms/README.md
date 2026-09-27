# OTP Forwarder — Mac receiver

Go daemon (`daemon/`) + SwiftUI menu bar app (`app/`) that receives forwarded SMS from a paired
Android phone over the LAN. See `docs/PROTOCOL.md` and `docs/ARCHITECTURE.md` for the design;
this file is just the practical "how do I run/debug/reset this" reference.

## Where everything lives

```
~/Library/Application Support/OTPForwarder/
  identity.json    pairing keys + storage key (0600, no Keychain — by design)
  messages.enc     encrypted SMS history (0600)
  config.json      settings (max messages, port, clipboard delay, ...)
  otpd.sock        Unix socket the menu bar app talks to
  bin/             installed otpd + OTPForwarder binaries (only if autostart is installed)

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

This is the "quick" path — no `.app` bundle, no code signing, just `launchd` running the two
built binaries. Because of that, the Settings window's "Launch at Login" toggle is currently a
no-op (it calls `SMAppService`, which needs a real signed `.app` bundle) — manage autostart with
these scripts instead. Quitting the app from its menu works normally (won't auto-relaunch);
`otpd` restarts on crash (`KeepAlive: true`) since it has no "Quit" of its own — stop it with the
uninstall script or `launchctl bootout gui/$(id -u)/com.otpforwarder.otpd`, not `kill`.

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
  LaunchServices-registered `.app` bundle. Running via `swift run`/`swift build` debug binaries
  disables notifications gracefully (checked via `Bundle.main.bundlePath.hasSuffix(".app")`); the
  release binaries installed by `install-login-items.sh` are still bare executables too, so this
  still applies until real `.app` packaging exists.
