# OTP Forwarder — Architecture

Companion to `PROTOCOL.md` (which owns exact wire formats). This document covers how the pieces
fit together: process boundaries, storage, IPC, and the SwiftUI app.

## 1. Component diagram

```
                         LAN (Wi-Fi)
   Android phone  ───────────────────────────►  otpd  (Go daemon)
   (built separately)   POST /v1/pair                │
                         POST /v1/msg                 │  owns: keys, storage,
                         mDNS: _otpfwd._tcp  ◄─────────  networking, pairing state
                                                       │
                                                       │ Unix domain socket
                                                       │ ~/Library/Application Support/
                                                       │   OTPForwarder/otpd.sock (0600)
                                                       │ newline-delimited JSON,
                                                       │ request/response + push events
                                                       ▼
                                          SwiftUI menu bar app
                                          owns: clipboard, notifications,
                                          settings UI, QR rendering
```

The daemon is the only process that ever touches the network or the private keys. The UI is a
thin client over the Unix socket and never sees `mac_priv`, `k_p2m`, or `k_m2p` — it receives
already-decrypted message content and status, matching the spec's "who does what" split.

## 2. Repo layout

```
in-sms/
  docs/
    PROTOCOL.md
    ARCHITECTURE.md
  daemon/                    # Go module: otpd
    go.mod
    cmd/
      otpd/                  # daemon entrypoint
      fakephone/             # test CLI standing in for the Android app
    internal/
      crypto/                # ECDH/HKDF/HMAC/AEAD wrappers, all stdlib
      pairing/                # pairing window state machine
      store/                  # message store + secrets file + config file
      server/                 # HTTP handlers for /v1/pair, /v1/msg
      ipc/                    # Unix socket protocol + event bus
      mdns/                   # dns-sd subprocess wrapper
      ratelimit/              # per-IP token bucket
  app/                        # SwiftUI Xcode project
    OTPForwarder/
      OTPForwarderApp.swift
      MenuContent.swift
      PairWindow.swift
      SettingsWindow.swift
      IPCClient.swift
      ClipboardManager.swift
```

## 3. Go daemon (`otpd`)

### 3.1 Build

Plain Go, no Cgo anywhere — the two things that would normally need it (Keychain, native mDNS)
are handled without it (see below), so the build stays a simple:

```
GOOS=darwin GOARCH=arm64  go build -o otpd-arm64 ./cmd/otpd
GOOS=darwin GOARCH=amd64  go build -o otpd-amd64 ./cmd/otpd
lipo -create -output otpd otpd-arm64 otpd-amd64
```

The universal `otpd` binary is embedded in the `.app` bundle (Milestone 5).

### 3.2 mDNS advertisement

Go's standard library has no mDNS support. Per the user's decision, the daemon shells out to
macOS's built-in `dns-sd` tool rather than hand-rolling a responder or adding a dependency:

```go
exec.Command("dns-sd", "-R", macName, "_otpfwd._tcp", "local", strconv.Itoa(port))
```

`internal/mdns` starts this subprocess when the daemon starts listening, keeps a handle to it for
the daemon's lifetime, and restarts it if it exits unexpectedly (`dns-sd -R` normally runs until
killed). No TXT records are registered — the QR payload is the actual source of truth for
connection details (`PROTOCOL.md` §2).

### 3.3 Concurrency model

- `net/http`'s default one-goroutine-per-connection model for the HTTP server.
- A single struct, guarded by one `sync.Mutex`, holds the daemon's mutable state shared between
  the pairing and message handlers: current pairing window (if any), pinned phone key material,
  `last_ctr`, and the dedupe cache. All handler logic that reads or mutates this state does so
  under the lock; the lock is held only for the in-memory check/update, never across disk I/O or
  network calls.
- The pairing window's 120-second expiry is a `time.AfterFunc` that takes the same lock to close
  the window.

### 3.4 Storage — no Keychain

Per the user's explicit decision, **the daemon does not use the macOS Keychain**. All state,
secret or not, lives in plain files under:

```
~/Library/Application Support/OTPForwarder/
  config.json      # non-secret settings, mode 0600
  identity.json     # pairing + key material + counter, mode 0600
  messages.enc      # encrypted message store, mode 0600
  otpd.sock          # Unix domain socket, mode 0600
```

**`config.json`** — user-visible settings, mirrors the Settings window (§5): `max_messages` (10–1000,
default 100), `auto_copy_newest`, `clipboard_clear_seconds` (default 30), `port` (default 47820),
`launch_at_login`, `notifications_enabled`. Not secret; kept at `0600` anyway for consistency with
the rest of the directory.

**`identity.json`** — everything that would otherwise have gone in the Keychain:

```json
{
  "pairing_version": 1,
  "mac_priv": "<b64url, P-256 scalar>",
  "phone_pub": "<b64url, 65-byte point>",
  "device_name": "<string>",
  "k_p2m": "<b64url, 32 bytes>",
  "k_m2p": "<b64url, 32 bytes>",
  "key_id": "<b64url, 8 bytes>",
  "last_ctr": 41,
  "storage_key": "<b64url, 32 bytes, AES-256 key for messages.enc>"
}
```

Written atomically (write to a temp file in the same directory, `fsync`, `rename` over the real
path) on every pairing event and after every accepted message (for `last_ctr`). Absent entirely
when unpaired.

> **Accepted tradeoff:** without the Keychain, these secrets are protected only by Unix file
> permissions (`0600`, owner-only). Unlike a Keychain item, they are not gated behind login/biometric
> re-authentication, they're readable by any process running as the same user (including a
> compromised app with no special entitlement), and they sit in plaintext in backups unless the
> volume itself is encrypted (FileVault). This is a deliberate simplification the user chose over
> the added complexity of Cgo/Security.framework or shelling out to the `security` CLI — worth
> restating here so it's an informed choice, not an oversight.

**`messages.enc`** — the message store, AES-256-GCM encrypted with `storage_key` (a random key
generated once, at first run, before any pairing exists, and never rotated). FIFO eviction: once
the stored count exceeds `config.max_messages`, the oldest record is dropped before the new one is
appended. Each record:

```json
{
  "id": "<uuid from the message>",
  "received_at": "<RFC3339>",
  "sender": "<string>",
  "body": "<string>",
  "sim": 1
}
```

*(Assumption, revised from the original prompt.md: no OTP-code extraction at all.* A first pass
tried a keyword-proximity regex, then a bare 4-8-digit-run regex; both produced false positives
or missed real OTP messages that don't contain a recognizable keyword or fall outside that digit
range. The daemon now stores and forwards the full body untouched — the UI displays and copies
the whole SMS rather than a parsed-out code.)

### 3.5 HTTP server (`internal/server`)

Two routes, `POST /v1/pair` and `POST /v1/msg`, implementing `PROTOCOL.md` §3–§4 exactly. The
listener is built from `net.Interfaces()`, binding only to addresses on non-loopback,
non-link-local interfaces (i.e. real LAN interfaces) — never `0.0.0.0`, so the daemon doesn't
silently also answer on a VPN interface or similar. Body size and rate limiting (see
`internal/ratelimit`) are enforced by middleware ahead of the route handlers.

### 3.6 IPC (`internal/ipc`)

Unix domain socket at `otpd.sock`, mode `0600`, created with the parent directory itself also
locked down to the owner. Protocol: newline-delimited JSON, one JSON value per line, either
direction.

**Requests** (UI → daemon), each `{"id": "<request id>", "method": "<name>", "params": {...}}`,
answered with `{"id": "<same id>", "result": {...}}` or `{"id": "<same id>", "error": "<string>"}`:

| Method | Purpose |
|---|---|
| `pair.start` | begin a new pairing window; returns the QR URI and `exp` |
| `pair.status` | current pairing-window state (waiting / paired / failed / idle) |
| `pair.cancel` | close an in-progress pairing window early |
| `device.status` | paired device name + last-seen time, or "not paired" |
| `device.unpair` | wipe `identity.json`'s key material |
| `messages.list` | paginated, `{offset, limit}` in, for the chunk-of-20 "Older" submenus |
| `messages.get` | full record for one message id (used for ⌥-click / notification tap) |
| `history.clear` | wipe `messages.enc` |
| `settings.get` / `settings.set` | read/write `config.json` |

**Events** (daemon → UI, unsolicited, no `id`), `{"type": "event", "event": "<name>", "data": {...}}`:

| Event | Fires when |
|---|---|
| `message.new` | a message passes validation and is stored |
| `pairing.status` | pairing state changes (attempt used, succeeded, expired, failed) |
| `device.lastSeen` | a paired phone's message updates the last-seen timestamp |

A single connection carries both request/response traffic and events, multiplexed by the presence
of `id` (requests/responses) vs `type: "event"` (push).

### 3.7 Rate limiting (`internal/ratelimit`)

A `sync.Mutex`-guarded `map[string]*bucket` keyed by source IP, each bucket a simple token-bucket
(capacity 20, refill 10/sec — `PROTOCOL.md` §4.7) implemented with only `sync` and `time`. Entries
for IPs idle longer than a few minutes are swept periodically so the map doesn't grow unbounded
over a long-running daemon's lifetime.

## 4. `fakephone` CLI (`cmd/fakephone`)

A standalone Go binary that behaves exactly as the eventual Android app will, for end-to-end
testing before it exists:

- Takes a pasted `otpfwd://...` pairing URI (or scans it from a file/stdin).
- Performs the full pairing exchange against the real daemon over the LAN.
- Offers a REPL or flag-driven mode to send test `POST /v1/msg` payloads with adjustable `ctr`,
  `ts`, `sender`, `body` — including intentionally-invalid ones (stale timestamp, replayed id,
  non-increasing counter, tampered ciphertext) to exercise the daemon's rejection paths manually.

## 5. SwiftUI app

- Deployment target macOS 13, `LSUIElement = YES` (no Dock icon), `MenuBarExtra(.menu)` styled to
  look like a native `NSMenu`.
- **`MenuContent`** — disabled "Recent" header, latest 5 messages as `body  —  Sender · HH:mm`,
  "Older" chunked into submenus of 20 (fetched via `messages.list`), a status line (paired device
  + last seen, via `device.status`/`device.lastSeen` events), then `Pair New Phone…`, `Unpair`,
  `Clear History`, `Settings…`, `Quit`.
- **`PairWindow`** — calls `pair.start`, renders the returned URI as a QR code with
  `CIQRCodeGenerator`, shows a live countdown to `exp`, live status from `pairing.status` events,
  and closes itself automatically on the `paired` status.
- **`SettingsWindow`** — bound to `settings.get`/`settings.set`: max messages, auto-copy newest,
  clipboard clear delay, port, launch at login (toggles `SMAppService.agent(...)` registration),
  notifications on/off.
- **`ClipboardManager`** — a menu click copies the full SMS `body` (per §3.4's revised assumption,
  there is no separate "code" to distinguish with a modifier key anymore). Every write marks the
  pasteboard item transient/concealed (`org.nspasteboard.TransientType` / `ConcealedType`) so
  clipboard managers skip it. After the configured delay, clears the pasteboard **only if**
  `NSPasteboard.general.changeCount` still equals the value captured right after the copy — i.e.
  nothing else was copied in between.
- **Notifications** — `UNUserNotificationCenter`, triggered off `message.new` events (when enabled
  in settings), showing the body + sender; tapping one copies the body via the same
  `ClipboardManager` path used for a menu click.

## 6. Packaging & lifecycle (detailed in Milestone 5)

Documented now at a high level for consistency with the rest of this doc:

- The universal `otpd` binary (§3.1) is embedded in the `.app` bundle.
- The SwiftUI app registers `otpd` as a long-running agent via `SMAppService.agent(...)` so it
  keeps receiving messages even when the menu bar UI isn't open, per the spec.
- Code signing (and notarization, since it's launched outside the App Store sandboxable flow) is
  required for `SMAppService` registration to succeed reliably.
- The first time `otpd` binds a listening socket on a LAN interface, macOS will prompt the user
  for local-network permission; the README (Milestone 5) documents this so a first-time user isn't
  confused by the OS prompt.

## Assumptions to confirm

- No Keychain anywhere; all secrets in `identity.json` at `0600` — see the callout in §3.4 for the
  accepted security tradeoff.
- mDNS via shelling out to `dns-sd`, kept alive as a supervised subprocess for the daemon's lifetime.
- File layout under `~/Library/Application Support/OTPForwarder/` (`config.json`, `identity.json`,
  `messages.enc`, `otpd.sock`) as the single source of truth for daemon state — no other location.
- IPC method/event names listed in §3.6 (`pair.start`, `messages.list`, `message.new`, etc.) are
  proposed now so both the daemon and the SwiftUI app can be built against the same contract; happy
  to rename before Milestone 3 if something reads better.
- `storage_key` is generated once at first run (before any pairing) and never rotated.
- Listener interface filter (LAN-only, skip loopback/link-local) as described in §3.5.
