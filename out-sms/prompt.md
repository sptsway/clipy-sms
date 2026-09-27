# Project: OTP Forwarder — Android sender (minimal)

This is the phone-side companion to `../in-sms` (a Go daemon + SwiftUI menu bar app running on a
Mac). The Mac side receives forwarded SMS over the LAN; this app's only job is to read incoming
SMS on the phone and forward them, encrypted, to a paired Mac. Nothing else.

**The wire protocol is already fixed and documented — do not redesign it.** Read these before
writing any code:

- `../in-sms/docs/PROTOCOL.md` — the normative spec: QR payload, pairing HTTP exchange, exact
  HMAC/HKDF byte constructions, the message envelope's binary layout, validation rules. This app
  must match it byte-for-byte or it simply won't interoperate with the Mac daemon.
- `../in-sms/docs/ARCHITECTURE.md` — how the Mac side is structured (context only, not binding on
  you).
- `../in-sms/docs/CRYPTO_IMPLEMENTATION.md` — a Go-specific implementation guide written for the
  Mac daemon's author, who is hand-writing that side's crypto. Not directly usable on Android, but
  worth skimming for the *gotchas* section (nonce freshness, the counter sentinel bug, "every
  failure returns the same generic response") — those apply to any implementation, not just Go's.

**Status of the Mac side as of writing this**: the daemon's IPC/process skeleton exists and is
tested, but its `/v1/pair` and `/v1/msg` HTTP handlers and all the crypto are still being written
by hand by the project owner, following `CRYPTO_IMPLEMENTATION.md`. There may be nothing live to
test against yet — build this app strictly to the documented spec regardless, and say so plainly
if that leaves you blocked on end-to-end testing rather than guessing at what the Mac side does.

## Scope: minimal, on purpose

Read incoming SMS, forward each one encrypted to the paired Mac. That's the whole app.

**Non-goals** (resist scope creep even if they'd be easy to add):
- No message history/list UI on the phone — the Mac owns history, not this app.
- No settings screen beyond pairing/unpairing.
- No multi-Mac or multi-account support — one phone, one paired Mac, like the Mac side's own design.
- No mDNS-based Mac discovery — rely solely on the QR code's `hosts`/`port` fields.
- No dual-SIM UI polish — just pass whatever slot index is convenient for the optional `sim` field.
- No local outbox/dead-letter queue for failed sends — if forwarding fails after retries, the SMS
  simply stays on the phone as normal; that's an acceptable limitation for a minimal v1.

## Working style (same spirit as the Mac project)

- Before writing code, write a short `docs/DESIGN.md` covering the **Android-specific** pieces
  only (app structure, permissions, background-execution strategy, local storage). Do not restate
  the wire protocol — point at `../in-sms/docs/PROTOCOL.md` instead. Stop for review.
- Implement in the milestones below; stop after each one and summarize what was done and how to
  test it.
- Ask before adding any third-party dependency. This matters more here than it did on the Mac
  side — see "Open decisions" below, several of which are exactly this question.
- Where this document leaves something unstated, make a concrete choice, document it as an
  assumption, and flag it for review — don't silently guess and don't stall waiting for direction
  on something small.

## Suggested platform

- Kotlin, single-Activity, Jetpack Compose for the (very small) UI.
- A reasonable minSdk (26+ covers the vast majority of devices and has full `javax.crypto`
  support) — but confirm this with the user rather than locking it in unilaterally.
- Permissions: `RECEIVE_SMS`, `INTERNET`, `ACCESS_NETWORK_STATE`, `CAMERA` (QR scan), and possibly
  a foreground-service permission depending on the background-reliability decision below.

## Architecture sketch

- **One screen**: QR scanner + pairing status (paired device name, last sent time, Unpair button).
  There is nothing else to show — no message list.
- **A BroadcastReceiver** for `android.provider.Telephony.SMS_RECEIVED`, which does the
  encrypt-and-POST work for each incoming SMS. Whether a bare manifest-registered receiver is
  reliable enough or this needs a foreground service (Android's background-execution limits can
  kill plain receivers on some OEMs) is an open decision — see below.
- **Local storage**: the phone's own generated P-256 keypair, the Mac's pinned public key, the two
  derived session keys, `key_id`, `pairing_version`, and — critically — the phone's own outgoing
  message counter, which must be persisted durably and never reused across app restarts (see
  "Pairing" and "Forwarding" below).

## Pairing flow (phone's side of `PROTOCOL.md` §3)

1. Scan the `otpfwd://pair?...` QR code; parse `v`, `mac_pub`, `token`, `hosts`, `port`, `name`,
   `exp`. Reject if `exp` has already passed.
2. Generate a fresh P-256 keypair for this pairing (discard any previous one).
3. Compute `mac = HMAC-SHA256(token, "pair-v1" || mac_pub || phone_pub)` exactly as
   `PROTOCOL.md` §3.3 specifies (raw point bytes, not base64, in the HMAC input).
4. `hosts` is a comma-separated list of the Mac's LAN IPv4 addresses — try each in turn (with a
   short timeout) against `POST http://<host>:<port>/v1/pair` until one responds; the Mac may have
   more than one active interface.
5. Body: `{"v":1, "phone_pub": "<b64url>", "device_name": "<string>", "mac": "<b64url>"}`.
6. Derive session keys per §3.4 (`ikm = ECDH(phone_priv, mac_pub)`, `salt = token`,
   `info = "otpfwd-v1" || mac_pub || phone_pub"`, HKDF-SHA256 → 64 bytes → `k_p2m`/`k_m2p`, plus
   `key_id` if you're using the same derived-tag scheme the Mac side settled on — check
   `PROTOCOL.md` §4.2, since this was an assumption filled in on the Mac side, not something the
   original spec dictated; make sure both sides agree).
7. Verify the response `{"ok": true, "confirm": "<b64url>"}` by recomputing
   `HMAC-SHA256(k_m2p, "confirm-v1")` and comparing — treat any mismatch or non-200 response
   identically (don't try to distinguish *why* pairing failed to the user beyond "pairing failed").
8. On success, persist everything from step 2 and 6, and reset the outgoing counter to a state
   where the next message's `ctr` is `0` (see `PROTOCOL.md` §4.3 — the first message after a fresh
   pairing always starts at `ctr = 0`).

## Forwarding flow (phone's side of `PROTOCOL.md` §4)

1. On receiving an SMS: durably reserve the next `ctr` value *before* attempting to send (persist
   it, then use that fixed value for every retry of this particular message). This makes retries
   safe — the Mac's rule is `ctr` strictly increasing, not contiguous, so a dropped message that
   never got sent just leaves a gap, which is fine; what must never happen is reusing a `ctr` that
   was already sent successfully.
2. Build the plaintext `{"id": "<uuid>", "ts": <unix ms>, "ctr": <n>, "sender": "...", "body": "...", "sim": <int?>}`.
3. Encrypt with `k_p2m` into the exact binary envelope from `PROTOCOL.md` §4.2
   (`version(1) | key_id(8) | nonce(12) | ciphertext+tag`, AAD = `version || key_id`, fresh random
   12-byte nonce every single call — never reuse one).
4. `POST http://<host>:<port>/v1/msg`, `Content-Type: application/octet-stream`, body = the raw
   envelope bytes.
5. On `200`, decrypt the response envelope with `k_m2p`, and check the returned `{id, ctr}` matches
   what was sent, as a sanity check on your own round trip.
6. On any failure (network error, non-200, decrypt failure), retry a few times with backoff, then
   give up — per the non-goals above, there's no outbox for a minimal v1.

## Crypto notes specific to this platform

Match `PROTOCOL.md` exactly, but be aware of these Android/JVM-specific traps to check for
yourself (don't assume — verify against real test vectors, see "Testing" below):

- `javax.crypto.KeyAgreement.getInstance("ECDH")` with a Bouncy Castle or platform EC provider
  should give you the shared secret, but **confirm it returns the same thing Go's
  `crypto/ecdh.PrivateKey.ECDH()` does** (the X-coordinate only, not the full point) — different
  ECDH APIs across ecosystems have disagreed about this before.
- The JVM standard library has **no built-in HKDF**. You'll need either a small hand-rolled
  RFC 5869 implementation (it's short — an Extract and an Expand step, both just HMAC-SHA256 calls)
  or a dependency like Bouncy Castle's `HKDFBytesGenerator`. This is exactly the kind of
  third-party-dependency decision to raise with the user rather than deciding silently.
- Once `PROTOCOL.md` §6 has real test vectors generated from the Mac daemon's own implementation
  (it doesn't yet, as of writing this), running this app's crypto against those same fixed inputs
  and checking for byte-identical output is the real interoperability test — far more meaningful
  than either side's own unit tests in isolation.

## Testing

- Plain JVM unit tests (no Android framework needed) for: pairing key derivation, envelope
  encrypt/decrypt round trip, tampered-ciphertext rejection, counter persistence surviving a
  simulated process restart.
- Cross-check against `PROTOCOL.md` §6's test vectors as soon as they exist.
- Real end-to-end pairing + message send against an actual Mac running `otpd` is the final check,
  but is currently blocked on that project's own crypto work being finished — note this plainly in
  your milestone summaries rather than treating it as a silent gap.

## Milestones

1. Read `../in-sms/docs/PROTOCOL.md` in full (and skim `ARCHITECTURE.md`) before anything else.
2. `docs/DESIGN.md` (Android-specific architecture only) — stop for review.
3. Crypto module + unit tests (no Android dependencies, pure JVM-testable) — stop for review.
4. QR scan + pairing flow + persistence.
5. SMS receiver + encrypted forwarding + retry.
6. Minimal status UI (paired device, last sent, re-pair/unpair).

## Open decisions to raise with the user early

- **minSdk / language**: Kotlin is assumed; confirm the minimum supported Android version.
- **QR scanning**: CameraX + ML Kit Barcode Scanning vs. ZXing vs. something else — a third-party
  dependency either way, needs sign-off.
- **HKDF**: hand-roll (~20 lines, zero dependencies) vs. Bouncy Castle.
- **Key storage**: Android Keystore-backed EC key (more secure, but ECDH-via-Keystore has
  API-level and hardware caveats worth researching first) vs. a plain stored keypair matching the
  simplification the Mac side chose for its own key storage (no OS keychain, file permissions
  only). These don't have to match each other, but the choice should be deliberate, not default.
- **Background reliability**: a manifest-registered `BroadcastReceiver` alone vs. pairing it with
  a foreground service for OEMs that aggressively kill background receivers.
