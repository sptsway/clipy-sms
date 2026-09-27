# OTP Forwarder — Android App Design

Companion to `prompt.md` and `../in-sms/docs/PROTOCOL.md` (which owns the wire format — nothing in
this document restates it). This covers the Android-specific pieces only: app structure,
permissions, background-execution strategy, and local storage.

## 0. Decisions confirmed with the user

| Decision | Choice |
|---|---|
| minSdk | 26 (Android 8.0) |
| QR scanning | CameraX + ML Kit Barcode Scanning |
| HKDF | Hand-rolled RFC 5869 (HMAC-SHA256 based), zero new dependency |
| Background execution | Manifest `BroadcastReceiver` (no foreground service) |

## 1. Dependency list

Kept as small as the spec's own minimalism suggests. Every entry beyond the Kotlin/AGP/Compose
baseline is called out explicitly, per the "ask before adding a third-party dependency" rule:

| Dependency | Why | Status |
|---|---|---|
| `androidx.camera:camera-*` (CameraX) | Camera preview for QR scanning | **Approved above** |
| `com.google.mlkit:barcode-scanning` | On-device QR decode, no network call | **Approved above** |
| `androidx.work:work-runtime-ktx` (WorkManager) | See §4 — reliably runs the encrypt+POST job off the `BroadcastReceiver`, with built-in persisted retry/backoff that maps directly onto the spec's "retry a few times with backoff, then give up." | **New — flagging now.** This is a first-party Jetpack component (same category as CameraX, which is already approved), not an external library, but it's still an added Gradle dependency so I'm calling it out rather than assuming it's pre-cleared. Proceeding with it as the concrete choice for Milestone 5; the alternative would be hand-rolling a `Handler`/`Thread` + `AlarmManager` retry loop, which reimplements what WorkManager already does correctly (including surviving process death mid-retry). Say the word if you'd rather hand-roll it instead. |
| Everything else (HTTP, JSON, crypto) | `java.net.HttpURLConnection`, `org.json.JSONObject`, `javax.crypto`/`java.security` | Already in the Android SDK — **zero new dependencies.** |

No Bouncy Castle, no OkHttp/Retrofit, no kotlinx.serialization, no Keystore-backed key wrapper
library. HKDF is hand-rolled (§7); the JDK/Android platform crypto providers cover ECDH, HMAC, and
AES-GCM natively on API 26+.

## 2. Module / package layout

Single Gradle module (`app`), Kotlin, single-`Activity` + Jetpack Compose:

```
out-sms/
  docs/
    DESIGN.md
  app/
    build.gradle.kts
    src/
      main/
        AndroidManifest.xml
        kotlin/com/otpfwd/app/
          OtpFwdApp.kt                    # Application subclass, WorkManager config
          MainActivity.kt                 # single Activity, hosts Compose nav
          crypto/
            Base64Url.kt                  # unpadded base64url encode/decode
            Hkdf.kt                       # RFC 5869 extract/expand, HMAC-SHA256 only
            Ecdh.kt                       # P-256 keygen, point encode/decode, ECDH agreement
            Hmac.kt                       # thin HMAC-SHA256 wrapper
            Envelope.kt                   # binary envelope seal/open (§4.2 of PROTOCOL.md)
            PairingCrypto.kt              # mac / confirm / key_id derivations, ties the above together
          model/
            Identity.kt                   # data class mirroring identity.json
            PairingQr.kt                  # parsed otpfwd:// payload
            OutgoingSms.kt                # {id, ts, ctr, sender, body, sim}
          storage/
            IdentityStore.kt              # atomic JSON file, counter reservation
          pairing/
            PairingClient.kt              # POST /v1/pair against the hosts list
            PairingQrParser.kt            # otpfwd:// URI -> PairingQr
          net/
            MsgClient.kt                  # POST /v1/msg, single attempt (retry lives in ForwardWorker)
          sms/
            SmsReceivedReceiver.kt        # BroadcastReceiver, SMS_RECEIVED
            ForwardWorker.kt              # WorkManager CoroutineWorker: reserve ctr already done by
                                           # the time this runs; encrypts + POSTs + verifies ack
          ui/
            OtpFwdViewModel.kt
            PairScreen.kt                 # camera preview + ML Kit QR overlay
            StatusScreen.kt               # paired device, last sent, Unpair button
            Nav.kt
      test/
        kotlin/com/otpfwd/app/crypto/     # pure-JVM unit tests, no Android framework
        kotlin/com/otpfwd/app/storage/    # counter persistence / restart simulation
  build.gradle.kts
  settings.gradle.kts
  gradle/wrapper/...
  gradlew / gradlew.bat
```

`crypto/`, `model/`, and `storage/` have zero Android-framework imports (no `android.*`) so
Milestone 3's tests run as plain JVM unit tests (`./gradlew :app:testDebugUnitTest`), matching
`prompt.md`'s "no Android dependencies, pure JVM-testable" requirement. `storage/IdentityStore`
takes a `java.io.File` directory in its constructor rather than a `Context`, specifically so its
atomic-write/counter-reservation logic is JVM-testable by pointing it at a temp directory.

## 3. Permissions

Declared in `AndroidManifest.xml`:

| Permission | Why |
|---|---|
| `RECEIVE_SMS` | Required to register for `SMS_RECEIVED` |
| `INTERNET` | POST to the Mac daemon |
| `ACCESS_NETWORK_STATE` | Cheap pre-flight check before attempting a send (skip immediately if there's no active network, rather than waiting for a connect timeout) |
| `CAMERA` | QR pairing scan |

No `FOREGROUND_SERVICE*` permission — per the confirmed decision, there's no foreground service.
No `READ_SMS`/`SEND_SMS` — this app never reads SMS history or sends SMS itself, only reacts to the
receive broadcast, consistent with the "no message history" non-goal.

`RECEIVE_SMS`, `CAMERA`, and `POST_NOTIFICATIONS` (not needed here, no notifications) are the
runtime (dangerous) permissions relevant to this app; `RECEIVE_SMS` and `CAMERA` are requested from
`StatusScreen`/`PairScreen` respectively, at the point they're actually needed, not all up front at
first launch.

## 4. Background execution strategy

`android.provider.Telephony.SMS_RECEIVED_ACTION` is a **protected broadcast** — only the system can
send it, so a manifest-registered receiver can safely declare `android:exported="true"` (required
for the system to be able to deliver it) without opening any spoofing risk.

```xml
<receiver android:name=".sms.SmsReceivedReceiver" android:exported="true" android:permission="android.permission.BROADCAST_SMS">
    <intent-filter android:priority="500">
        <action android:name="android.provider.Telephony.SMS_RECEIVED" />
    </intent-filter>
</receiver>
```

A `BroadcastReceiver.onReceive()` runs on the main thread with an OS-enforced ~10 second execution
budget (longer with `goAsync()`, but still bounded and not meant for network I/O). It cannot safely
do the encrypt-and-POST work itself. Flow:

1. `SmsReceivedReceiver.onReceive()`: extract sender + concatenated body (see §8) and best-effort SIM
   slot from the intent (fast, synchronous, no I/O).
2. Synchronously call `IdentityStore.reserveNextCtr()` (a fast local file write, not network I/O) —
   this is the durable "reserve before attempting to send" step from `prompt.md`. If the app isn't
   currently paired (no `identity.json`), drop the SMS silently — there's nothing to forward to.
3. Enqueue a `OneTimeWorkRequest` for `ForwardWorker` via WorkManager, passing the reserved `ctr`,
   the SMS fields, and a UUID `id` as input `Data`. `onReceive()` returns immediately after
   enqueueing.
4. `ForwardWorker.doWork()` (background thread pool, off the receiver entirely) builds the
   plaintext, seals the envelope with `k_p2m`, `POST`s to `/v1/msg`, verifies the ack, and returns
   `Result.success()`/`Result.retry()`/`Result.failure()`.

**Retry policy** (concrete numeric choice, not specified in `prompt.md` beyond "a few retries with
backoff" — flagging as an assumption): `BackoffPolicy.EXPONENTIAL`, WorkManager's minimum backoff
floor of 10 seconds, `setBackoffCriteria(EXPONENTIAL, 10s)`, and the worker itself counts attempts
via `runAttemptCount` and returns `Result.failure()` once `runAttemptCount >= 3` (i.e. one initial
try plus two retries — roughly 10s then 20s apart) rather than retrying indefinitely. Once
WorkManager reports `Result.failure()`, the work is dropped for good — no dead-letter queue, per the
non-goals; the SMS simply stays on the phone as normal, unforwarded.

The reserved `ctr` is fixed at enqueue time and reused verbatim across every WorkManager retry of
that same work request — it is never re-reserved per attempt, exactly matching `prompt.md`'s
"persist it, then use that fixed value for every retry of this particular message."

**Known limitation, documented rather than solved**: a small number of OEM battery-management
skins (some Xiaomi/Huawei/Samsung builds historically) can still delay or kill background work
beyond what stock AOSP + WorkManager guarantees, even for a properly-declared receiver + enqueued
work. Per the confirmed decision, this v1 accepts that risk rather than adding a foreground
service/persistent notification; worth revisiting if real-world delivery reliability turns out to
be a problem.

## 5. Local storage

**No Android Keystore for the pairing keypair.** Plain file storage in app-private internal storage
(`Context.filesDir`), deliberately mirroring the Mac daemon's own explicit "no OS keychain, file
permissions only" simplification (`ARCHITECTURE.md` §3.4). Android's per-app internal storage is
sandboxed by UID (conceptually the Android analogue of the Mac's `0600`, owner-only) and unreadable
by other apps without root — the same threat model the Mac side already accepted. This is a
deliberate choice, not a default: `prompt.md` explicitly says the two sides' key-storage choices
don't have to match, but should each be a considered decision — recorded here as one. A
Keystore-backed hardware-bound key would be strictly more secure (survives a rooted-device key
dump) but adds real complexity (ECDH via `AndroidKeyStore` has API-level gaps and OEM inconsistency
issues that would need their own research spike); out of scope for this minimal v1.

**File**: `filesDir/identity.json`, written atomically (write to `identity.json.tmp` in the same
directory, `FileOutputStream.getFD().sync()`, then `File.renameTo()` — `renameTo` on the same
filesystem is atomic on Linux/Android) on every pairing event and after every `ctr` reservation.
Absent entirely when unpaired (file deleted on unpair).

```json
{
  "pairing_version": 1,
  "phone_priv": "<b64url, P-256 raw scalar, 32 bytes>",
  "phone_pub": "<b64url, 65-byte uncompressed point — cached, derivable from phone_priv, stored for convenience>",
  "mac_pub": "<b64url, 65-byte uncompressed point>",
  "device_name": "<string, Mac's name from the QR 'name' field>",
  "k_p2m": "<b64url, 32 bytes>",
  "k_m2p": "<b64url, 32 bytes>",
  "key_id": "<b64url, 8 bytes>",
  "hosts": ["192.168.1.23", "192.168.1.24"],
  "port": 47820,
  "next_ctr": 0,
  "last_sent_at_ms": null
}
```

`next_ctr` is the counter to use for the *next* message (so a fresh pairing writes `next_ctr = 0`,
and `reserveNextCtr()` returns the pre-increment value while persisting the incremented one). This
directly implements the durable "must never reuse a `ctr` that was already sent successfully" rule
— a reservation is durable the instant the file write completes, regardless of whether the
subsequent send ever succeeds.

**Concurrency**: reservation is guarded by an in-process Kotlin `Mutex` (single app, single
process, single file — no cross-process access to `identity.json` exists), so two SMS arriving in
quick succession can't race each other into reserving the same `ctr`.

No `SharedPreferences` (weaker atomicity guarantees for multi-field secret state than a manual
temp-file-plus-rename, and mixes UI prefs with secrets), no DataStore dependency for what's one
small JSON blob, no Room database for effectively one row — `java.io.File` + `org.json.JSONObject`
(already in the Android SDK) is the simplest thing that satisfies the durability requirement.

## 6. Pairing flow — Android-specific notes

(Wire format, HMAC/HKDF constructions, and validation order are entirely owned by `PROTOCOL.md` §3
— this section only covers Android plumbing around that.)

- QR payload parsed with `android.net.Uri.parse(...)` against the scanned `otpfwd://pair?...`
  string; `name` is percent-decoded UTF-8 via `Uri.decode(...)`. `exp` is compared against
  `System.currentTimeMillis() / 1000`.
- `hosts` (comma-separated) tried in the order given, each via a plain
  `HttpURLConnection` with a short explicit timeout (**2s connect / 3s read** — concrete numeric
  choice, not specified in the spec) — first host that returns any HTTP response wins; a
  connect-timeout/refused/unreachable host just moves on to the next one in the list.
- Response handling follows `prompt.md` step 7 literally: **every** pairing failure — no host
  reachable, non-200 from a reachable host, or a reachable host's `confirm` failing to verify — is
  shown to the user as the same single generic message ("Pairing failed. Check that your phone and
  Mac are on the same Wi-Fi network and try again."), with no distinction surfaced in the UI beyond
  that. This reading treats `prompt.md`'s "don't try to distinguish *why* pairing failed to the user
  beyond 'pairing failed'" as applying to the phone's own UI, not just the daemon's wire responses
  — flagging this interpretation explicitly since it's slightly stricter than what's strictly
  necessary for wire-protocol security (the daemon-side opacity in `PROTOCOL.md` §3.6 is about
  preventing a network attacker probing the token; a "no host reachable" failure never reached the
  daemon at all). Happy to relax this to a two-bucket message ("couldn't reach your Mac" vs.
  "pairing failed") if you'd find that more useful for troubleshooting — noting it here rather than
  silently picking the stricter reading.
- On success: `IdentityStore.savePairing(...)` performs the atomic write in §5, seeding
  `next_ctr = 0`.

## 7. Forwarding flow — Android-specific notes

- `SmsReceivedReceiver` uses `Telephony.Sms.Intents.getMessagesFromIntent(intent)`, which already
  returns one `SmsMessage` per PDU. A single "logical" SMS that arrived as a multipart/concatenated
  message shows up as multiple `SmsMessage` entries sharing the same originating address; this app
  concatenates their `messageBody` in order into one string and forwards **one** logical message per
  broadcast intent (not specified explicitly in the spec — flagging as the concrete, obviously-
  correct reading: the Mac side has no notion of "part 2 of 3").
- `sender` = the first part's `originatingAddress`.
- `sim` slot: best-effort only, per the non-goals ("just pass whatever slot index is convenient").
  On API 26+, the intent carries a `"subscription"` extra (subscription ID, not slot index directly)
  on multi-SIM devices; `SubscriptionManager.getActiveSubscriptionInfo(subId)` maps that to
  `.simSlotIndex`. If any step fails (single-SIM device, extra absent, `SubscriptionManager` denies
  the lookup), `sim` is simply omitted from the plaintext JSON, matching the field's optional status
  in `PROTOCOL.md` §4.3.
- `ForwardWorker` (a `CoroutineWorker`) does: build plaintext JSON → `Envelope.seal(k_p2m, ...)` →
  `MsgClient.post(...)` → on `200`, `Envelope.open(k_m2p, ...)` the ack and check `{id, ctr}` match
  what was sent → `Result.success()`. Any failure (network exception, non-200, ack decrypt failure,
  ack mismatch) → `Result.retry()` unless `runAttemptCount >= 3`, in which case `Result.failure()`
  (§4). `hosts` are tried in the same fixed order as pairing, per attempt.

## 8. Crypto module

Pure Kotlin, `java.security`/`javax.crypto` only (no Bouncy Castle, per the confirmed decision):

- `Ecdh.kt` — `KeyPairGenerator.getInstance("EC")` + `ECGenParameterSpec("secp256r1")` for
  keygen; manual SEC1 uncompressed-point encode/decode (`0x04 || X(32) || Y(32)`, big-endian,
  zero-padded) using `java.security.interfaces.ECPublicKey`/`ECPrivateKey` and
  `java.security.spec.ECPoint`; `KeyAgreement.getInstance("ECDH")` for the shared secret. Per
  `CRYPTO_IMPLEMENTATION.md`'s warning, this is verified (not assumed) in unit tests: (a) a
  round-trip self-consistency test — `ECDH(alicePriv, bobPub) == ECDH(bobPriv, alicePub)` — and (b)
  an explicit length/format assertion that the JCA `KeyAgreement.generateSecret()` output for the
  `"ECDH"` algorithm on EC keys is exactly 32 bytes (the X-coordinate only, per JCA's documented
  behavior for `KeyAgreement` on elliptic curves, matching Go's `crypto/ecdh` convention).
- `Hkdf.kt` — hand-rolled RFC 5869 Extract (`HMAC-SHA256(salt, ikm)`) and Expand (iterated
  `HMAC-SHA256(prk, T(n-1) || info || counter_byte)`), ~25 lines, verified against RFC 5869's own
  published SHA-256 test vectors (Appendix A.1/A.2) in unit tests — these are the one piece of this
  module with an authoritative, source-independent answer to check against before `PROTOCOL.md` §6
  ever gets real vectors from the Mac side.
- `Hmac.kt` — thin wrapper over `javax.crypto.Mac.getInstance("HmacSHA256")`.
- `Envelope.kt` — `seal(key, keyId, plaintext): ByteArray` / `open(key, keyId, envelope):
  ByteArray?` implementing the exact `version(1) | key_id(8) | nonce(12) | ciphertext++tag` layout
  and `AAD = version || key_id` from `PROTOCOL.md` §4.2, using `Cipher.getInstance("AES/GCM/NoPadding")`
  and a fresh `SecureRandom` 12-byte nonce per call. `open()` returns `null` on **any** failure
  (bad version, wrong `key_id`, `AEADBadTagException`, truncated input) — collapsed into one
  outcome by design, mirroring the daemon's generic-rejection posture, so callers can't
  accidentally branch on *why* decryption failed.
- `PairingCrypto.kt` — `computePairingMac`, `computeConfirm`, `deriveSessionKeys` (ECDH → HKDF →
  split → `key_id`), composing the primitives above exactly per `PROTOCOL.md` §3.3/§3.4.

## 9. UI

Single `Activity` (`MainActivity`), Compose, three screens — plain conditional composition in
`OtpFwdRoot`, no navigation library:

- **`WelcomeScreen`** — the first thing shown when unpaired, before the camera ever opens: app name,
  a one-line description, and a "Scan QR Code to Pair" button. Exists so the camera permission
  prompt is deferred until the user actually asks to pair (rather than firing immediately on first
  launch), and to give new users context before the camera view takes over the screen.
- **`PairScreen`** — shown after tapping that button. CameraX `PreviewView` + ML Kit
  `BarcodeScanning` analyzer looking for a QR code whose value starts with `otpfwd://pair`; on a
  decode, stops the camera and runs the pairing flow (§6), showing a spinner then either success
  (the app now shows `StatusScreen` instead, since `uiState.paired` flips to true) or the single
  generic failure message with a "Try again" button that resumes scanning.
- **`StatusScreen`** — shown when paired. Shows `device_name`, `last_sent_at_ms` (formatted
  relative, e.g. "2 minutes ago", or "Never" before the first forward), and an "Unpair" button
  (deletes `identity.json`, which returns to `WelcomeScreen`). No message list, no settings beyond
  this — per the non-goals.
- `OtpFwdViewModel` exposes paired/unpaired state (derived from whether `identity.json` exists) and
  the last-sent timestamp; `ForwardWorker` updates `last_sent_at_ms` in `identity.json` on a
  successful send, which the `StatusScreen` picks up via a `Flow` that re-reads the file (a
  `FileObserver` or simple polling `Flow` — implementation detail decided in Milestone 6).

## 10. Testing strategy

Matches `prompt.md`'s Testing section:

- **Plain JVM unit tests** (`./gradlew :app:testDebugUnitTest`, no emulator/device needed): HKDF
  against RFC 5869 vectors, ECDH round-trip + length assertions, HMAC known-answer checks, envelope
  seal/open round trip, tampered-ciphertext / wrong-AAD / wrong-key rejection, `IdentityStore`
  counter reservation surviving a simulated restart (construct a fresh `IdentityStore` instance
  against the same temp directory a second time and confirm `next_ctr` picks up where it left off).
- **Cross-check against `PROTOCOL.md` §6's test vectors** as soon as they exist — not yet, per
  `prompt.md`'s note that this is blocked on the Mac side's own crypto implementation.
- **Real end-to-end pairing + send against a live `otpd`** — also blocked on the same Mac-side work
  being finished, exactly as `prompt.md` anticipates. This will be called out again plainly in the
  Milestone 4/5 summaries rather than treated as a silent gap: those milestones can only be verified
  against a local mock HTTP server standing in for the daemon, not the real thing, until then.

## Implementation notes (discovered while building, not anticipated above)

- **`usesCleartextTraffic="true"` is required**, not optional: PROTOCOL.md §4.1 mandates plain HTTP
  for `/v1/pair` and `/v1/msg`, but Android blocks cleartext traffic by default from targetSdk 28+.
  Set on `<application>` in the manifest, scoped implicitly by the fact this app makes no other
  network calls at all.
- **WorkManager network constraint**: `ForwardWorker`'s `OneTimeWorkRequest` carries
  `Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED)`, using the
  `ACCESS_NETWORK_STATE` permission from §3. WorkManager holds the job until any network is active
  rather than burning through the 3-attempt budget while the phone is briefly offline (e.g. airplane
  mode) — a refinement on top of the retry policy in §4, not a contradiction of it.
- **HKDF empty-salt edge case**: RFC 5869 defines an omitted salt as a string of `HashLen` (32) zero
  bytes, but `javax.crypto.spec.SecretKeySpec` throws `IllegalArgumentException` on a literal
  zero-length key. `Hkdf.extract()` substitutes 32 zero bytes for an empty salt to match the RFC's
  defined behavior rather than throwing. Not reachable through this app's own use of HKDF (`salt` is
  always the 32-byte pairing token, never empty) — caught by a unit test exercising `Hkdf` as a
  standalone RFC 5869 primitive, independent of PROTOCOL.md's specific usage.
- **Crypto verification beyond unit tests**: before wiring the crypto module into the rest of the
  app, every primitive was additionally cross-checked in development against independent,
  non-JVM implementations — HMAC-SHA256 and ECDH against OpenSSL (`openssl dgst`, `openssl
  pkeyutl -derive` on `openssl genpkey`-generated keys), HKDF against Python's `hmac`/`hashlib`
  (after an attempt to check against the `openssl kdf HKDF` CLI subcommand itself disagreed with
  both Python and a manual `openssl dgst` HMAC chain — the CLI subcommand was the outlier and was
  dropped, not trusted as ground truth), and AES-256-GCM against a standalone ~70-line C program
  calling OpenSSL's EVP API directly. All agreed. This is not a substitute for PROTOCOL.md §6's own
  test vectors once they exist — it's cross-implementation agreement on the *general* primitives
  (RFC 5869 HKDF, NIST P-256 ECDH, AES-256-GCM), not proof of interop with the actual Go daemon.
- **Build/test environment limitation**: this implementation was built in a sandboxed environment
  where `curl` has normal network access but JVM-originated socket connections (including Gradle's
  own dependency resolution) time out — a Gradle build could not actually be run here. Worked around
  for verification purposes by compiling the Android-framework-independent modules (`crypto/`,
  `json/`, `model/`, `storage/`, `pairing/PairingQrParser`, `pairing/PairingClient`, `net/`) directly
  with a standalone `kotlinc` and running their full JUnit4 suite (52 tests, all passing) outside
  Gradle entirely. The Gradle wrapper itself (`gradlew`, `gradle-wrapper.jar`) is present and
  correctly configured (Gradle 9.8.0, AGP 9.4.1, Kotlin 2.4.20), but **the Compose UI, WorkManager,
  CameraX, and ML Kit code (`MainActivity`, `OtpFwdApp`, everything under `sms/` and `ui/`) has not
  been compiled, run, or tested in this session** — it was written carefully against well-established
  APIs and reviewed line-by-line, but needs `./gradlew assembleDebug` / `./gradlew testDebugUnitTest`
  on a machine with normal network access (or opening the project in Android Studio) as the first
  real compile check, before any on-device testing.

## Assumptions recorded for review

Beyond the four decisions already confirmed (§0):

1. WorkManager (`androidx.work`) added as a new Jetpack dependency for background retry — §4.
2. `HttpURLConnection` (built-in, zero-dependency) chosen over adding OkHttp — §6.
3. Retry numbers: 2s connect / 3s read timeout per host attempt; WorkManager exponential backoff
   with a 10s floor, capped at 3 total attempts — §4, §6.
4. Plain file storage (no Android Keystore) for the pairing keypair and session keys — §5.
5. Pairing failure UI is fully generic across all failure causes, including "no host reachable" —
   §6 (flagged as possibly stricter than necessary).
6. Multipart SMS parts are concatenated into a single logical forwarded message — §7.
7. SIM slot extraction is best-effort via `SubscriptionManager`, silently omitted on any failure —
   §7.
