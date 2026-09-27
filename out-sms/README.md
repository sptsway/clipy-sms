# OTP Forwarder — Android sender

The phone half of [clipy-sms](../README.md): reads incoming SMS and forwards them, end-to-end
encrypted, to one paired Mac on the same LAN. No cloud, no accounts — just this app and the Mac's
`otpd` daemon talking directly over Wi-Fi.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the Android-specific design and
[`../in-sms/docs/PROTOCOL.md`](../in-sms/docs/PROTOCOL.md) for the wire protocol this app
implements exactly (binding for both sides — nothing here overrides it).

## What it does

1. Scan the QR code the Mac app shows to pair (`WelcomeScreen` → `PairScreen`): generates a P-256
   keypair, exchanges public keys with the Mac over `POST /v1/pair`, derives shared session keys
   (ECDH + HKDF-SHA256), and pins the Mac's key.
2. From then on, a `BroadcastReceiver` catches every incoming SMS and a `WorkManager` job
   (`ForwardWorker`) encrypts it (AES-256-GCM) and posts it to the Mac's `POST /v1/msg`, with
   persisted retry/backoff if the Mac is briefly unreachable.
3. `StatusScreen` shows the paired device name and last-sent time, with an unpair option.

There's no message list or history in this app — the Mac owns that.

## Stack

- Kotlin, single-Activity Jetpack Compose, minSdk 26 (Android 8.0) / targetSdk 37.
- CameraX + ML Kit Barcode Scanning for the QR scanner (the only two third-party dependencies —
  everything else, including all crypto, is `javax.crypto`/`java.security`, already in the SDK).
- WorkManager for reliable, retrying background delivery.
- HKDF is hand-rolled (RFC 5869 over `javax.crypto.Mac`) since the JDK has no built-in HKDF.
- Pairing/session keys live in plain app-private file storage, not Android Keystore — deliberately
  mirrors the same simplification the Mac side made for its own key storage (see
  `docs/DESIGN.md` for the reasoning).

## Build & run

```bash
./gradlew assembleDebug
./gradlew installDebug   # with a device/emulator connected
```

## Testing

```bash
./gradlew test
```

Crypto (`Ecdh`, `Hkdf`, `PairingCrypto`, `Envelope`), the QR parser, and identity storage are all
plain-JVM unit tested — no emulator needed. `PairingQrParserTest` in particular exercises the
same malformed/expired/wrong-version QR cases the Mac side's protocol spec calls out.

## Status

Pairing, QR scanning, encrypted message forwarding, and the status/unpair UI are implemented and
unit tested. Not yet done: a signed release build, and end-to-end verification against the Mac
app's real (not simulated) daemon on a variety of networks.
