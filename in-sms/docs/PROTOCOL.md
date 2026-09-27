# OTP Forwarder — Wire Protocol (v1)

This document is the authoritative spec for everything that crosses a process or network boundary:
the QR pairing payload, the `POST /v1/pair` and `POST /v1/msg` HTTP calls, and the cryptography
that binds them together. It is written so the Android sender can be implemented independently
from this document alone, without reading the Go source.

Anything the original spec left unstated has a concrete decision here, and every such decision is
listed again in [Assumptions to confirm](#assumptions-to-confirm) at the bottom for review.

## 1. Conventions

- **Versioning.** The protocol version is `1` everywhere (`v=1` in the QR URI, `version` byte in
  the message envelope, `pairing_version` in stored state). A future breaking change increments
  these independently — e.g. a new pairing method bumps `pairing_version` without touching the
  message envelope's `version`.
- **Integer byte order.** Any multi-byte integer serialized outside JSON (`key_id`) is big-endian.
- **Text encoding.** All binary values embedded in URIs or JSON strings use **base64url without
  padding** (RFC 4648 §5, i.e. `-`/`_` alphabet, no trailing `=`). *(Assumption — the source spec
  says "base64url" but doesn't state a padding convention.)*
- **EC points.** A P-256 public key is always the 65-byte uncompressed SEC1 point form:
  `0x04 || X (32 bytes) || Y (32 bytes)`. Never send or accept the compressed (33-byte) form.
- **`||` denotes byte concatenation** of raw bytes, never of base64 or JSON text, unless stated
  otherwise.

## 2. Discovery

The daemon advertises `_otpfwd._tcp` over mDNS/Bonjour so the phone *could* discover it on the LAN,
but the QR code is the actual source of truth for connection details (see §3.2) — mDNS discovery
is a convenience, not required for pairing to work. The service name is the Mac's computer name;
no TXT records are needed since the QR payload already carries everything the phone needs.

## 3. Pairing

### 3.1 Overview

1. UI asks the daemon to start pairing.
2. Daemon generates a fresh Mac P-256 keypair (discarding any previous pairing), a 32-byte random
   token, and opens a 120-second window allowing at most 5 verification attempts.
3. Daemon renders the QR code; phone scans it and `POST`s `/v1/pair`.
4. Daemon verifies, derives session keys, pins the phone's public key, and replies.

### 3.2 QR code payload

A URI, encoded into the QR code as-is:

```
otpfwd://pair?v=1&mac_pub=<b64url>&token=<b64url>&hosts=<host-list>&port=<port>&name=<name>&exp=<unix-seconds>
```

| Field | Contents |
|---|---|
| `v` | `1` |
| `mac_pub` | base64url of the 65-byte uncompressed Mac P-256 public key |
| `token` | base64url of the 32 random pairing-token bytes |
| `hosts` | comma-separated list of the Mac's LAN IPv4 addresses, e.g. `192.168.1.23,192.168.1.24`. *(Assumption — IPv6 is out of scope for v1; if the Mac has no IPv4 LAN address pairing cannot proceed.)* |
| `port` | decimal TCP port the daemon is listening on |
| `name` | the Mac's computer name, **percent-encoded UTF-8** (it may contain spaces or non-ASCII characters). *(Assumption.)* |
| `exp` | unix seconds when the pairing window closes (`start + 120`) |

The phone should try each address in `hosts` (e.g. in order) since a Mac can have more than one
active LAN interface.

### 3.3 `POST /v1/pair`

Plain HTTP, JSON body, `Content-Type: application/json`:

```json
{
  "v": 1,
  "phone_pub": "<b64url, 65-byte uncompressed P-256 point>",
  "device_name": "<string>",
  "mac": "<b64url, 32-byte HMAC output>"
}
```

`mac` authenticates the pairing request and is computed as:

```
mac = HMAC-SHA256(
        key = token,                              // 32 raw bytes, NOT base64
        msg = "pair-v1" || mac_pub || phone_pub    // literal ASCII "pair-v1" (7 bytes),
      )                                            // then the two raw 65-byte uncompressed points
```

`mac_pub` and `phone_pub` here are the **raw 65-byte point bytes**, not their base64url text — decode
before concatenating.

### 3.4 Daemon processing

On receiving `POST /v1/pair` while a pairing window is open and attempts remain:

1. Decode `phone_pub`; reject (see §3.6) if it is not a valid uncompressed P-256 point.
2. Recompute `mac` as in §3.3 and compare to the request's `mac` in constant time
   (`crypto/subtle.ConstantTimeCompare`). Consume one attempt regardless of outcome.
3. On mismatch, or if the window has expired, or attempts are exhausted: reject (§3.6).
4. On match:
   - `ikm = ECDH(mac_priv, phone_pub)` — the shared X-coordinate, 32 bytes, via `crypto/ecdh`.
   - `salt = token` (32 raw bytes).
   - `info = "otpfwd-v1" || mac_pub || phone_pub` (raw bytes, literal ASCII `"otpfwd-v1"` is 9 bytes,
     then the two raw 65-byte points).
   - `okm = HKDF-SHA256(ikm, salt, info, 64)` via `crypto/hkdf`.
   - **`k_p2m = okm[0:32]`, `k_m2p = okm[32:64]`.** *(Assumption — the spec names the two keys in
     this order but doesn't say which half of the HKDF output each one is; this is the natural
     reading and is fixed here so both sides agree.)*
   - `key_id = SHA-256("otpfwd-key-id" || k_p2m || k_m2p)[0:8]` — see §4.2 for why this exists.
   - Pin `phone_pub`, store `device_name`, set `pairing_version = 1`, reset the message counter to
     `0`, burn the token, close the pairing window.
5. Reply `200` with:
   ```json
   { "ok": true, "confirm": "<b64url, 32-byte HMAC output>" }
   ```
   where `confirm = HMAC-SHA256(key = k_m2p, msg = "confirm-v1")` (literal ASCII, 10 bytes).

### 3.5 Attempt / window limits

- Window: 120 seconds from when pairing was started.
- Attempts: at most 5 verification attempts (§3.4 step 2) count against the window regardless of
  success or failure; the window closes immediately on a successful pair.
- Starting a **new** pairing session at any time discards the in-progress or previously-completed
  pairing state entirely — there is no rollback to an old pairing.

### 3.6 Failure handling

Any failure in §3.4 (bad point encoding, HMAC mismatch, expired window, attempts exhausted, no
pairing in progress) returns a generic:

```
HTTP/1.1 400 Bad Request
```

with an empty or fixed-generic body — never a message that distinguishes *why* it failed. This
avoids giving an attacker an oracle for guessing the token or probing window state.
*(Assumption — extending this posture, which the source spec states for pairing, to `/v1/msg` too
is covered in §4.6.)*

### 3.7 `pairing_version`

Stored alongside the derived keys as an integer, currently always `1` (this ECDH + one-time-token
method). It exists purely for forward compatibility: a future numeric-comparison pairing method
would ship as `pairing_version = 2` and the message path (§4) would not change at all — it only
ever consumes `k_p2m`/`k_m2p`, regardless of how they were derived.

## 4. Message path

### 4.1 Transport

- `POST /v1/msg`, plain HTTP (no TLS — every payload is independently authenticated and encrypted).
- Listener binds only to LAN-scoped interface addresses (never loopback-only or `0.0.0.0` in a way
  that would also answer on a VPN/public interface — see ARCHITECTURE.md for the exact interface
  filter). Default port `47820`, configurable.
- Reject any request body over **8192 bytes** (checked against `Content-Length` and while reading)
  before attempting to parse anything.
- Per-source-IP rate limiting (see §4.7).

### 4.2 Binary envelope

The request (and the ack response) body is:

```
+-----------+-------------+-----------+------------------------+
| version(1)| key_id(8)   | nonce(12) | ciphertext ++ tag       |
+-----------+-------------+-----------+------------------------+
```

- `version`: `0x01`.
- `key_id`: 8 bytes, big-endian, `SHA-256("otpfwd-key-id" || k_p2m || k_m2p)[0:8]`, computed once at
  pairing time and stored with the keys. *(Assumption — not specified by the source spec.)* Its
  purpose: after a re-pair, an old/stale phone sending with old keys gets a clean generic rejection
  because its `key_id` won't match the daemon's current one, without the daemon ever needing to
  reveal *why* (still just a `400` — `key_id` is derived from key material but does not leak it,
  since it's a one-way hash).
- `nonce`: 12 random bytes from `crypto/rand`, freshly generated for every message — never reused
  under the same key.
- `ciphertext ++ tag`: AES-256-GCM output (Go's `cipher.AEAD.Seal` appends the 16-byte tag).

AAD for the AEAD call is `version || key_id` (9 raw bytes) — this binds the envelope header to the
ciphertext so it can't be spliced onto a different header.

- **Request** encryption key: `k_p2m`.
- **Ack** encryption key: `k_m2p`. Same envelope layout, same `key_id`, a fresh random nonce.

### 4.3 Plaintext (request)

JSON, encrypted as the envelope's ciphertext:

```json
{
  "id": "<uuid>",
  "ts": 1735238400000,
  "ctr": 42,
  "sender": "<string>",
  "body": "<string>",
  "sim": 1
}
```

- `id`: a UUID (v4 recommended), used for replay dedup (§4.4).
- `ts`: unix milliseconds when the phone captured the SMS.
- `ctr`: `uint64`, strictly increasing per phone across its lifetime with the current pairing
  (resets to 0 — i.e. next message is `ctr=0` — on a fresh pairing, per §3.4).
- `sender`, `body`: the SMS sender and full text.
- `sim`: optional integer SIM slot index, omit on single-SIM phones.

### 4.4 Validation

Applied in this order; **any** failure produces the same generic rejection (§4.6) with no
indication of which check failed:

1. Envelope well-formed, `version` recognized, `key_id` matches the current pairing, AEAD open
   succeeds against `k_p2m` (bad key/tampered ciphertext/wrong AAD all fail here, indistinguishably).
2. `abs(now_ms - ts) <= 120_000`.
3. `ctr > last_ctr` (the daemon's persisted last-seen counter for the current pairing — see
   ARCHITECTURE.md §"Secrets file"). Persisted **after** a message is accepted, so a crash between
   accept and persist could in theory require the phone to resend with a higher `ctr`, which is
   safe (never rejects a legitimate resend, at worst re-requires one).
4. `id` not present in the in-memory dedupe cache (see §4.5).

On success: persist `ctr` as the new `last_ctr`, insert `id` into the dedupe cache, store the
message (see ARCHITECTURE.md), and reply with the ack (§4.2/§4.6).

### 4.5 Dedupe cache

In-memory only, not persisted across daemon restarts. Entries expire 240 seconds after insertion
(2× the ±120s timestamp tolerance — anything that old is already rejected by the timestamp check
in §4.4 step 2 regardless of cache state, so a bounded, time-based cache is sufficient and never
needs to grow unbounded). *(Assumption — the source spec says "keep a dedupe cache" without sizing
or persistence requirements.)* Consequence: a daemon restart re-opens at most a 120-second replay
window, bounded by the timestamp check either way.

### 4.6 Responses

- **Success:** `200 OK`, `Content-Type: application/octet-stream`, body = the binary envelope
  (§4.2) encrypted with `k_m2p`, plaintext `{"id": "<same id>", "ctr": <same ctr>}`.
- **Any failure** (malformed envelope, decrypt failure, unknown `key_id`, not currently paired,
  stale timestamp, non-increasing counter, replayed id, oversized body, rate-limited): generic
  `400 Bad Request`, empty/fixed body — no field indicates which check failed. *(Assumption —
  the source spec states this generic-400 posture explicitly only for `/v1/pair`; it's extended
  here to `/v1/msg` for the same anti-oracle reason.)*

### 4.7 Rate limiting

Per-source-IP token bucket: capacity 20, refill 10 tokens/second. *(Assumption — the source spec
requires "rate-limit per source IP" without giving numbers; these defaults comfortably exceed
realistic SMS arrival rates while bounding abuse. Implemented as a small `sync.Mutex`-guarded
map — no third-party dependency needed.)* A request that exceeds the bucket gets the same generic
`400` as any other rejection (§4.6) — it is not distinguished as "rate limited" to the caller.

## 5. Key & counter lifecycle

- A fresh pairing (§3.4) always resets `last_ctr` to a state where the next accepted message must
  have `ctr > -1`, i.e. `ctr = 0` is the first valid value — old counters from a previous pairing
  are meaningless once the keys change.
- `last_ctr` is persisted to disk after every accepted message (ARCHITECTURE.md), so a daemon
  restart cannot be used to roll the counter back and replay old messages.

## 6. Test vectors

Generated directly from the daemon's real Go implementation (`daemon/internal/crypto`), not
hand-computed — so any other implementation (the Android sender included) that reproduces these
outputs from these inputs is byte-for-byte wire-compatible. All values are lowercase hex unless
noted; P-256 scalars/points are raw bytes (not base64) here for readability — encode as
base64url-without-padding when placing them on the wire per §1.

### 6.1 Pairing exchange

Inputs (32-byte P-256 scalars, chosen as simple repeating patterns purely for readability — they
are otherwise unremarkable valid private keys):

```
mac_priv   = 0101010101010101010101010101010101010101010101010101010101010101
phone_priv = 0202020202020202020202020202020202020202020202020202020202020202
token      = 0303030303030303030303030303030303030303030303030303030303030303
```

Derived (65-byte uncompressed points, `0x04 || X || Y`):

```
mac_pub   = 046ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca163c4f753a55bf01dc53f6c0b0c7eee78b40c6ff7d25a96e2282b989cef71c144a
phone_pub = 04550f471003f3df97c3df506ac797f6721fb1a1fb7b8f6f83d224498a65c88e24136093d7012e509a73715cbd0b00a3cc0ff4b5c01b3ffa196ab1fb327036b8e6
```

`mac = HMAC-SHA256(token, "pair-v1" || mac_pub || phone_pub)`:

```
mac = 0243e701d05438855ac7f39e76977236a45dec668e47eb0107263fc7dddc1294
```

`okm = HKDF-SHA256(ikm=ECDH(mac_priv, phone_pub), salt=token, info="otpfwd-v1"||mac_pub||phone_pub, 64)`,
split per §3.4:

```
k_p2m  = 7cde3a20477d5bd7ee84aea6fe96dc7fe230d24dda556ec7769d0752d78ecec4
k_m2p  = 1cbd40e7fd5b57ccc4bfbffd01d8d9fad8bf9502eb2d1ab6fc0b394af5a0c765
```

`key_id = SHA-256("otpfwd-key-id" || k_p2m || k_m2p)[0:8]`:

```
key_id = 92fbce47412a0f01
```

`confirm = HMAC-SHA256(k_m2p, "confirm-v1")`:

```
confirm = a47be19aa070cd2f31baaa8c48027aee3edcc8c49a82e862d4545974676d8db7
```

Sanity check for an implementation: computing `ECDH(phone_priv, mac_pub)` instead (the phone's
side) must produce the identical `ikm`, and therefore the identical `k_p2m`/`k_m2p`/`key_id` above.

### 6.2 Message envelope

Using `k_p2m` from §6.1 above, and a **fixed nonce for reproducibility only** — a real
implementation must always generate a fresh random nonce per message; this vector fixes it purely
so the ciphertext is checkable byte-for-byte:

```
key_id (from above) = 92fbce47412a0f01
nonce                = 000102030405060708090a0b
aad = version(0x01) || key_id = 0192fbce47412a0f01
plaintext = {"id":"11111111-1111-1111-1111-111111111111","ts":1735689600000,"ctr":0,"sender":"38221","body":"Your OTP is 123456."}
```

`ciphertext ++ tag = AES-256-GCM-Seal(k_p2m, nonce, plaintext, aad)`:

```
fbe0658149d62940ce1664e3097a73c23e628f03521fe6876e29dd00758991642d2b3f82957fdda84f0b86990a25b11dd0448058561962e3a618720620e8e3c54c73d8caf260f56007fc58c0d1ad3c6500834a13336d03a446eec8e948fb9559f00904138877292d74331f8c1d36ea16e1596d15dd9d744687dd388c4432722b7998d4b7e49c
```

Full envelope (`aad || nonce || ciphertext++tag`):

```
0192fbce47412a0f01000102030405060708090a0bfbe0658149d62940ce1664e3097a73c23e628f03521fe6876e29dd00758991642d2b3f82957fdda84f0b86990a25b11dd0448058561962e3a618720620e8e3c54c73d8caf260f56007fc58c0d1ad3c6500834a13336d03a446eec8e948fb9559f00904138877292d74331f8c1d36ea16e1596d15dd9d744687dd388c4432722b7998d4b7e49c
```

### 6.3 Ack envelope

Using `k_m2p` from §6.1, same `aad`, a different fixed nonce:

```
nonce     = 101112131415161718191a1b
plaintext = {"id":"11111111-1111-1111-1111-111111111111","ctr":0}
```

`ciphertext ++ tag`:

```
c5a0aac12441e323f4660d1071f4642636fd7b9802b0713f3ded5a82a1c5ad61bcd76e535d2db6e550fcf781d70926df32cc3e9456f14b9ae0acb3bece77bcc0504deebb72
```

Full envelope:

```
0192fbce47412a0f01101112131415161718191a1bc5a0aac12441e323f4660d1071f4642636fd7b9802b0713f3ded5a82a1c5ad61bcd76e535d2db6e550fcf781d70926df32cc3e9456f14b9ae0acb3bece77bcc0504deebb72
```

## Assumptions to confirm

- base64url is used **without padding** everywhere.
- `hosts` is IPv4-only, comma-separated; IPv6 is out of scope for v1.
- `name` in the QR URI is percent-encoded UTF-8.
- HKDF output split: first 32 bytes → `k_p2m`, last 32 bytes → `k_m2p`.
- `key_id = SHA-256("otpfwd-key-id" || k_p2m || k_m2p)[0:8]` — a derived, non-secret envelope tag;
  not specified by the original prompt.
- Dedupe cache: in-memory, 240-second entry lifetime, not persisted across restarts.
- Generic-`400`-with-no-details posture is extended from `/v1/pair` (explicitly stated) to
  `/v1/msg` (not explicitly stated, but same rationale).
- Rate limit defaults: 20-token bucket, 10 tokens/sec refill, per source IP, hand-rolled (no
  dependency).
- Message body size cap (8 KB) is enforced pre-parse on both `Content-Length` and actual bytes read.
