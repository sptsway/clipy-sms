# Implementing the crypto yourself — a guide, not code

`PROTOCOL.md` is the normative spec (exact byte layouts, HMAC/HKDF constructions). This
document is the companion you asked for: notes from actually poking at the Go 1.26 standard
library APIs involved, so you can implement `internal/crypto` and `internal/pairing` yourself
without re-discovering the same API surface and gotchas. No production code here on purpose —
just verified API shapes, pseudocode, and the traps that are easy to fall into.

## 1. The exact stdlib API surface

Everything below was confirmed with `go doc` against Go 1.26.2 — good to re-check if you're on a
different version, but these have been stable since `crypto/ecdh` (Go 1.20) and `crypto/hkdf`
(Go 1.24) were introduced.

### `crypto/ecdh`

```go
func P256() Curve

type Curve interface {
    GenerateKey(rand io.Reader) (*PrivateKey, error)
    NewPrivateKey(key []byte) (*PrivateKey, error)  // reload a raw scalar
    NewPublicKey(key []byte) (*PublicKey, error)    // parse a raw point
}

func (k *PrivateKey) Bytes() []byte                    // raw scalar, 32 bytes for P-256
func (k *PrivateKey) PublicKey() *PublicKey
func (k *PrivateKey) ECDH(remote *PublicKey) ([]byte, error)

func (k *PublicKey) Bytes() []byte                     // uncompressed SEC1 point
```

**Key facts that matter for this protocol:**

- `PublicKey.Bytes()` already returns the SEC1 **uncompressed** point (`0x04 || X || Y`, 65 bytes
  for P-256) — this is exactly the wire format PROTOCOL.md requires. No manual encoding needed.
- `Curve.NewPublicKey` **rejects** the compressed point form and the point at infinity for NIST
  curves automatically (per its doc comment) — you get PROTOCOL.md's "always uncompressed, reject
  everything else" requirement for free, just by using this constructor instead of hand-parsing.
- `PrivateKey.ECDH(remote)` — for NIST curves this returns **only the X-coordinate**, 32 bytes for
  P-256, not the full point. That's exactly `ikm` in PROTOCOL.md §3.4. Don't hash it, don't prepend
  anything — the raw 32 bytes it returns *is* `ikm`.
- `Curve.NewPrivateKey(key)` is how you reload `mac_priv` from wherever you stored its raw scalar
  bytes (e.g. after reading it back out of your identity file).

### `crypto/hkdf`

```go
func Key[Hash hash.Hash](h func() Hash, secret, salt []byte, info string, keyLength int) ([]byte, error)
```

One-shot Extract-then-Expand. Maps directly onto PROTOCOL.md §3.4:

```go
okm, err := hkdf.Key(sha256.New, ikm, token /* salt */, info, 64)
```

**Gotcha:** `info` is typed as a Go `string`, but the info string in this protocol is raw binary
(`"otpfwd-v1" || mac_pub || phone_pub`, where the two pubkeys are arbitrary point bytes, not text).
This is fine — a Go `string` is just an immutable byte sequence, not required to be valid UTF-8.
`string(someByteSlice)` is a lossless, zero-semantic-meaning conversion here. Build `info` as a
`[]byte` (append the literal `"otpfwd-v1"`, then the two raw 65-byte point encodings), then convert
the whole thing to `string(...)` only at the call site.

Splitting the 64-byte output: `kP2M := okm[:32]`, `kM2P := okm[32:]` — see PROTOCOL.md §3.4 for
why it's this order (a documented assumption, not something HKDF itself dictates).

### `crypto/hmac` + `crypto/sha256`

Standard streaming API:

```go
h := hmac.New(sha256.New, key)
h.Write(part1)
h.Write(part2)
sum := h.Sum(nil) // 32 bytes
```

Use this for both `mac` (PROTOCOL.md §3.3) and `confirm` (§3.4) — same pattern, different key and
message parts. Nothing unusual here; just remember the message parts are concatenated as raw
bytes via separate `Write` calls (or one `append`-built slice), never as JSON or base64 text.

### `crypto/subtle`

```go
func ConstantTimeCompare(x, y []byte) int // 1 if equal, 0 otherwise
```

**Gotcha:** if `len(x) != len(y)`, it returns `0` immediately — that early return is itself not
constant-time with respect to *length*, only content. That's fine here because every comparison
in this protocol is between two fixed-size values (both always 32-byte HMAC outputs), so length
never varies with secret data. Don't reuse this pattern for variable-length secrets elsewhere
without thinking about it again.

### `crypto/aes` + `cipher.NewGCM`

```go
block, _ := aes.NewCipher(key) // key must be exactly 32 bytes for AES-256
gcm, _ := cipher.NewGCM(block) // standard 12-byte nonce, 16-byte tag
ciphertext := gcm.Seal(nil, nonce, plaintext, aad)   // appends the tag
plaintext, err := gcm.Open(nil, nonce, ciphertext, aad) // err != nil on ANY failure
```

**Gotchas:**
- `gcm.Open`'s error is a black box by design — it does not (and should not) tell you *why*
  decryption failed. That's actually convenient here: PROTOCOL.md §4.6 wants every message-path
  failure to look identical from the outside, so just propagate a single generic error type
  regardless of what `Open` or your own validation returns — don't let Go's error string leak
  through to an HTTP response body.
- The nonce must be **fresh random bytes every single call**, generated with `crypto/rand`, never
  a counter or anything derived/predictable — GCM's security collapses under nonce reuse with the
  same key. 12 bytes (`gcm.NonceSize()`) is the standard/efficient size; don't change it.

## 2. Pseudocode — pairing (`POST /v1/pair` handling)

```
function StartPairingWindow(now):
    mac_priv = ecdh.P256().GenerateKey(crypto/rand)
    token    = 32 random bytes (crypto/rand)
    return Session{
        mac_priv, mac_pub_bytes: mac_priv.PublicKey().Bytes(),
        token, expires_at: now + 120s, attempts_left: 5, closed: false,
    }

function VerifyAttempt(session, now, phone_pub_bytes, device_name, mac):
    if session == nil or session.closed: return ErrWindowExpired
    if now >= session.expires_at: session.closed = true; return ErrWindowExpired
    if session.attempts_left <= 0: session.closed = true; return ErrAttemptsUsedUp

    session.attempts_left -= 1        # consume an attempt REGARDLESS of outcome below

    phone_pub, err = ecdh.P256().NewPublicKey(phone_pub_bytes)
    if err != nil:
        if session.attempts_left <= 0: session.closed = true
        return ErrBadMAC   # fold "malformed point" into the same generic failure

    expected_mac = HMAC-SHA256(key=token, msg="pair-v1" || mac_pub_bytes || phone_pub_bytes)
    if !ConstantTimeCompare(expected_mac, mac):
        if session.attempts_left <= 0: session.closed = true
        return ErrBadMAC

    ikm = session.mac_priv.ECDH(phone_pub)                     # 32 bytes, X-coordinate only
    info = "otpfwd-v1" || session.mac_pub_bytes || phone_pub_bytes
    okm = HKDF-SHA256(ikm, salt=session.token, info, 64)
    k_p2m, k_m2p = okm[:32], okm[32:]
    key_id = SHA256("otpfwd-key-id" || k_p2m || k_m2p)[:8]
    confirm = HMAC-SHA256(key=k_m2p, msg="confirm-v1")

    session.closed = true   # window can't be reused after a success
    return Result{phone_pub_bytes, device_name, k_p2m, k_m2p, key_id, confirm}
```

Every `Err*` above must map to the *same* generic `400` response (PROTOCOL.md §3.6) — resist the
temptation to return different HTTP statuses or bodies per case, even temporarily "for debugging."

## 3. Pseudocode — message path (`POST /v1/msg` handling)

```
function HandleMsg(body_bytes, source_ip, now):
    if len(body_bytes) > 8192: reject()                     # PROTOCOL.md §4.1, before parsing
    if !rate_limiter.Allow(source_ip, now): reject()

    if len(body_bytes) < 1 + 8 + 12 + 16: reject()           # too short for a valid envelope
    version = body_bytes[0]
    if version != 1: reject()
    key_id  = body_bytes[1:9]
    if key_id != current_pairing.key_id: reject()            # ConstantTimeCompare is fine but
                                                              # not required — key_id isn't secret
    nonce      = body_bytes[9:21]
    ciphertext = body_bytes[21:]                             # includes the 16-byte GCM tag
    aad        = body_bytes[0:9]                             # version || key_id

    plaintext, err = AES-256-GCM-Open(key=current_pairing.k_p2m, nonce, ciphertext, aad)
    if err != nil: reject()                                  # bad key, tampered bytes, wrong AAD

    msg = ParseJSON(plaintext)                                # {id, ts, ctr, sender, body, sim?}
    if abs(now_ms - msg.ts) > 120_000: reject()
    if int64(msg.ctr) <= current_pairing.last_ctr: reject()   # see the sentinel note below
    if dedupe_cache.Contains(msg.id): reject()

    current_pairing.last_ctr = int64(msg.ctr)
    persist(current_pairing)                                 # BEFORE returning success
    dedupe_cache.Insert(msg.id, expires_at: now + 240s)
    store_message(msg)

    ack_plaintext = JSON{id: msg.id, ctr: msg.ctr}
    return AES-256-GCM-Seal(key=current_pairing.k_m2p, fresh_nonce, ack_plaintext, aad)
```

**The counter sentinel gotcha:** the first message a phone ever sends after pairing has `ctr = 0`
(PROTOCOL.md §4.3), and the rule is "reject unless `ctr > last_ctr`". If you store `last_ctr` as a
plain `uint64` zero-initialized on a fresh pairing, `0 > 0` is false and you'll reject the very
first legitimate message. Store it as a **signed** integer initialized to **-1** on every fresh
pairing (not 0), so `0 > -1` correctly passes. This bit me in my own first draft — worth flagging
explicitly since it's the kind of off-by-one that only shows up when you actually test against a
real "first message after pairing."

Every `reject()` above must produce the same indistinguishable generic `400`, exactly like the
pairing path — malformed envelope, decrypt failure, replay, bad counter, stale timestamp, and
rate-limit are all the same response from the outside (PROTOCOL.md §4.6).

## 4. Suggested file layout

Unchanged from `ARCHITECTURE.md` §2 — this is just a reminder of where things were expected to go
so the rest of the daemon (storage, HTTP wiring, IPC) still lines up with what's documented there:

```
daemon/internal/crypto/     # ECDH/HKDF/HMAC/AEAD + envelope seal/open (§1 above)
daemon/internal/pairing/    # the Session state machine (§2 above)
daemon/internal/server/     # HTTP handlers that call into crypto + pairing (§3 above)
```

## 5. Test vectors

Once you have a working implementation, generate one full pairing exchange (fixed `mac_priv`,
`phone_priv`, `token` → resulting `k_p2m`, `k_m2p`, `key_id`, `confirm`) and one full message
envelope (fixed key, nonce, plaintext → ciphertext), and paste them as fixed hex/base64 constants
into `PROTOCOL.md` §6. Generating them from your own code (rather than copying numbers from
somewhere else) is what makes them useful as regression tests later.

## 6. Suggested self-check list

Mirrors the testing requirements in `prompt.md`/`PROTOCOL.md` — useful as a checklist once you've
written the real implementation:

- [ ] Pairing round-trip: mac-side and phone-side derivations of `ikm` (via `ECDH(mac_priv,
      phone_pub)` vs `ECDH(phone_priv, mac_pub)`) produce identical `k_p2m`/`k_m2p`/`key_id`.
- [ ] `ParsePublicKey`/`NewPublicKey` rejects a compressed point.
- [ ] Tampered ciphertext, wrong AAD, and wrong key all fail `Open` with the same error type.
- [ ] A replayed `id`, a non-increasing `ctr`, and a stale `ts` are each independently rejected.
- [ ] The very first message after a fresh pairing (`ctr = 0`) is **accepted**.
- [ ] The pairing window rejects attempts after 120s even with a correct `mac`.
- [ ] The pairing window rejects a 6th attempt even with a correct `mac` on the 6th try.
- [ ] Nonces are never repeated across two calls to your seal function with the same key.
