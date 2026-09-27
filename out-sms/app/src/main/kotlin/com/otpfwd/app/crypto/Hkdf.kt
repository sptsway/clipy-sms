package com.otpfwd.app.crypto

/**
 * Hand-rolled RFC 5869 HKDF (Extract-then-Expand), HMAC-SHA256 only. The JVM/Android standard
 * library has no built-in HKDF (java.crypto.hkdf is a Go 1.24 addition, not a JVM one) — this is
 * the confirmed hand-roll-vs-Bouncy-Castle decision from DESIGN.md §0. Kept deliberately generic
 * (RFC 5869, not protocol-specific) so it's independently checkable against RFC 5869's own
 * published test vectors, rather than only ever exercised through PROTOCOL.md-specific inputs.
 */
object Hkdf {
    private const val HASH_LEN = 32

    /** HKDF-Extract: PRK = HMAC-Hash(salt, IKM). Per RFC 5869 §2.2, an omitted salt is defined as
     * a string of HashLen zero bytes — substituted here because `javax.crypto.spec.SecretKeySpec`
     * throws on a genuinely zero-length key, which would otherwise make `extract(ByteArray(0),
     * ikm)` fail instead of falling back to the RFC-defined default. Not exercised by
     * PROTOCOL.md's own usage (salt is always the 32-byte token, never empty), but this is a
     * generic RFC 5869 primitive, not protocol-specific, so it should still be correct standalone. */
    fun extract(salt: ByteArray, ikm: ByteArray): ByteArray =
        HmacSha256.compute(if (salt.isEmpty()) ByteArray(HASH_LEN) else salt, ikm)

    /** HKDF-Expand: OKM = T(1) || T(2) || ... truncated to `length` bytes, where
     * T(0) = empty, T(i) = HMAC-Hash(PRK, T(i-1) || info || i) for a single-byte counter i. */
    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 0..(255 * HASH_LEN)) { "length must be in 0..${255 * HASH_LEN}" }
        if (length == 0) return ByteArray(0)
        val blocks = (length + HASH_LEN - 1) / HASH_LEN
        val okm = ByteArray(blocks * HASH_LEN)
        var previous = ByteArray(0)
        for (i in 1..blocks) {
            val counter = byteArrayOf(i.toByte())
            previous = HmacSha256.compute(prk, previous, info, counter)
            previous.copyInto(okm, (i - 1) * HASH_LEN)
        }
        return okm.copyOf(length)
    }

    /** One-shot Extract-then-Expand, mirroring Go's `hkdf.Key(sha256.New, ikm, salt, info, length)`. */
    fun deriveKey(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray =
        expand(extract(salt, ikm), info, length)
}
