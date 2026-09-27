package com.otpfwd.app.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Binary envelope from PROTOCOL.md §4.2:
 *
 *   version(1) | key_id(8) | nonce(12) | ciphertext ++ tag(16)
 *
 * AAD = version || key_id (9 raw bytes) — binds the header to the ciphertext. Used for both the
 * outgoing request (sealed with k_p2m) and the ack response (opened with k_m2p) — same layout,
 * same key_id, independent fresh nonces each way.
 */
object Envelope {
    const val VERSION: Byte = 0x01
    const val KEY_ID_SIZE = 8
    const val NONCE_SIZE = 12
    private const val TAG_SIZE_BITS = 128
    private const val TAG_SIZE_BYTES = TAG_SIZE_BITS / 8
    private const val HEADER_SIZE = 1 + KEY_ID_SIZE + NONCE_SIZE
    private const val MIN_ENVELOPE_SIZE = HEADER_SIZE + TAG_SIZE_BYTES

    /** Encrypts `plaintext` under `key` (must be 32 bytes, AES-256) with a fresh random 12-byte
     * nonce, and returns the full envelope (header + ciphertext + tag). Never reuses a nonce —
     * a new `SecureRandom` draw happens on every call. */
    fun seal(key: ByteArray, keyId: ByteArray, plaintext: ByteArray, random: SecureRandom = SecureRandom()): ByteArray {
        require(keyId.size == KEY_ID_SIZE) { "key_id must be $KEY_ID_SIZE bytes" }
        val nonce = ByteArray(NONCE_SIZE).also { random.nextBytes(it) }
        val aad = byteArrayOf(VERSION) + keyId
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE_BITS, nonce))
        cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(plaintext)
        return aad + nonce + ciphertext
    }

    /**
     * Opens an envelope, returning the plaintext on success or `null` on **any** failure —
     * malformed/too-short input, unrecognized version, `key_id` mismatch, or AEAD authentication
     * failure (bad key, tampered ciphertext, wrong AAD) are all collapsed into the same outcome
     * on purpose, matching PROTOCOL.md §4.6's "every failure looks identical" posture. Callers
     * must not try to recover *why* `null` came back.
     */
    fun open(key: ByteArray, expectedKeyId: ByteArray, envelope: ByteArray): ByteArray? {
        if (envelope.size < MIN_ENVELOPE_SIZE) return null
        if (envelope[0] != VERSION) return null
        val keyId = envelope.copyOfRange(1, 1 + KEY_ID_SIZE)
        if (!keyId.contentEquals(expectedKeyId)) return null
        val nonce = envelope.copyOfRange(1 + KEY_ID_SIZE, HEADER_SIZE)
        val ciphertext = envelope.copyOfRange(HEADER_SIZE, envelope.size)
        val aad = envelope.copyOfRange(0, HEADER_SIZE - NONCE_SIZE)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE_BITS, nonce))
            cipher.updateAAD(aad)
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            // Intentionally broad: any decrypt failure (bad tag, bad key, malformed ciphertext)
            // must produce the same generic outcome — see the kdoc above.
            null
        }
    }
}
