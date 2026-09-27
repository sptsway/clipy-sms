package com.otpfwd.app.crypto

import java.security.MessageDigest

/**
 * Pairing-specific derivations from PROTOCOL.md §3.3/§3.4, composing Ecdh/Hkdf/HmacSha256. Owns
 * no state of its own — pure functions over byte arrays so they're trivially unit-testable.
 */
object PairingCrypto {
    private val PAIR_LABEL = "pair-v1".toByteArray(Charsets.US_ASCII)
    private val INFO_LABEL = "otpfwd-v1".toByteArray(Charsets.US_ASCII)
    private val CONFIRM_LABEL = "confirm-v1".toByteArray(Charsets.US_ASCII)
    private val KEY_ID_LABEL = "otpfwd-key-id".toByteArray(Charsets.US_ASCII)

    const val SESSION_KEY_SIZE = 32
    const val KEY_ID_SIZE = 8

    data class SessionKeys(val kP2m: ByteArray, val kM2p: ByteArray, val keyId: ByteArray)

    /** mac = HMAC-SHA256(key = token, msg = "pair-v1" || mac_pub || phone_pub). `macPub`/`phonePub`
     * must be the raw 65-byte points, never base64url text (PROTOCOL.md §3.3). */
    fun computePairingMac(token: ByteArray, macPub: ByteArray, phonePub: ByteArray): ByteArray =
        HmacSha256.compute(token, PAIR_LABEL, macPub, phonePub)

    /** confirm = HMAC-SHA256(key = k_m2p, msg = "confirm-v1"). */
    fun computeConfirm(kM2p: ByteArray): ByteArray = HmacSha256.compute(kM2p, CONFIRM_LABEL)

    /**
     * Full session-key derivation, phone side of PROTOCOL.md §3.4:
     *   ikm = ECDH(phone_priv, mac_pub); salt = token
     *   info = "otpfwd-v1" || mac_pub || phone_pub
     *   okm = HKDF-SHA256(ikm, salt, info, 64); k_p2m = okm[0:32]; k_m2p = okm[32:64]
     *   key_id = SHA-256("otpfwd-key-id" || k_p2m || k_m2p)[0:8]
     */
    fun deriveSessionKeys(
        phonePrivateScalar: ByteArray,
        macPub: ByteArray,
        phonePub: ByteArray,
        token: ByteArray,
    ): SessionKeys {
        val ikm = Ecdh.sharedSecret(phonePrivateScalar, macPub)
        val info = INFO_LABEL + macPub + phonePub
        val okm = Hkdf.deriveKey(ikm, salt = token, info = info, length = 2 * SESSION_KEY_SIZE)
        val kP2m = okm.copyOfRange(0, SESSION_KEY_SIZE)
        val kM2p = okm.copyOfRange(SESSION_KEY_SIZE, 2 * SESSION_KEY_SIZE)
        return SessionKeys(kP2m, kM2p, deriveKeyId(kP2m, kM2p))
    }

    /** key_id = SHA-256("otpfwd-key-id" || k_p2m || k_m2p)[0:8] — PROTOCOL.md §4.2. */
    fun deriveKeyId(kP2m: ByteArray, kM2p: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(KEY_ID_LABEL)
        digest.update(kP2m)
        digest.update(kM2p)
        return digest.digest().copyOf(KEY_ID_SIZE)
    }
}
