package com.otpfwd.app.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Thin wrapper over the platform's HmacSHA256, used for both the pairing `mac`/`confirm`
 * derivations (PROTOCOL.md §3.3/§3.4) and as the primitive underneath HKDF (§Hkdf.kt). */
object HmacSha256 {
    private const val ALGORITHM = "HmacSHA256"

    /** Computes HMAC-SHA256(key, parts[0] || parts[1] || ... ) — each part concatenated as raw bytes. */
    fun compute(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(key, ALGORITHM))
        for (part in parts) mac.update(part)
        return mac.doFinal()
    }
}
