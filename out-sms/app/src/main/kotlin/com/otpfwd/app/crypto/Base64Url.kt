package com.otpfwd.app.crypto

import java.util.Base64

/**
 * base64url without padding (RFC 4648 §5), per PROTOCOL.md §1 — used for every binary value
 * embedded in the QR URI, pairing JSON, or local storage.
 */
object Base64Url {
    fun encode(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun decode(text: String): ByteArray =
        Base64.getUrlDecoder().decode(text)
}
