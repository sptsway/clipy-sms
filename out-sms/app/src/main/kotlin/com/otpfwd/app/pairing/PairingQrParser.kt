package com.otpfwd.app.pairing

import com.otpfwd.app.crypto.Base64Url
import com.otpfwd.app.model.PairingQr
import java.io.ByteArrayOutputStream
import java.net.URI

/**
 * Parses the `otpfwd://pair?...` QR payload (PROTOCOL.md §3.2). Deliberately built on plain JDK
 * (`java.net.URI` + a hand-rolled percent-decoder, not `android.net.Uri`) so this class has zero
 * Android-framework imports and is plain-JVM unit-testable, matching DESIGN.md §2's module
 * boundary for the pairing package's parsing logic.
 */
object PairingQrParser {
    class InvalidPairingQr(message: String) : Exception(message)

    fun parse(text: String, nowUnixSeconds: Long): PairingQr {
        val uri = try {
            URI(text)
        } catch (e: Exception) {
            throw InvalidPairingQr("not a valid URI")
        }
        if (uri.scheme != "otpfwd") throw InvalidPairingQr("wrong URI scheme")

        val rawQuery = uri.rawQuery ?: throw InvalidPairingQr("missing query string")
        val params = parseQuery(rawQuery)

        fun required(key: String): String = params[key] ?: throw InvalidPairingQr("missing '$key'")

        if (required("v") != "1") throw InvalidPairingQr("unsupported pairing version")

        val macPub = decodePoint(required("mac_pub"))
        val token = decodeToken(required("token"))
        val hosts = required("hosts").split(",").map { it.trim() }.filter { it.isNotEmpty() }
        if (hosts.isEmpty()) throw InvalidPairingQr("empty hosts list")
        val port = required("port").toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw InvalidPairingQr("invalid port")
        val name = required("name")
        val exp = required("exp").toLongOrNull() ?: throw InvalidPairingQr("invalid exp")

        if (exp <= nowUnixSeconds) throw InvalidPairingQr("pairing window already expired")

        return PairingQr(macPub, token, hosts, port, name, exp)
    }

    private fun decodePoint(b64url: String): ByteArray {
        val bytes = try {
            Base64Url.decode(b64url)
        } catch (e: Exception) {
            throw InvalidPairingQr("mac_pub is not valid base64url")
        }
        if (bytes.size != 65 || bytes[0] != 0x04.toByte()) {
            throw InvalidPairingQr("mac_pub must be a 65-byte uncompressed P-256 point")
        }
        return bytes
    }

    private fun decodeToken(b64url: String): ByteArray {
        val bytes = try {
            Base64Url.decode(b64url)
        } catch (e: Exception) {
            throw InvalidPairingQr("token is not valid base64url")
        }
        if (bytes.size != 32) throw InvalidPairingQr("token must be 32 bytes")
        return bytes
    }

    private fun parseQuery(rawQuery: String): Map<String, String> =
        rawQuery.split("&").filter { it.isNotEmpty() }.associate { pair ->
            val idx = pair.indexOf('=')
            val key = if (idx >= 0) pair.substring(0, idx) else pair
            val value = if (idx >= 0) pair.substring(idx + 1) else ""
            percentDecode(key) to percentDecode(value)
        }

    /**
     * Plain RFC 3986 percent-decoding — deliberately NOT `java.net.URLDecoder`, which also
     * converts a literal `+` into a space (application/x-www-form-urlencoded convention).
     * PROTOCOL.md §3.2 says `name` is "percent-encoded UTF-8", not form-encoded, so a device name
     * containing a literal `+` must round-trip unchanged.
     */
    private fun percentDecode(s: String): String {
        val bytes = ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            if (s[i] == '%' && i + 2 < s.length) {
                val value = s.substring(i + 1, i + 3).toIntOrNull(16)
                if (value != null) {
                    bytes.write(value)
                    i += 3
                    continue
                }
            }
            val start = i
            while (i < s.length && s[i] != '%') i++
            if (i == start) i++ else bytes.write(s.substring(start, i).toByteArray(Charsets.UTF_8))
        }
        return bytes.toString("UTF-8")
    }
}
