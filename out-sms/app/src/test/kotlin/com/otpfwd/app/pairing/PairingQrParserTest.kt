package com.otpfwd.app.pairing

import com.otpfwd.app.crypto.Base64Url
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PairingQrParserTest {

    private val macPub = byteArrayOf(0x04) + ByteArray(64) { it.toByte() }
    private val token = ByteArray(32) { (it + 1).toByte() }
    private val now = 1_735_238_400L

    private fun buildUri(
        name: String = "Swaraj's MacBook Pro",
        hosts: String = "192.168.1.23,192.168.1.24",
        port: String = "47820",
        exp: Long = now + 120,
        macPubB64: String = Base64Url.encode(macPub),
        tokenB64: String = Base64Url.encode(token),
        v: String = "1",
    ): String {
        val encodedName = name.toByteArray(Charsets.UTF_8).joinToString("") { b ->
            val c = b.toInt() and 0xFF
            if (c in 0x30..0x39 || c in 0x41..0x5A || c in 0x61..0x7A) c.toChar().toString() else "%%%02X".format(c)
        }
        return "otpfwd://pair?v=$v&mac_pub=$macPubB64&token=$tokenB64&hosts=$hosts&port=$port&name=$encodedName&exp=$exp"
    }

    @Test
    fun `parses a well-formed pairing URI`() {
        val qr = PairingQrParser.parse(buildUri(), now)

        assertArrayEquals(macPub, qr.macPub)
        assertArrayEquals(token, qr.token)
        assertEquals(listOf("192.168.1.23", "192.168.1.24"), qr.hosts)
        assertEquals(47820, qr.port)
        assertEquals("Swaraj's MacBook Pro", qr.name)
        assertEquals(now + 120, qr.expUnixSeconds)
    }

    @Test
    fun `percent-decodes a name with spaces, apostrophes, and unicode`() {
        val qr = PairingQrParser.parse(buildUri(name = "Bureau de Swaraj — café"), now)
        assertEquals("Bureau de Swaraj — café", qr.name)
    }

    @Test
    fun `a literal plus in the name is not turned into a space`() {
        // Regression test for the URLDecoder pitfall described in PairingQrParser's kdoc: RFC 3986
        // percent-decoding must NOT treat '+' as an encoded space (that's form-encoding, not what
        // PROTOCOL.md §3.2 specifies).
        val qr = PairingQrParser.parse(buildUri(name = "A+B"), now)
        assertEquals("A+B", qr.name)
    }

    @Test
    fun `rejects an already-expired pairing window`() {
        assertThrows(PairingQrParser.InvalidPairingQr::class.java) {
            PairingQrParser.parse(buildUri(exp = now - 1), now)
        }
    }

    @Test
    fun `rejects a non-otpfwd scheme`() {
        assertThrows(PairingQrParser.InvalidPairingQr::class.java) {
            PairingQrParser.parse("https://pair?v=1", now)
        }
    }

    @Test
    fun `rejects an unsupported version`() {
        assertThrows(PairingQrParser.InvalidPairingQr::class.java) {
            PairingQrParser.parse(buildUri(v = "2"), now)
        }
    }

    @Test
    fun `rejects a mac_pub that is not 65 bytes`() {
        val shortPoint = Base64Url.encode(ByteArray(64))
        assertThrows(PairingQrParser.InvalidPairingQr::class.java) {
            PairingQrParser.parse(buildUri(macPubB64 = shortPoint), now)
        }
    }

    @Test
    fun `rejects a token that is not 32 bytes`() {
        val shortToken = Base64Url.encode(ByteArray(16))
        assertThrows(PairingQrParser.InvalidPairingQr::class.java) {
            PairingQrParser.parse(buildUri(tokenB64 = shortToken), now)
        }
    }

    @Test
    fun `rejects an empty hosts list`() {
        assertThrows(PairingQrParser.InvalidPairingQr::class.java) {
            PairingQrParser.parse(buildUri(hosts = ""), now)
        }
    }

    @Test
    fun `rejects a garbage string that is not a URI at all`() {
        assertThrows(PairingQrParser.InvalidPairingQr::class.java) {
            PairingQrParser.parse("not a uri at all", now)
        }
    }

    @Test
    fun `rejects an out-of-range port`() {
        assertThrows(PairingQrParser.InvalidPairingQr::class.java) {
            PairingQrParser.parse(buildUri(port = "70000"), now)
        }
    }
}
