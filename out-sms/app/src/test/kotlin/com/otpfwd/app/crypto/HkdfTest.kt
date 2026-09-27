package com.otpfwd.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * All three OKM constants below were cross-checked in development against an independent
 * Python (hmac/hashlib) implementation AND a manual HMAC-SHA256 chain computed via `openssl
 * dgst` — not copied from memory of the RFC text (see DESIGN.md §10 on why: an initial attempt
 * to check against the `openssl kdf HKDF` CLI subcommand itself turned out to disagree with both
 * of those independent references, so it was dropped as an unreliable check, not used as ground
 * truth here).
 */
class HkdfTest {

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) {
        ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte()
    }
    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    @Test
    fun `vector A - RFC5869-shaped 42-byte output`() {
        val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val expected = "e8b3434491694fad93452666eaadf5e6f11b2dc47a2c9541550ca0569320c62763a0773e8a5f62836286"

        assertEquals(expected, hex(Hkdf.deriveKey(ikm, salt, info, 42)))
    }

    @Test
    fun `vector B - 64-byte output exercises multi-block expand`() {
        val ikm = hex("516de6320916046cf796afa092f1217f18c5cd63921d93248eb84a78a32437ae")
        val salt = hex("adf769bcfab9e7204f535ade8ccaae64647d7345efd8")
        val info = hex("8e0c6d158c4fd52709d142e239e9")
        val expected = "36afa2ab973a1351ffb121772667d6c65424c398856d3e11ce7252ccc88cb12104f0beedd0ff2aa515dae003f423733018af75dc80070090f004a375bfddab0f"

        assertEquals(expected, hex(Hkdf.deriveKey(ikm, salt, info, 64)))
    }

    @Test
    fun `vector C - empty salt and empty info are valid HKDF inputs`() {
        val ikm = hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
        val expected = "0f19998974cf771231a8d7cd2fad2e986ac29dd7aca429f437a971495d6711f0"

        assertEquals(expected, hex(Hkdf.deriveKey(ikm, salt = ByteArray(0), info = ByteArray(0), length = 32)))
    }

    @Test
    fun `expand is prefix-consistent across output lengths`() {
        // A structural property of HKDF-Expand: T(i) only depends on PRK, info, and the previous
        // block, never on the caller's requested total length — so a longer request's output
        // must start with exactly the same bytes as a shorter request for the same PRK/info.
        val prk = HmacSha256.compute(hex("000102030405060708090a0b0c"), hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
        val info = hex("f0f1f2f3f4f5f6f7f8f9")

        val short = Hkdf.expand(prk, info, 32)
        val long = Hkdf.expand(prk, info, 64)

        assertArrayEquals(short, long.copyOfRange(0, 32))
    }

    @Test
    fun `deriveKey splits into k_p2m and k_m2p halves as PROTOCOL_md specifies`() {
        val ikm = ByteArray(32) { it.toByte() }
        val salt = ByteArray(32) { (it * 2).toByte() }
        val info = "otpfwd-v1".toByteArray()

        val okm = Hkdf.deriveKey(ikm, salt, info, 64)
        assertEquals(64, okm.size)
        val kP2m = okm.copyOfRange(0, 32)
        val kM2p = okm.copyOfRange(32, 64)
        assertEquals(32, kP2m.size)
        assertEquals(32, kM2p.size)
        // halves must actually differ (extremely unlikely to collide for real HKDF output)
        org.junit.Assert.assertFalse(kP2m.contentEquals(kM2p))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `expand rejects a length request larger than 255 times the hash length`() {
        Hkdf.expand(ByteArray(32), ByteArray(0), 255 * 32 + 1)
    }
}
