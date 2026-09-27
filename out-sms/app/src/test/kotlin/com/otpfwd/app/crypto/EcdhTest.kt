package com.otpfwd.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.interfaces.ECPublicKey

/**
 * The shared-secret-vs-openssl and 500-iteration keygen/agree/encode round trip in
 * DESIGN.md §10's development harness (checked against `openssl pkeyutl -derive` on
 * independently `openssl genpkey`-generated P-256 keys) are the authoritative cross-checks for
 * this class; these tests cover the same logic in a self-contained, CI-friendly form.
 */
class EcdhTest {

    @Test
    fun `generateKeyPair produces a 65-byte uncompressed point and a 32-byte scalar`() {
        val pair = Ecdh.generateKeyPair()
        assertEquals(65, pair.publicPoint.size)
        assertEquals(0x04.toByte(), pair.publicPoint[0])
        assertEquals(32, pair.privateScalar.size)
    }

    @Test
    fun `ECDH agreement is symmetric between both sides`() {
        val alice = Ecdh.generateKeyPair()
        val bob = Ecdh.generateKeyPair()

        val fromAlice = Ecdh.sharedSecret(alice.privateScalar, bob.publicPoint)
        val fromBob = Ecdh.sharedSecret(bob.privateScalar, alice.publicPoint)

        assertArrayEquals(fromAlice, fromBob)
        assertEquals(32, fromAlice.size)
    }

    @Test
    fun `500 rounds of keygen, agreement, and point re-encoding never mismatch`() {
        // Runs many iterations specifically to shake out the BigInteger zero-padding edge case
        // (a coordinate with a leading zero byte) probabilistically, since any single run has
        // only a small chance of hitting it.
        repeat(500) {
            val a = Ecdh.generateKeyPair()
            val b = Ecdh.generateKeyPair()

            val s1 = Ecdh.sharedSecret(a.privateScalar, b.publicPoint)
            val s2 = Ecdh.sharedSecret(b.privateScalar, a.publicPoint)
            assertArrayEquals(s1, s2)
            assertEquals(32, s1.size)

            val decoded = Ecdh.publicKeyFromPoint(a.publicPoint) as ECPublicKey
            val reEncoded = Ecdh.encodePoint(decoded)
            assertArrayEquals(a.publicPoint, reEncoded)
        }
    }

    @Test
    fun `publicKeyFromPoint rejects a compressed point`() {
        val pair = Ecdh.generateKeyPair()
        val compressed = byteArrayOf(0x02) + pair.publicPoint.copyOfRange(1, 33) // 33-byte compressed form
        assertThrows(IllegalArgumentException::class.java) {
            Ecdh.publicKeyFromPoint(compressed)
        }
    }

    @Test
    fun `publicKeyFromPoint rejects the wrong length`() {
        assertThrows(IllegalArgumentException::class.java) {
            Ecdh.publicKeyFromPoint(ByteArray(64))
        }
    }

    @Test
    fun `publicKeyFromPoint rejects the point at infinity`() {
        val infinity = byteArrayOf(0x04) + ByteArray(64)
        assertThrows(IllegalArgumentException::class.java) {
            Ecdh.publicKeyFromPoint(infinity)
        }
    }

    @Test
    fun `privateKeyFromScalar rejects the wrong length`() {
        assertThrows(IllegalArgumentException::class.java) {
            Ecdh.privateKeyFromScalar(ByteArray(31))
        }
    }

    @Test
    fun `two independent keypairs never produce the same public point`() {
        val a = Ecdh.generateKeyPair()
        val b = Ecdh.generateKeyPair()
        assertFalse(a.publicPoint.contentEquals(b.publicPoint))
    }
}
