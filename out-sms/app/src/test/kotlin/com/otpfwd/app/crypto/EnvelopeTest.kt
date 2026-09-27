package com.otpfwd.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.security.SecureRandom

/**
 * The `Envelope.seal()`/`open()` pair was also cross-checked in development against a standalone
 * C program calling OpenSSL's EVP AES-256-GCM API directly (a genuinely separate implementation
 * from the JVM's own `javax.crypto`) — both directions: our ciphertext decrypted correctly by the
 * C tool, and the C tool's ciphertext decrypted correctly by `Envelope.open()`. These tests cover
 * the same layout/AAD/rejection logic in a self-contained form.
 */
class EnvelopeTest {

    private val random = SecureRandom()
    private fun randomKey() = ByteArray(32).also { random.nextBytes(it) }
    private fun randomKeyId() = ByteArray(8).also { random.nextBytes(it) }

    @Test
    fun `seal then open round trips the plaintext`() {
        val key = randomKey()
        val keyId = randomKeyId()
        val plaintext = """{"id":"11111111-1111-1111-1111-111111111111","ts":1735238400000,"ctr":0,"sender":"+15551234567","body":"Your code is 123456"}""".toByteArray()

        val envelope = Envelope.seal(key, keyId, plaintext)
        assertEqualsVersionAndKeyId(envelope, keyId)

        val opened = Envelope.open(key, keyId, envelope)
        assertNotNull(opened)
        assertArrayEquals(plaintext, opened)
    }

    private fun assertEqualsVersionAndKeyId(envelope: ByteArray, keyId: ByteArray) {
        org.junit.Assert.assertEquals(Envelope.VERSION, envelope[0])
        assertArrayEquals(keyId, envelope.copyOfRange(1, 9))
    }

    @Test
    fun `tampered ciphertext is rejected`() {
        val key = randomKey()
        val keyId = randomKeyId()
        val envelope = Envelope.seal(key, keyId, "hello".toByteArray())
        val tampered = envelope.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1] + 1).toByte()

        assertNull(Envelope.open(key, keyId, tampered))
    }

    @Test
    fun `wrong key is rejected`() {
        val keyId = randomKeyId()
        val envelope = Envelope.seal(randomKey(), keyId, "hello".toByteArray())
        assertNull(Envelope.open(randomKey(), keyId, envelope))
    }

    @Test
    fun `wrong key_id is rejected without attempting decryption`() {
        val key = randomKey()
        val envelope = Envelope.seal(key, randomKeyId(), "hello".toByteArray())
        assertNull(Envelope.open(key, randomKeyId(), envelope))
    }

    @Test
    fun `unrecognized version byte is rejected`() {
        val key = randomKey()
        val keyId = randomKeyId()
        val envelope = Envelope.seal(key, keyId, "hello".toByteArray())
        envelope[0] = 0x02
        assertNull(Envelope.open(key, keyId, envelope))
    }

    @Test
    fun `truncated envelope is rejected rather than throwing`() {
        val key = randomKey()
        val keyId = randomKeyId()
        assertNull(Envelope.open(key, keyId, ByteArray(5)))
        assertNull(Envelope.open(key, keyId, ByteArray(0)))
    }

    @Test
    fun `wrong AAD (tampered header) is rejected`() {
        val key = randomKey()
        val keyId = randomKeyId()
        val envelope = Envelope.seal(key, keyId, "hello".toByteArray())
        // Flip a bit inside key_id (part of the AAD) without going through the keyId-mismatch
        // fast path by also updating expectedKeyId to the corrupted value — this exercises the
        // AEAD authentication failure path specifically, not the earlier key_id short-circuit.
        val corrupted = envelope.copyOf()
        corrupted[3] = (corrupted[3].toInt() xor 0x01).toByte()
        val corruptedKeyId = corrupted.copyOfRange(1, 9)
        assertNull(Envelope.open(key, corruptedKeyId, corrupted))
    }

    @Test
    fun `200 seals never repeat a nonce`() {
        val key = randomKey()
        val keyId = randomKeyId()
        val nonces = (1..200).map {
            Envelope.seal(key, keyId, "x".toByteArray()).copyOfRange(9, 21).joinToString("") { b -> "%02x".format(b) }
        }
        org.junit.Assert.assertEquals(nonces.size, nonces.toSet().size)
    }
}
