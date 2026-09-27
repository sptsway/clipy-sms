package com.otpfwd.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.security.SecureRandom

/**
 * Simulates both sides of PROTOCOL.md §3.4 using this module's own primitives (the "mac side"
 * math is inlined here rather than imported from a separate class, deliberately mirroring what an
 * independent Go implementation must compute) and confirms they agree — this is the same
 * structural check as CRYPTO_IMPLEMENTATION.md §6's "Pairing round-trip" self-check-list item.
 * Real interoperability with the actual Go daemon still requires PROTOCOL.md §6's test vectors,
 * which don't exist yet (noted throughout DESIGN.md/prompt.md as blocked on the Mac side).
 */
class PairingCryptoTest {

    private val random = SecureRandom()

    @Test
    fun `phone-side and mac-side derivations agree on k_p2m, k_m2p, and key_id`() {
        val mac = Ecdh.generateKeyPair()
        val phone = Ecdh.generateKeyPair()
        val token = ByteArray(32).also { random.nextBytes(it) }

        val phoneSession = PairingCrypto.deriveSessionKeys(phone.privateScalar, mac.publicPoint, phone.publicPoint, token)

        // "Mac side": ikm = ECDH(mac_priv, phone_pub) — the same shared secret from the other
        // direction, per PROTOCOL.md §3.4 step 4.
        val macIkm = Ecdh.sharedSecret(mac.privateScalar, phone.publicPoint)
        val macInfo = "otpfwd-v1".toByteArray(Charsets.US_ASCII) + mac.publicPoint + phone.publicPoint
        val macOkm = Hkdf.deriveKey(macIkm, token, macInfo, 64)
        val macKP2m = macOkm.copyOfRange(0, 32)
        val macKM2p = macOkm.copyOfRange(32, 64)
        val macKeyId = PairingCrypto.deriveKeyId(macKP2m, macKM2p)

        assertArrayEquals(macKP2m, phoneSession.kP2m)
        assertArrayEquals(macKM2p, phoneSession.kM2p)
        assertArrayEquals(macKeyId, phoneSession.keyId)
    }

    @Test
    fun `pairing mac is 32 bytes and deterministic for the same inputs`() {
        val token = ByteArray(32) { it.toByte() }
        val macPub = byteArrayOf(0x04) + ByteArray(64) { it.toByte() }
        val phonePub = byteArrayOf(0x04) + ByteArray(64) { (it + 1).toByte() }

        val mac1 = PairingCrypto.computePairingMac(token, macPub, phonePub)
        val mac2 = PairingCrypto.computePairingMac(token, macPub, phonePub)

        assertEquals(32, mac1.size)
        assertArrayEquals(mac1, mac2)
    }

    @Test
    fun `pairing mac changes if either public key changes`() {
        val token = ByteArray(32) { it.toByte() }
        val macPub = byteArrayOf(0x04) + ByteArray(64) { it.toByte() }
        val phonePubA = byteArrayOf(0x04) + ByteArray(64) { (it + 1).toByte() }
        val phonePubB = byteArrayOf(0x04) + ByteArray(64) { (it + 2).toByte() }

        val macA = PairingCrypto.computePairingMac(token, macPub, phonePubA)
        val macB = PairingCrypto.computePairingMac(token, macPub, phonePubB)

        assertFalse(macA.contentEquals(macB))
    }

    @Test
    fun `confirm matches between both sides and is 32 bytes`() {
        val kM2p = ByteArray(32).also { random.nextBytes(it) }
        val confirmFromPhoneView = PairingCrypto.computeConfirm(kM2p)
        val confirmFromMacView = PairingCrypto.computeConfirm(kM2p)

        assertEquals(32, confirmFromPhoneView.size)
        assertArrayEquals(confirmFromMacView, confirmFromPhoneView)
    }

    @Test
    fun `end-to-end message envelope round trip using derived session keys`() {
        val mac = Ecdh.generateKeyPair()
        val phone = Ecdh.generateKeyPair()
        val token = ByteArray(32).also { random.nextBytes(it) }

        val phoneSession = PairingCrypto.deriveSessionKeys(phone.privateScalar, mac.publicPoint, phone.publicPoint, token)
        val macIkm = Ecdh.sharedSecret(mac.privateScalar, phone.publicPoint)
        val macInfo = "otpfwd-v1".toByteArray(Charsets.US_ASCII) + mac.publicPoint + phone.publicPoint
        val macOkm = Hkdf.deriveKey(macIkm, token, macInfo, 64)
        val macKP2m = macOkm.copyOfRange(0, 32)
        val macKM2p = macOkm.copyOfRange(32, 64)
        val macKeyId = PairingCrypto.deriveKeyId(macKP2m, macKM2p)

        val requestPlaintext = """{"id":"11111111-1111-1111-1111-111111111111","ts":1735238400000,"ctr":0,"sender":"+15551234567","body":"Your OTP is 482913"}""".toByteArray()
        val request = Envelope.seal(phoneSession.kP2m, phoneSession.keyId, requestPlaintext)
        val macOpened = Envelope.open(macKP2m, macKeyId, request)
        assertNotNull(macOpened)
        assertArrayEquals(requestPlaintext, macOpened)

        val ackPlaintext = """{"id":"11111111-1111-1111-1111-111111111111","ctr":0}""".toByteArray()
        val ack = Envelope.seal(macKM2p, macKeyId, ackPlaintext)
        val phoneOpenedAck = Envelope.open(phoneSession.kM2p, phoneSession.keyId, ack)
        assertNotNull(phoneOpenedAck)
        assertArrayEquals(ackPlaintext, phoneOpenedAck)
    }
}
