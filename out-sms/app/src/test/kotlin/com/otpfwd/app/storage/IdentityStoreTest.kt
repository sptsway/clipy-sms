package com.otpfwd.app.storage

import com.otpfwd.app.model.Identity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.security.SecureRandom
import java.util.concurrent.ConcurrentLinkedQueue

class IdentityStoreTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val random = SecureRandom()
    private fun randomBytes(n: Int) = ByteArray(n).also { random.nextBytes(it) }

    private fun sampleIdentity(nextCtr: Long = 0L, lastSent: Long? = null) = Identity(
        pairingVersion = 1,
        phonePrivateScalar = randomBytes(32),
        phonePublicPoint = byteArrayOf(0x04) + randomBytes(64),
        macPublicPoint = byteArrayOf(0x04) + randomBytes(64),
        deviceName = "Swaraj's MacBook Pro",
        kP2m = randomBytes(32),
        kM2p = randomBytes(32),
        keyId = randomBytes(8),
        hosts = listOf("192.168.1.23", "192.168.1.24"),
        port = 47820,
        nextCtr = nextCtr,
        lastSentAtMs = lastSent,
    )

    @Test
    fun `fresh store reports unpaired`() {
        val store = IdentityStore(tempFolder.newFolder())
        assertFalse(store.isPaired())
        assertNull(store.load())
        assertNull(store.reserveNextCtr())
    }

    @Test
    fun `savePairing then load round trips the identity exactly`() {
        val store = IdentityStore(tempFolder.newFolder())
        val identity = sampleIdentity()

        store.savePairing(identity)

        assertTrue(store.isPaired())
        assertEquals(identity, store.load())
    }

    @Test
    fun `clear removes the pairing`() {
        val store = IdentityStore(tempFolder.newFolder())
        store.savePairing(sampleIdentity())
        store.clear()

        assertFalse(store.isPaired())
        assertNull(store.load())
    }

    @Test
    fun `reserveNextCtr starts at 0 after a fresh pairing and increments monotonically`() {
        val store = IdentityStore(tempFolder.newFolder())
        store.savePairing(sampleIdentity(nextCtr = 0L))

        assertEquals(0L, store.reserveNextCtr())
        assertEquals(1L, store.reserveNextCtr())
        assertEquals(2L, store.reserveNextCtr())
    }

    @Test
    fun `counter reservation survives a simulated process restart`() {
        val dir = tempFolder.newFolder()
        var store = IdentityStore(dir)
        store.savePairing(sampleIdentity(nextCtr = 0L))
        store.reserveNextCtr() // 0
        store.reserveNextCtr() // 1
        store.reserveNextCtr() // 2

        // A brand new instance over the same directory stands in for a process restart.
        store = IdentityStore(dir)
        assertEquals(3L, store.reserveNextCtr())
    }

    @Test
    fun `a reserved counter is never reused even if the caller never records success`() {
        val dir = tempFolder.newFolder()
        val store = IdentityStore(dir)
        store.savePairing(sampleIdentity(nextCtr = 0L))

        val reserved = store.reserveNextCtr()
        // Simulate every retry of "this" message failing forever - the app never calls anything
        // that would roll the reservation back (no such API exists), so the next SMS's
        // reservation must move past it, never repeat it.
        val next = store.reserveNextCtr()

        assertEquals(0L, reserved)
        assertEquals(1L, next)
    }

    @Test
    fun `concurrent reservations from multiple threads never collide or skip`() {
        val store = IdentityStore(tempFolder.newFolder())
        store.savePairing(sampleIdentity(nextCtr = 0L))

        val threadCount = 8
        val perThread = 25
        val results = ConcurrentLinkedQueue<Long>()
        val threads = (1..threadCount).map {
            Thread { repeat(perThread) { store.reserveNextCtr()?.let(results::add) } }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        val values = results.toList().sorted()
        val expected = (0 until threadCount * perThread).map { it.toLong() }
        assertEquals(expected, values)
    }

    @Test
    fun `recordSuccessfulSend updates last_sent_at_ms and nothing else`() {
        val store = IdentityStore(tempFolder.newFolder())
        val identity = sampleIdentity(nextCtr = 5L, lastSent = null)
        store.savePairing(identity)

        store.recordSuccessfulSend(1735238400000L)

        val reloaded = store.load()!!
        assertEquals(1735238400000L, reloaded.lastSentAtMs)
        assertEquals(5L, reloaded.nextCtr)
    }

    @Test
    fun `identity file survives being read by a completely separate instance`() {
        val dir = tempFolder.newFolder()
        val identity = sampleIdentity()
        IdentityStore(dir).savePairing(identity)

        val reopened = IdentityStore(dir).load()

        assertEquals(identity, reopened)
    }
}
