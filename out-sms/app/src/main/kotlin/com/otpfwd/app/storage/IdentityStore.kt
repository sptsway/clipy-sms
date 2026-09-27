package com.otpfwd.app.storage

import com.otpfwd.app.crypto.Base64Url
import com.otpfwd.app.json.Json
import com.otpfwd.app.model.Identity
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Durable local storage for the pairing/session state (DESIGN.md §5) — plain files in app-private
 * storage, atomically written, deliberately mirroring the Mac daemon's own "no OS keychain, file
 * permissions only" simplification (ARCHITECTURE.md §3.4) rather than the Android Keystore.
 *
 * Takes a plain [File] directory rather than a `Context` specifically so this class has zero
 * Android-framework imports and is exercised directly by plain JVM unit tests (a temp directory
 * standing in for `Context.filesDir`), per prompt.md's "counter persistence surviving a simulated
 * process restart" requirement — a fresh `IdentityStore` instance pointed at the same directory
 * must pick up exactly where a previous instance left off.
 *
 * Callers must share a single instance per process (e.g. one held by the `Application` subclass):
 * the in-process [lock] only serializes calls made through the *same* `IdentityStore` object.
 */
class IdentityStore(private val dir: File) {
    private val file = File(dir, "identity.json")
    private val tmpFile = File(dir, "identity.json.tmp")
    private val lock = ReentrantLock()

    fun isPaired(): Boolean = lock.withLock { file.exists() }

    fun load(): Identity? = lock.withLock { readLocked() }

    fun savePairing(identity: Identity) = lock.withLock { writeLocked(identity) }

    fun clear() = lock.withLock { if (file.exists()) file.delete() }

    /**
     * Durably reserves the next outgoing `ctr` and returns it, implementing prompt.md's "reserve
     * the next ctr value before attempting to send; persist it, then use that fixed value for
     * every retry of this particular message." The reservation is final the instant this call
     * returns, regardless of whether the subsequent network send ever succeeds — a gap in `ctr`
     * values is fine (PROTOCOL.md §4.3), reuse is never fine. Returns `null` if unpaired.
     */
    fun reserveNextCtr(): Long? = lock.withLock {
        val identity = readLocked() ?: return@withLock null
        val reserved = identity.nextCtr
        writeLocked(identity.copy(nextCtr = reserved + 1))
        reserved
    }

    fun recordSuccessfulSend(atMs: Long) = lock.withLock {
        val identity = readLocked() ?: return@withLock
        writeLocked(identity.copy(lastSentAtMs = atMs))
    }

    private fun readLocked(): Identity? {
        if (!file.exists()) return null
        val obj = Json.parseObj(file.readText(Charsets.UTF_8))
        return Identity(
            pairingVersion = obj.getLong("pairing_version").toInt(),
            phonePrivateScalar = Base64Url.decode(obj.getString("phone_priv")),
            phonePublicPoint = Base64Url.decode(obj.getString("phone_pub")),
            macPublicPoint = Base64Url.decode(obj.getString("mac_pub")),
            deviceName = obj.getString("device_name"),
            kP2m = Base64Url.decode(obj.getString("k_p2m")),
            kM2p = Base64Url.decode(obj.getString("k_m2p")),
            keyId = Base64Url.decode(obj.getString("key_id")),
            hosts = obj.getStringList("hosts"),
            port = obj.getLong("port").toInt(),
            nextCtr = obj.getLong("next_ctr"),
            lastSentAtMs = obj.getNullableLong("last_sent_at_ms"),
        )
    }

    private fun writeLocked(identity: Identity) {
        val obj = Json.obj()
            .put("pairing_version", identity.pairingVersion.toLong())
            .put("phone_priv", Base64Url.encode(identity.phonePrivateScalar))
            .put("phone_pub", Base64Url.encode(identity.phonePublicPoint))
            .put("mac_pub", Base64Url.encode(identity.macPublicPoint))
            .put("device_name", identity.deviceName)
            .put("k_p2m", Base64Url.encode(identity.kP2m))
            .put("k_m2p", Base64Url.encode(identity.kM2p))
            .put("key_id", Base64Url.encode(identity.keyId))
            .put("hosts", identity.hosts)
            .put("port", identity.port.toLong())
            .put("next_ctr", identity.nextCtr)
            .putNullableLong("last_sent_at_ms", identity.lastSentAtMs)
        val bytes = Json.write(obj).toByteArray(Charsets.UTF_8)

        dir.mkdirs()
        FileOutputStream(tmpFile).use { fos ->
            fos.write(bytes)
            fos.fd.sync()
        }
        if (!tmpFile.renameTo(file)) {
            // renameTo is atomic on the same filesystem on Linux/Android but can fail across
            // filesystems on some hosts (notably in a couple of JVM/OS combinations used for
            // plain-JVM unit tests) — fall back to a plain copy+delete rather than leaving the
            // temp file orphaned.
            file.writeBytes(tmpFile.readBytes())
            tmpFile.delete()
        }
    }
}
