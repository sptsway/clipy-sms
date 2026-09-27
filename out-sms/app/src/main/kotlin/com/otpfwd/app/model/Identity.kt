package com.otpfwd.app.model

/**
 * Everything persisted about the current pairing — the Android analogue of the Mac daemon's
 * `identity.json` (ARCHITECTURE.md §3.4), stored via `IdentityStore` (DESIGN.md §5). Absent
 * entirely (no instance, no file) when unpaired.
 */
data class Identity(
    val pairingVersion: Int,
    /** Raw 32-byte P-256 scalar. */
    val phonePrivateScalar: ByteArray,
    /** Raw 65-byte uncompressed point — cached alongside the scalar since the platform's EC APIs
     * don't expose a way to re-derive a public point from just a private scalar (see Ecdh.kt). */
    val phonePublicPoint: ByteArray,
    /** Raw 65-byte uncompressed point, pinned at pairing time. */
    val macPublicPoint: ByteArray,
    val deviceName: String,
    val kP2m: ByteArray,
    val kM2p: ByteArray,
    val keyId: ByteArray,
    val hosts: List<String>,
    val port: Int,
    /** The `ctr` value to use for the *next* outgoing message; 0 immediately after a fresh pairing. */
    val nextCtr: Long,
    val lastSentAtMs: Long?,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Identity) return false
        return pairingVersion == other.pairingVersion &&
            phonePrivateScalar.contentEquals(other.phonePrivateScalar) &&
            phonePublicPoint.contentEquals(other.phonePublicPoint) &&
            macPublicPoint.contentEquals(other.macPublicPoint) &&
            deviceName == other.deviceName &&
            kP2m.contentEquals(other.kP2m) &&
            kM2p.contentEquals(other.kM2p) &&
            keyId.contentEquals(other.keyId) &&
            hosts == other.hosts &&
            port == other.port &&
            nextCtr == other.nextCtr &&
            lastSentAtMs == other.lastSentAtMs
    }

    override fun hashCode(): Int {
        var result = pairingVersion
        result = 31 * result + phonePrivateScalar.contentHashCode()
        result = 31 * result + phonePublicPoint.contentHashCode()
        result = 31 * result + macPublicPoint.contentHashCode()
        result = 31 * result + deviceName.hashCode()
        result = 31 * result + kP2m.contentHashCode()
        result = 31 * result + kM2p.contentHashCode()
        result = 31 * result + keyId.contentHashCode()
        result = 31 * result + hosts.hashCode()
        result = 31 * result + port
        result = 31 * result + nextCtr.hashCode()
        result = 31 * result + (lastSentAtMs?.hashCode() ?: 0)
        return result
    }
}
