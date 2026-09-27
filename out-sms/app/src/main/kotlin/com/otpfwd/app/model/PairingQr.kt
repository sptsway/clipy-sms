package com.otpfwd.app.model

/** Parsed `otpfwd://pair?...` QR payload (PROTOCOL.md §3.2). Transient — never persisted as-is;
 * a successful pairing exchange turns this into an [Identity] instead. */
data class PairingQr(
    /** Raw 65-byte uncompressed P-256 point. */
    val macPub: ByteArray,
    /** Raw 32 bytes. */
    val token: ByteArray,
    val hosts: List<String>,
    val port: Int,
    val name: String,
    val expUnixSeconds: Long,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PairingQr) return false
        return macPub.contentEquals(other.macPub) &&
            token.contentEquals(other.token) &&
            hosts == other.hosts &&
            port == other.port &&
            name == other.name &&
            expUnixSeconds == other.expUnixSeconds
    }

    override fun hashCode(): Int {
        var result = macPub.contentHashCode()
        result = 31 * result + token.contentHashCode()
        result = 31 * result + hosts.hashCode()
        result = 31 * result + port
        result = 31 * result + name.hashCode()
        result = 31 * result + expUnixSeconds.hashCode()
        return result
    }
}
