package com.otpfwd.app.crypto

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

/**
 * P-256 (secp256r1) key handling matching PROTOCOL.md §1's wire conventions exactly: public keys
 * are always the 65-byte uncompressed SEC1 point (0x04 || X(32) || Y(32), big-endian, zero
 * padded), private keys are the raw 32-byte scalar, and ECDH agreement yields the 32-byte
 * X-coordinate only — matching Go's `crypto/ecdh.PrivateKey.ECDH()` (CRYPTO_IMPLEMENTATION.md §1).
 *
 * Two JCA-specific traps handled explicitly here (not assumed — see DESIGN.md §8):
 *  1. `KeyAgreement.generateSecret()` for EC keys returns the shared X-coordinate as the minimal
 *     big-endian encoding of a BigInteger, NOT zero-padded to the curve's byte length. If the true
 *     coordinate happens to have leading zero byte(s) (~1/256 chance per byte), the raw output
 *     would come back shorter than 32 bytes, silently misaligning with Go's always-32-byte output.
 *  2. The same applies when reading X/Y off an `ECPublicKey`'s `ECPoint` to build the 65-byte
 *     uncompressed point encoding, and `BigInteger.toByteArray()` can also *add* a leading 0x00
 *     sign byte when the high bit of the true value is set.
 * `fixedBytes` below normalizes both directions to an exact, correctly-padded byte length.
 */
object Ecdh {
    private const val CURVE_NAME = "secp256r1"
    const val POINT_SIZE = 65
    const val COORD_SIZE = 32
    const val SCALAR_SIZE = 32
    private const val UNCOMPRESSED_PREFIX: Byte = 0x04

    private val ecParameterSpec: ECParameterSpec by lazy {
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec(CURVE_NAME))
        params.getParameterSpec(ECParameterSpec::class.java)
    }

    private val keyFactory: KeyFactory by lazy { KeyFactory.getInstance("EC") }

    data class KeyPairBytes(val privateScalar: ByteArray, val publicPoint: ByteArray)

    /** Generates a fresh P-256 keypair, returning both the raw private scalar and the raw
     * uncompressed public point — a fresh pairing always discards any previous keypair
     * (prompt.md pairing step 2), so callers should never try to reuse one across pairings. */
    fun generateKeyPair(random: SecureRandom = SecureRandom()): KeyPairBytes {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec(CURVE_NAME), random)
        val pair = generator.generateKeyPair()
        val priv = pair.private as ECPrivateKey
        val pub = pair.public as ECPublicKey
        return KeyPairBytes(
            privateScalar = fixedBytes(priv.s, SCALAR_SIZE),
            publicPoint = encodePoint(pub),
        )
    }

    /** Rebuilds a `PrivateKey` from a raw 32-byte scalar, e.g. after reading it back from
     * `IdentityStore`. */
    fun privateKeyFromScalar(scalar: ByteArray): PrivateKey {
        require(scalar.size == SCALAR_SIZE) { "private scalar must be $SCALAR_SIZE bytes, got ${scalar.size}" }
        val spec = ECPrivateKeySpec(BigInteger(1, scalar), ecParameterSpec)
        return keyFactory.generatePrivate(spec)
    }

    /** Parses a 65-byte uncompressed SEC1 point. Rejects anything else (compressed form, point at
     * infinity, wrong length) — PROTOCOL.md §1 requires uncompressed-only, never accept other forms. */
    fun publicKeyFromPoint(point: ByteArray): PublicKey {
        require(point.size == POINT_SIZE) { "public point must be $POINT_SIZE bytes (uncompressed), got ${point.size}" }
        require(point[0] == UNCOMPRESSED_PREFIX) { "public point must start with 0x04 (uncompressed form)" }
        val x = BigInteger(1, point.copyOfRange(1, 1 + COORD_SIZE))
        val y = BigInteger(1, point.copyOfRange(1 + COORD_SIZE, 1 + 2 * COORD_SIZE))
        require(x.signum() != 0 || y.signum() != 0) { "public point must not be the point at infinity" }
        val spec = ECPublicKeySpec(ECPoint(x, y), ecParameterSpec)
        return keyFactory.generatePublic(spec)
    }

    /** Encodes an `ECPublicKey` as the 65-byte uncompressed SEC1 point. */
    fun encodePoint(publicKey: ECPublicKey): ByteArray {
        val x = fixedBytes(publicKey.w.affineX, COORD_SIZE)
        val y = fixedBytes(publicKey.w.affineY, COORD_SIZE)
        return byteArrayOf(UNCOMPRESSED_PREFIX) + x + y
    }

    /** The raw ECDH shared secret (X-coordinate only, 32 bytes) — this value IS `ikm` in
     * PROTOCOL.md §3.4; never hash it or prepend anything before feeding it to HKDF. */
    fun sharedSecret(privateScalar: ByteArray, remotePublicPoint: ByteArray): ByteArray {
        val priv = privateKeyFromScalar(privateScalar)
        val pub = publicKeyFromPoint(remotePublicPoint)
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(priv)
        agreement.doPhase(pub, true)
        return leftPad(agreement.generateSecret(), COORD_SIZE)
    }

    private fun fixedBytes(value: BigInteger, length: Int): ByteArray {
        val raw = value.toByteArray()
        return when {
            raw.size == length -> raw
            raw.size == length + 1 && raw[0] == 0.toByte() -> raw.copyOfRange(1, raw.size)
            raw.size < length -> leftPad(raw, length)
            else -> throw IllegalStateException("EC coordinate does not fit in $length bytes (got ${raw.size})")
        }
    }

    private fun leftPad(bytes: ByteArray, length: Int): ByteArray {
        if (bytes.size == length) return bytes
        check(bytes.size < length) { "value longer than $length bytes (got ${bytes.size})" }
        val padded = ByteArray(length)
        bytes.copyInto(padded, length - bytes.size)
        return padded
    }
}
