package com.otpfwd.app.pairing

import com.otpfwd.app.crypto.Base64Url
import com.otpfwd.app.crypto.Ecdh
import com.otpfwd.app.crypto.PairingCrypto
import com.otpfwd.app.json.Json
import com.otpfwd.app.model.Identity
import com.otpfwd.app.model.PairingQr
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.nio.charset.StandardCharsets

/**
 * Phone's side of PROTOCOL.md §3 — POSTs `/v1/pair` to each host in turn, derives session keys,
 * and verifies the daemon's `confirm`.
 *
 * Per DESIGN.md §6 / prompt.md's pairing step 7, every failure surfaces identically as
 * [PairingFailed], including "no host reachable" — deliberately stricter than the wire protocol's
 * own opacity requirement (which is about the daemon's HTTP responses, not this app's own UI), but
 * that's the literal reading of "don't try to distinguish why pairing failed to the user beyond
 * 'pairing failed'".
 *
 * `hosts` are alternate LAN network paths to the *same single* daemon (multiple interfaces on one
 * Mac), not independent pairing endpoints — so once any host gives a definitive HTTP response
 * (success or failure), that response is final and no other host is tried, matching DESIGN.md §6:
 * "first host that returns any HTTP response wins". Only a connection-level failure (unreachable,
 * timed out) moves on to the next host in the list.
 */
object PairingClient {
    class PairingFailed :
        Exception("Pairing failed. Check that your phone and Mac are on the same Wi-Fi network and try again.")

    private const val CONNECT_TIMEOUT_MS = 2000
    private const val READ_TIMEOUT_MS = 3000

    fun pair(qr: PairingQr, deviceName: String): Identity {
        val phoneKeys = Ecdh.generateKeyPair()
        val mac = PairingCrypto.computePairingMac(qr.token, qr.macPub, phoneKeys.publicPoint)

        val requestBody = Json.obj()
            .put("v", 1L)
            .put("phone_pub", Base64Url.encode(phoneKeys.publicPoint))
            .put("device_name", deviceName)
            .put("mac", Base64Url.encode(mac))
        val requestBytes = Json.write(requestBody).toByteArray(StandardCharsets.UTF_8)

        for (host in qr.hosts) {
            when (val attempt = attemptHost(host, qr.port, requestBytes)) {
                is HostAttempt.Unreachable -> continue
                is HostAttempt.Reached -> return handleResponse(attempt, qr, phoneKeys, deviceName)
            }
        }
        throw PairingFailed() // no host in the list was reachable at all
    }

    private fun handleResponse(
        attempt: HostAttempt.Reached,
        qr: PairingQr,
        phoneKeys: Ecdh.KeyPairBytes,
        deviceName: String,
    ): Identity {
        if (attempt.statusCode != 200) throw PairingFailed()

        val responseObj = try {
            Json.parseObj(String(attempt.body, StandardCharsets.UTF_8))
        } catch (e: Exception) {
            throw PairingFailed()
        }
        if (responseObj.getBoolOrNull("ok") != true) throw PairingFailed()

        val confirmBytes = try {
            Base64Url.decode(responseObj.getString("confirm"))
        } catch (e: Exception) {
            throw PairingFailed()
        }

        val session = PairingCrypto.deriveSessionKeys(
            phoneKeys.privateScalar, qr.macPub, phoneKeys.publicPoint, qr.token,
        )
        val expectedConfirm = PairingCrypto.computeConfirm(session.kM2p)
        if (!confirmBytes.contentEquals(expectedConfirm)) throw PairingFailed()

        return Identity(
            pairingVersion = 1,
            phonePrivateScalar = phoneKeys.privateScalar,
            phonePublicPoint = phoneKeys.publicPoint,
            macPublicPoint = qr.macPub,
            deviceName = deviceName,
            kP2m = session.kP2m,
            kM2p = session.kM2p,
            keyId = session.keyId,
            hosts = qr.hosts,
            port = qr.port,
            nextCtr = 0L,
            lastSentAtMs = null,
        )
    }

    private sealed class HostAttempt {
        data class Reached(val statusCode: Int, val body: ByteArray) : HostAttempt()
        object Unreachable : HostAttempt()
    }

    private fun attemptHost(host: String, port: Int, body: ByteArray): HostAttempt = try {
        val connection = URI("http://$host:$port/v1/pair").toURL().openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.setRequestProperty("Content-Type", "application/json")
            connection.outputStream.use { it.write(body) }

            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val responseBody = stream?.use { it.readBytes() } ?: ByteArray(0)
            HostAttempt.Reached(code, responseBody)
        } finally {
            connection.disconnect()
        }
    } catch (e: IOException) {
        HostAttempt.Unreachable
    }
}
