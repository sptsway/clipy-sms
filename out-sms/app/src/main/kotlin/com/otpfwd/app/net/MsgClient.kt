package com.otpfwd.app.net

import com.otpfwd.app.crypto.Envelope
import com.otpfwd.app.json.Json
import com.otpfwd.app.model.Identity
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI

/**
 * A single `POST /v1/msg` attempt (PROTOCOL.md §4) — no retry logic here; `ForwardWorker` owns
 * retry/backoff via WorkManager (DESIGN.md §4). One call to [send] walks `identity.hosts` once, in
 * order, exactly like `PairingClient`: the first host that gives *any* HTTP response wins (that
 * response, success or failure, is final for this attempt), and only a connection-level failure
 * moves on to the next host in the list.
 */
object MsgClient {
    sealed class Result {
        data class Success(val ackId: String, val ackCtr: Long) : Result()
        object Failure : Result()
    }

    private const val CONNECT_TIMEOUT_MS = 2000
    private const val READ_TIMEOUT_MS = 3000

    fun send(identity: Identity, envelope: ByteArray, expectedId: String, expectedCtr: Long): Result {
        for (host in identity.hosts) {
            val response = postEnvelope(host, identity.port, envelope) ?: continue
            return parseAck(identity, response, expectedId, expectedCtr)
        }
        return Result.Failure
    }

    private fun parseAck(identity: Identity, response: HttpResponse, expectedId: String, expectedCtr: Long): Result {
        if (response.statusCode != 200) return Result.Failure
        val plaintext = Envelope.open(identity.kM2p, identity.keyId, response.body) ?: return Result.Failure
        return try {
            val obj = Json.parseObj(String(plaintext, Charsets.UTF_8))
            val ackId = obj.getString("id")
            val ackCtr = obj.getLong("ctr")
            if (ackId == expectedId && ackCtr == expectedCtr) Result.Success(ackId, ackCtr) else Result.Failure
        } catch (e: Exception) {
            Result.Failure
        }
    }

    private data class HttpResponse(val statusCode: Int, val body: ByteArray)

    private fun postEnvelope(host: String, port: Int, envelope: ByteArray): HttpResponse? = try {
        val connection = URI("http://$host:$port/v1/msg").toURL().openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.setRequestProperty("Content-Type", "application/octet-stream")
            connection.outputStream.use { it.write(envelope) }

            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.use { it.readBytes() } ?: ByteArray(0)
            HttpResponse(code, body)
        } finally {
            connection.disconnect()
        }
    } catch (e: IOException) {
        null
    }
}
