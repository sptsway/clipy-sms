package com.otpfwd.app.sms

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.WorkerParameters
import androidx.work.hasKeyWithValueOfType
import com.otpfwd.app.OtpFwdApp
import com.otpfwd.app.crypto.Envelope
import com.otpfwd.app.model.OutgoingSms
import com.otpfwd.app.net.MsgClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import androidx.work.ListenableWorker.Result as WorkResult

/**
 * Does the actual encrypt-and-POST work for one SMS, off the `BroadcastReceiver` entirely
 * (DESIGN.md §4). The `ctr` this worker uses is fixed at enqueue time (passed in via [Data], see
 * [SmsReceivedReceiver]) and reused verbatim across every WorkManager retry of this same work
 * request — this class never calls `IdentityStore.reserveNextCtr()` itself, which is what makes
 * WorkManager's automatic retries safe rather than double-reserving a counter value per retry.
 */
class ForwardWorker(appContext: Context, params: WorkerParameters) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): WorkResult {
        val identityStore = OtpFwdApp.from(applicationContext).identityStore
        // Unpaired (e.g. the user unpaired between this SMS arriving and this worker running) —
        // nothing to forward to; per the non-goals there is no outbox, so just stop.
        val identity = identityStore.load() ?: return WorkResult.failure()

        val id = inputData.getString(KEY_ID) ?: return WorkResult.failure()
        val tsMs = inputData.getLong(KEY_TS_MS, -1L).takeIf { it >= 0 } ?: return WorkResult.failure()
        val ctr = inputData.getLong(KEY_CTR, -1L).takeIf { it >= 0 } ?: return WorkResult.failure()
        val sender = inputData.getString(KEY_SENDER) ?: return WorkResult.failure()
        val body = inputData.getString(KEY_BODY) ?: return WorkResult.failure()
        val sim = if (inputData.hasKeyWithValueOfType<Int>(KEY_SIM)) inputData.getInt(KEY_SIM, 0) else null

        val plaintext = OutgoingSms(id = id, tsMs = tsMs, ctr = ctr, sender = sender, body = body, sim = sim).toJsonBytes()
        val envelope = Envelope.seal(identity.kP2m, identity.keyId, plaintext)

        val result = withContext(Dispatchers.IO) {
            MsgClient.send(identity, envelope, expectedId = id, expectedCtr = ctr)
        }
        return when (result) {
            is MsgClient.Result.Success -> {
                identityStore.recordSuccessfulSend(System.currentTimeMillis())
                WorkResult.success()
            }
            MsgClient.Result.Failure -> {
                // runAttemptCount is 0 on the first run; give up once this was the last of
                // MAX_ATTEMPTS allowed tries (DESIGN.md §4 — a concrete, spec-unspecified choice).
                if (runAttemptCount >= MAX_ATTEMPTS - 1) WorkResult.failure() else WorkResult.retry()
            }
        }
    }

    companion object {
        const val KEY_ID = "id"
        const val KEY_TS_MS = "ts_ms"
        const val KEY_CTR = "ctr"
        const val KEY_SENDER = "sender"
        const val KEY_BODY = "body"
        const val KEY_SIM = "sim"

        /** One initial attempt plus two retries. */
        const val MAX_ATTEMPTS = 3
        const val BACKOFF_DELAY_MS = 10_000L
    }
}
