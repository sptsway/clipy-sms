package com.otpfwd.app.sms

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.telephony.SubscriptionManager
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.Data
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.otpfwd.app.OtpFwdApp
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Reacts to the protected `SMS_RECEIVED` system broadcast (DESIGN.md §4). Does only fast,
 * synchronous work here — parsing the intent and durably reserving the next `ctr` — then hands the
 * actual encrypt-and-POST job to WorkManager ([ForwardWorker]) so it survives beyond this
 * receiver's short execution budget and gets WorkManager's built-in retry/backoff.
 */
class SmsReceivedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        // A single logical SMS delivered as multiple concatenated-SMS parts shows up as several
        // SmsMessage entries sharing one sender in the same broadcast; forward them as one message
        // (DESIGN.md §7 — the Mac side has no notion of "part 2 of 3").
        val sender = messages[0].originatingAddress ?: return
        val body = messages.joinToString(separator = "") { it.messageBody ?: "" }
        val simSlot = extractSimSlot(context, intent)

        val identityStore = OtpFwdApp.from(context).identityStore
        // Not currently paired — nothing to forward to, and no outbox to hold it for later
        // (non-goals): just let this SMS sit on the phone like normal.
        val ctr = identityStore.reserveNextCtr() ?: return

        val dataBuilder = Data.Builder()
            .putString(ForwardWorker.KEY_ID, UUID.randomUUID().toString())
            .putLong(ForwardWorker.KEY_TS_MS, System.currentTimeMillis())
            .putLong(ForwardWorker.KEY_CTR, ctr)
            .putString(ForwardWorker.KEY_SENDER, sender)
            .putString(ForwardWorker.KEY_BODY, body)
        if (simSlot != null) dataBuilder.putInt(ForwardWorker.KEY_SIM, simSlot)

        val request = OneTimeWorkRequestBuilder<ForwardWorker>()
            .setInputData(dataBuilder.build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, ForwardWorker.BACKOFF_DELAY_MS, TimeUnit.MILLISECONDS)
            // Uses ACCESS_NETWORK_STATE (DESIGN.md §3) so WorkManager holds the job until there is
            // any active network rather than burning through MAX_ATTEMPTS while offline.
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()

        WorkManager.getInstance(context).enqueue(request)
    }

    /** Best-effort only (DESIGN.md §7 / prompt.md's "just pass whatever slot index is
     * convenient"): this app deliberately does not request READ_PHONE_STATE, so
     * `SubscriptionManager` lookups routinely fail with `SecurityException` on many OEM/API
     * combinations — that, a missing "subscription" extra, or a single-SIM device all just result
     * in `sim` being omitted from the forwarded message, never in blocking the forward. */
    private fun extractSimSlot(context: Context, intent: Intent): Int? = try {
        val subId = intent.getIntExtra("subscription", -1)
        if (subId == -1) {
            null
        } else {
            context.getSystemService(SubscriptionManager::class.java)
                ?.getActiveSubscriptionInfo(subId)
                ?.simSlotIndex
        }
    } catch (e: Exception) {
        null
    }
}
