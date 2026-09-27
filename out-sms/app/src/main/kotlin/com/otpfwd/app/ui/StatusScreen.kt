package com.otpfwd.app.ui

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** Status screen shown while paired (DESIGN.md §9) — paired device name, last-forwarded time, and
 * an Unpair button. No message list, no settings beyond this, per the non-goals. */
@Composable
fun StatusScreen(deviceName: String, lastSentAtMs: Long?, onUnpair: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Paired with", style = MaterialTheme.typography.labelLarge)
        Spacer(Modifier.height(4.dp))
        Text(deviceName, style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(24.dp))
        Text("Last forwarded SMS", style = MaterialTheme.typography.labelLarge)
        Spacer(Modifier.height(4.dp))
        Text(formatLastSent(lastSentAtMs), style = MaterialTheme.typography.bodyLarge)
        Spacer(Modifier.height(48.dp))
        OutlinedButton(onClick = onUnpair) {
            Text("Unpair")
        }
    }
}

private fun formatLastSent(lastSentAtMs: Long?): String {
    if (lastSentAtMs == null) return "Never"
    return DateUtils.getRelativeTimeSpanString(
        lastSentAtMs,
        System.currentTimeMillis(),
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}
