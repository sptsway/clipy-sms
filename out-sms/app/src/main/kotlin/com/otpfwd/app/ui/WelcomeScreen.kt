package com.otpfwd.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * First screen shown when unpaired, before the camera/QR scanner ever opens. Two reasons this
 * exists rather than jumping straight into [PairScreen]:
 *  - Gives the user context on what the app does before asking for anything.
 *  - Defers the camera-permission prompt until the user actually taps "Scan QR Code", matching
 *    DESIGN.md §3's "permissions requested when actually needed" principle — previously the
 *    camera permission was requested immediately on first launch, before any user action.
 */
@Composable
fun WelcomeScreen(onStartPairing: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = "OTP Forwarder",
            style = MaterialTheme.typography.headlineMedium,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = "Forwards incoming SMS to a paired Mac, encrypted end to end. Pair once with " +
                "the QR code shown by the Mac app, then leave this running in the background.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(32.dp))
        Button(onClick = onStartPairing, modifier = Modifier.fillMaxWidth()) {
            Text("Scan QR Code to Pair")
        }
    }
}
