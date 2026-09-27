package com.otpfwd.app

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.viewmodel.compose.viewModel
import com.otpfwd.app.ui.OtpFwdTheme
import com.otpfwd.app.ui.OtpFwdViewModel
import com.otpfwd.app.ui.PairScreen
import com.otpfwd.app.ui.StatusScreen
import com.otpfwd.app.ui.WelcomeScreen

/** The app's single Activity (DESIGN.md §9) — hosts three Compose screens, with no navigation
 * library: which one shows is purely a function of `uiState.paired` plus one local
 * "has the user tapped Scan yet" flag for the unpaired welcome/scanner split. */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            OtpFwdTheme {
                OtpFwdRoot()
            }
        }
    }
}

@Composable
private fun OtpFwdRoot(viewModel: OtpFwdViewModel = viewModel()) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    val smsPermissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }

    // Forwarding cannot work at all without RECEIVE_SMS, so ask for it as soon as pairing
    // succeeds (DESIGN.md §3 — requested when actually needed, not at first launch).
    LaunchedEffect(uiState.paired) {
        if (uiState.paired &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED
        ) {
            smsPermissionLauncher.launch(Manifest.permission.RECEIVE_SMS)
        }
    }

    // Re-read persisted state whenever the activity returns to the foreground, so a
    // background ForwardWorker's `last_sent_at_ms` update (or an unpair from elsewhere) shows up
    // without the user needing to relaunch the app.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) viewModel.refresh()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    if (uiState.paired) {
        StatusScreen(
            deviceName = uiState.deviceName ?: "Unknown device",
            lastSentAtMs = uiState.lastSentAtMs,
            onUnpair = viewModel::unpair,
        )
    } else {
        var showScanner by rememberSaveable { mutableStateOf(false) }
        if (showScanner) {
            PairScreen(
                pairingInProgress = uiState.pairingInProgress,
                pairingError = uiState.pairingError,
                onQrScanned = viewModel::onQrScanned,
                onDismissError = viewModel::dismissPairingError,
            )
        } else {
            WelcomeScreen(onStartPairing = { showScanner = true })
        }
    }
}
