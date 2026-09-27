package com.otpfwd.app.ui

import android.app.Application
import android.os.Build
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.otpfwd.app.OtpFwdApp
import com.otpfwd.app.pairing.PairingClient
import com.otpfwd.app.pairing.PairingQrParser
import com.otpfwd.app.storage.IdentityStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class UiState(
    val paired: Boolean,
    val deviceName: String? = null,
    val lastSentAtMs: Long? = null,
    val pairingInProgress: Boolean = false,
    val pairingError: String? = null,
)

class OtpFwdViewModel(application: Application) : AndroidViewModel(application) {
    private val identityStore: IdentityStore = OtpFwdApp.from(application).identityStore

    private val _uiState = MutableStateFlow(loadPairedState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private fun loadPairedState(): UiState {
        val identity = identityStore.load()
        return UiState(paired = identity != null, deviceName = identity?.deviceName, lastSentAtMs = identity?.lastSentAtMs)
    }

    /** Called when returning to the screen (e.g. after a successful send updated `last_sent_at_ms`
     * on disk) to pick up the latest persisted state. */
    fun refresh() {
        if (_uiState.value.pairingInProgress) return
        _uiState.value = loadPairedState()
    }

    fun onQrScanned(rawValue: String) {
        if (_uiState.value.pairingInProgress) return
        _uiState.value = _uiState.value.copy(pairingInProgress = true, pairingError = null)

        viewModelScope.launch {
            val errorMessage = withContext(Dispatchers.IO) {
                try {
                    val qr = PairingQrParser.parse(rawValue, System.currentTimeMillis() / 1000)
                    val deviceName = Build.MODEL ?: "Android phone"
                    val identity = PairingClient.pair(qr, deviceName)
                    identityStore.savePairing(identity)
                    null
                } catch (e: PairingQrParser.InvalidPairingQr) {
                    // Not a wire-protocol exchange failure at all (nothing was sent over the
                    // network) — safe to be specific here without touching the generic-failure
                    // posture PROTOCOL.md/prompt.md require for the actual pairing exchange.
                    "That doesn't look like an OTP Forwarder pairing QR code. Try scanning it again."
                } catch (e: PairingClient.PairingFailed) {
                    e.message
                } catch (e: Exception) {
                    PairingClient.PairingFailed().message
                }
            }

            _uiState.value = if (errorMessage == null) {
                loadPairedState()
            } else {
                _uiState.value.copy(pairingInProgress = false, pairingError = errorMessage)
            }
        }
    }

    fun dismissPairingError() {
        _uiState.value = _uiState.value.copy(pairingError = null)
    }

    fun unpair() {
        identityStore.clear()
        _uiState.value = loadPairedState()
    }
}
