package com.otpfwd.app

import android.app.Application
import android.content.Context
import com.otpfwd.app.storage.IdentityStore

/**
 * Holds the single app-wide [IdentityStore] instance. Callers (the SMS receiver, the forward
 * worker, and the UI) must all go through this one instance rather than constructing their own —
 * `IdentityStore`'s counter-reservation locking (DESIGN.md §5) only serializes calls made through
 * the *same* object.
 */
class OtpFwdApp : Application() {
    val identityStore: IdentityStore by lazy { IdentityStore(filesDir) }

    companion object {
        fun from(context: Context): OtpFwdApp = context.applicationContext as OtpFwdApp
    }
}
