import SwiftUI

@main
struct OTPForwarderApp: App {
    @StateObject private var model: AppModel

    init() {
        let client = Self.makeClient()
        _model = StateObject(wrappedValue: AppModel(client: client))
        NotificationManager.shared.requestAuthorizationIfNeeded()
    }

    var body: some Scene {
        MenuBarExtra("OTP Forwarder", systemImage: "key.fill") {
            MenuContent(model: model)
        }
        .menuBarExtraStyle(.menu)

        Window("Pair New Phone", id: "pair") {
            PairWindow(model: model)
        }
        .windowResizability(.contentSize)

        Window("Settings", id: "settings") {
            SettingsWindow(model: model)
        }
        .windowResizability(.contentSize)
    }

    /// Connects to the real daemon. If otpd isn't running yet,
    /// DisconnectedIPCClient takes over so the UI shows "Daemon not
    /// running" instead of crashing or inventing data.
    private static func makeClient() -> IPCClient {
        if let real = try? UnixSocketIPCClient() {
            return real
        }
        return DisconnectedIPCClient()
    }
}
