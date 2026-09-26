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

    /// Prefers the real daemon; falls back to canned sample data so the menu
    /// is fully browsable even before otpd's pairing/message path exists
    /// (docs/CRYPTO_IMPLEMENTATION.md) — e.g. during UI-only development.
    private static func makeClient() -> IPCClient {
        if let real = try? UnixSocketIPCClient() {
            return real
        }
        return MockIPCClient()
    }
}
