import ServiceManagement
import SwiftUI

/// Settings window (prompt.md): N (max stored messages), auto-copy newest,
/// clipboard clear delay, port, launch at login, notifications.
struct SettingsWindow: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var draft = AppSettings.defaults
    @State private var launchAtLoginError: String?

    var body: some View {
        Form {
            Section("History") {
                Stepper(value: $draft.maxMessages, in: 10...1000, step: 10) {
                    Text("Max stored messages: \(draft.maxMessages)")
                }
                Toggle("Auto-copy newest code", isOn: $draft.autoCopyNewest)
            }

            Section("Clipboard") {
                Stepper(value: $draft.clipboardClearSeconds, in: 0...300, step: 5) {
                    Text("Clear after: \(draft.clipboardClearSeconds == 0 ? "Never" : "\(draft.clipboardClearSeconds)s")")
                }
            }

            Section("Network") {
                TextField("Port", value: $draft.port, format: .number.grouping(.never))
            }

            Section("Startup") {
                Toggle("Launch at login", isOn: launchAtLoginBinding)
                if let launchAtLoginError {
                    Text(launchAtLoginError)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Section("Notifications") {
                Toggle("Show notifications for new codes", isOn: $draft.notificationsEnabled)
            }

            HStack {
                Spacer()
                Button("Cancel") { model.isSettingsWindowPresented = false }
                Button("Save") {
                    Task {
                        await model.saveSettings(draft)
                        model.isSettingsWindowPresented = false
                    }
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 420)
        .onAppear { draft = model.settings }
        .onChange(of: model.isSettingsWindowPresented) { presented in
            if !presented { dismiss() }
        }
    }

    /// SMAppService requires a properly signed, bundled .app to actually
    /// register a login item (ARCHITECTURE.md §6, Milestone 5) — running via
    /// `swift run` during development, this will typically fail, which is
    /// expected rather than a bug in this code.
    private var launchAtLoginBinding: Binding<Bool> {
        Binding(
            get: { draft.launchAtLogin },
            set: { newValue in
                do {
                    if newValue {
                        try SMAppService.mainApp.register()
                    } else {
                        try SMAppService.mainApp.unregister()
                    }
                    draft.launchAtLogin = newValue
                    launchAtLoginError = nil
                } catch {
                    launchAtLoginError = "Couldn't change login item: \(error.localizedDescription)"
                }
            }
        )
    }
}
