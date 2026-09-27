import AppKit
import SwiftUI

/// The MenuBarExtra's contents (ARCHITECTURE.md §5): disabled "Recent"
/// header, latest 5 messages, "Older" chunked submenus, a status line, then
/// the action items. Menu order matches prompt.md exactly.
struct MenuContent: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Group {
            Text("Recent  (click to view full message)").font(.caption).foregroundStyle(.secondary)

            if model.recentMessages.isEmpty {
                Text("No messages yet").disabled(true)
            } else {
                ForEach(model.recentMessages) { message in
                    MessageRow(message: message, model: model)
                }
            }

            if !model.olderChunks.isEmpty {
                Divider()
                ForEach(model.olderChunks) { chunk in
                    Menu(chunk.label) {
                        OlderChunkContent(model: model, chunk: chunk)
                    }
                }
            }

            Divider()
            Text(model.statusLine).font(.caption).foregroundStyle(.secondary)

            Divider()
            Button("Pair New Phone…") {
                model.isPairWindowPresented = true
                openWindow(id: "pair")
            }
            Button("Unpair") { Task { await model.unpair() } }
                .disabled(!model.deviceStatus.paired)
            Button("Clear History") { Task { await model.clearHistory() } }
                .disabled(model.totalMessages == 0)
            Button("Settings…") {
                model.isSettingsWindowPresented = true
                openWindow(id: "settings")
            }

            Divider()
            Button("Quit") { NSApp.terminate(nil) }
        }
    }
}

/// One "OTP:xyz  SMS preview  —  Sender · HH:mm" row. Click opens the full
/// message in a floating popup near the click, with selectable text and a
/// Copy button — the preview shown here is capped in length regardless,
/// since NSMenu sizes the whole menu to its widest row, so an uncapped long
/// SMS would stretch every row, including Settings/Quit/etc.
struct MessageRow: View {
    let message: SMSMessage
    @ObservedObject var model: AppModel

    private static let previewLimit = 45

    var body: some View {
        Button(action: {
            MessageDetailPanelController.shared.show(message, model: model)
        }) {
            Text(label)
        }
    }

    private var label: String {
        let time = message.receivedDate.formatted(date: .omitted, time: .shortened)
        let body = message.body
        let preview = body.count > Self.previewLimit
            ? String(body.prefix(Self.previewLimit)) + "…"
            : body
        let otp = message.otpHint ?? "nil"
        return "OTP:\(otp)  \(preview)  —  \(message.sender) · \(time)"
    }
}

/// Lazily loads one "Older" chunk's messages when its submenu is opened,
/// via the same messages.list pagination the daemon exposes over IPC.
struct OlderChunkContent: View {
    @ObservedObject var model: AppModel
    let chunk: OlderChunk

    @State private var items: [SMSMessage] = []
    @State private var loaded = false

    var body: some View {
        Group {
            if !loaded {
                Text("Loading…").disabled(true)
            } else if items.isEmpty {
                Text("No messages").disabled(true)
            } else {
                ForEach(items) { message in
                    MessageRow(message: message, model: model)
                }
            }
        }
        .task {
            guard !loaded else { return }
            items = await model.fetchOlderChunk(offset: chunk.offset, limit: chunk.limit)
            loaded = true
        }
    }
}
