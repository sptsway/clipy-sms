import AppKit
import SwiftUI

/// The message detail popup's content — full body as selectable text, plus
/// Copy/Close. Not a Window scene: hosted directly inside a FloatingPanel
/// (see below) so it can appear as a borderless popup near the click
/// instead of a normal titled window.
private struct MessageDetailContent: View {
    let message: SMSMessage
    @ObservedObject var model: AppModel
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(message.sender)
                .font(.headline)
            Text(message.receivedDate.formatted(date: .abbreviated, time: .shortened))
                .font(.caption)
                .foregroundStyle(.secondary)

            Divider()

            ScrollView {
                Text(message.body)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 180)

            HStack {
                Spacer()
                Button("Copy") { model.copy(message) }
                Button("Close", action: onClose)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(width: 340)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color(nsColor: .windowBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(Color(nsColor: .separatorColor), lineWidth: 1)
        )
    }
}

/// A borderless, non-activating panel — no title bar, doesn't appear in
/// Mission Control or the Window menu, but otherwise behaves like a normal
/// window: ordinary z-ordering (other windows can come in front of it),
/// stays on the Space it was opened on, doesn't sit above other apps.
private final class FloatingPanel: NSPanel {
    init(contentRect: NSRect) {
        super.init(contentRect: contentRect, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        level = .normal
        hasShadow = true
        isOpaque = false
        backgroundColor = .clear
        hidesOnDeactivate = false
        isReleasedWhenClosed = false
        isMovableByWindowBackground = true // borderless panels don't drag by background otherwise
    }

    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

/// Owns the single message-detail popup. `MenuBarExtra` doesn't expose its
/// underlying NSStatusItem, so this can't be a true NSPopover anchored to
/// it — instead it's a FloatingPanel positioned at the mouse location at
/// the moment a menu row was clicked, which in practice is right where the
/// dropdown menu (and thus the icon) is.
///
/// Known limitation: clicking the menu bar icon again while this is open
/// doesn't auto-dismiss it (only clicks in *other* apps do, via the global
/// monitor below) — a real NSStatusItem-anchored popover wouldn't have
/// this gap, but building one means replacing MenuBarExtra with a
/// hand-managed NSStatusItem + NSMenu, a much larger change.
@MainActor
final class MessageDetailPanelController {
    static let shared = MessageDetailPanelController()

    private var panel: FloatingPanel?
    private var outsideClickMonitor: Any?

    private init() {}

    func show(_ message: SMSMessage, model: AppModel) {
        let size = NSSize(width: 340, height: 260)
        let content = MessageDetailContent(message: message, model: model, onClose: { [weak self] in self?.close() })
        let hostingView = NSHostingView(rootView: content)
        hostingView.frame = NSRect(origin: .zero, size: size)

        let panel = self.panel ?? FloatingPanel(contentRect: NSRect(origin: .zero, size: size))
        panel.contentView = hostingView
        panel.setContentSize(size)

        let mouse = NSEvent.mouseLocation
        panel.setFrameOrigin(NSPoint(x: mouse.x - size.width / 2, y: mouse.y - size.height - 8))
        panel.orderFrontRegardless()
        self.panel = panel

        installOutsideClickMonitor()
    }

    func close() {
        panel?.orderOut(nil)
        removeOutsideClickMonitor()
    }

    private func installOutsideClickMonitor() {
        removeOutsideClickMonitor()
        outsideClickMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            self?.close()
        }
    }

    private func removeOutsideClickMonitor() {
        if let monitor = outsideClickMonitor {
            NSEvent.removeMonitor(monitor)
            outsideClickMonitor = nil
        }
    }
}
