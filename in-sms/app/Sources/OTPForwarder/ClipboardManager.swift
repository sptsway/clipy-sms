import AppKit

/// Owns every clipboard write so the auto-clear behavior lives in one place
/// (ARCHITECTURE.md §5): mark copied items transient/concealed so clipboard
/// managers skip them, then clear after a delay — but only if nothing else
/// was copied in between, checked via NSPasteboard.changeCount.
final class ClipboardManager {
    static let shared = ClipboardManager()
    private init() {}

    private var pendingClear: DispatchWorkItem?

    /// Copies `text`, marking it transient/concealed, and schedules a clear
    /// after `clearAfterSeconds` (0 disables auto-clear).
    func copy(_ text: String, clearAfterSeconds: Int) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()

        let item = NSPasteboardItem()
        item.setString(text, forType: .string)
        // https://nspasteboard.org — conventions clipboard managers check to
        // skip an item entirely (transient) or hide its content (concealed).
        item.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.TransientType"))
        item.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        pasteboard.writeObjects([item])

        pendingClear?.cancel()
        guard clearAfterSeconds > 0 else { return }

        let expectedChangeCount = pasteboard.changeCount
        let workItem = DispatchWorkItem {
            let pb = NSPasteboard.general
            guard pb.changeCount == expectedChangeCount else { return } // something else was copied since
            pb.clearContents()
        }
        pendingClear = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(clearAfterSeconds), execute: workItem)
    }
}
