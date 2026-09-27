import Foundation
import UserNotifications

/// Wraps UNUserNotificationCenter (ARCHITECTURE.md §5): shows the full SMS
/// body + sender for a new message, and copies the body when tapped.
///
/// Hard requirement, confirmed by testing (not just a doc caveat):
/// UNUserNotificationCenter.current() *crashes* the process
/// ("bundleProxyForCurrentProcess is nil") unless it's running from a real,
/// LaunchServices-registered .app bundle. `swift run`/`swift build`'s bare
/// executable is not one, even with an Info.plist linked into __info_plist —
/// that's enough for Bundle.main to report a CFBundleIdentifier, but not
/// enough for LaunchServices. So every entry point here is gated on
/// `isSupported` and this class never touches UNUserNotificationCenter at
/// all until Milestone 5's real .app packaging makes it safe to.
final class NotificationManager: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationManager()

    private let isSupported = Bundle.main.bundlePath.hasSuffix(".app")

    /// Set by AppModel so a notification tap can copy the body using the
    /// user's current clipboard-clear-delay setting.
    var onTapped: ((_ messageId: String, _ body: String) -> Void)?

    private override init() {
        super.init()
        guard isSupported else { return }
        UNUserNotificationCenter.current().delegate = self
    }

    func requestAuthorizationIfNeeded() {
        guard isSupported else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    func notify(sender: String, body: String, messageId: String) {
        guard isSupported else { return }
        let content = UNMutableNotificationContent()
        content.title = sender
        content.body = body
        content.userInfo = ["messageId": messageId, "body": body]
        let request = UNNotificationRequest(identifier: messageId, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let info = response.notification.request.content.userInfo
        let id = info["messageId"] as? String ?? ""
        let body = info["body"] as? String ?? ""
        onTapped?(id, body)
        completionHandler()
    }

    // Show the banner even while the app is frontmost (menu bar apps have no
    // "background" state distinction the way a normal app does).
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}
