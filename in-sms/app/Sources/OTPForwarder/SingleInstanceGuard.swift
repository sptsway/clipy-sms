import Darwin
import Foundation

/// Ensures only one copy of this app runs at a time, no matter how each
/// copy was launched — LaunchAgent RunAtLoad, Finder double-click,
/// Spotlight, `open`, or dev-mode `swift run` can all race each other,
/// producing two menu bar icons. `NSWorkspace.runningApplications` doesn't
/// reliably catch this: a process launchd spawns directly never goes
/// through LaunchServices, so it doesn't reliably show up there. A plain
/// advisory file lock (`flock`) does, and — unlike a hand-rolled PID file —
/// it can't go stale: the OS releases it automatically when the holding
/// process exits, crash or not.
enum SingleInstanceGuard {
    // Keeping the fd alive for the process's lifetime is what keeps the
    // lock held; letting it go out of scope/closing it would release it.
    private static var lockFileDescriptor: Int32 = -1

    /// Call once, as the very first thing in app startup, before creating
    /// any windows or connecting to the daemon. If another instance already
    /// holds the lock, this exits the process immediately and never
    /// returns — the duplicate launch becomes a silent no-op instead of a
    /// second menu bar icon.
    static func acquireOrExit() {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/OTPForwarder")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let lockPath = dir.appendingPathComponent("app.lock").path

        let fd = open(lockPath, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { return } // best-effort: don't block startup if we somehow can't even open the lock file

        if flock(fd, LOCK_EX | LOCK_NB) != 0 {
            close(fd)
            exit(0)
        }
        lockFileDescriptor = fd
    }
}
