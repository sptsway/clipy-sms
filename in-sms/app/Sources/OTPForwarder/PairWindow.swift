import CoreImage.CIFilterBuiltins
import SwiftUI

/// Renders a URI as a QR code via CoreImage's CIQRCodeGenerator
/// (ARCHITECTURE.md §5), scaled up with nearest-neighbor so modules stay
/// crisp instead of blurry.
enum QRCodeRenderer {
    static func image(for string: String, scale: CGFloat = 8) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"

        guard let output = filter.outputImage else { return nil }
        let transformed = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))

        let context = CIContext()
        guard let cgImage = context.createCGImage(transformed, from: transformed.extent) else { return nil }
        return NSImage(cgImage: cgImage, size: NSSize(width: transformed.extent.width, height: transformed.extent.height))
    }
}

/// The pairing window (prompt.md): QR code, countdown, live status, closes
/// automatically on success (handled by AppModel setting
/// isPairWindowPresented = false when a pairing.status event reports .paired).
struct PairWindow: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var uri: String?
    @State private var expiresAt: Date?
    @State private var now = Date()
    @State private var isStarting = true

    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 16) {
            Text("Pair New Phone").font(.headline)

            if isStarting {
                ProgressView()
            } else if let uri, let image = QRCodeRenderer.image(for: uri) {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 220, height: 220)
            } else {
                Text("Could not generate a pairing code.")
                    .foregroundStyle(.secondary)
            }

            statusView

            if let expiresAt {
                let remaining = max(0, Int(expiresAt.timeIntervalSince(now)))
                Text(remaining > 0 ? "Expires in \(remaining)s" : "Expired")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }

            Button("Cancel") {
                Task { await model.cancelPairing() }
                model.isPairWindowPresented = false
            }
        }
        .padding(24)
        .frame(width: 300)
        .onReceive(ticker) { now = $0 }
        .task { await startPairing() }
        .onChange(of: model.isPairWindowPresented) { presented in
            // Closes automatically on pairing success (AppModel sets this to
            // false when a pairing.status event reports .paired), and when
            // Cancel above flips it off.
            if !presented { dismiss() }
        }
    }

    @ViewBuilder
    private var statusView: some View {
        switch model.pairingStatus.state {
        case .idle:
            Label("Waiting to start…", systemImage: "hourglass")
        case .waiting:
            Label("Waiting for phone (\(model.pairingStatus.attemptsLeft) attempts left)…", systemImage: "wifi")
        case .paired:
            Label("Paired!", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
        case .failed:
            Label("Pairing failed", systemImage: "xmark.circle.fill").foregroundStyle(.red)
        }
    }

    private func startPairing() async {
        isStarting = true
        if let result = await model.startPairing() {
            uri = result.uri
            expiresAt = Date(timeIntervalSince1970: TimeInterval(result.expiresAt))
        }
        isStarting = false
    }
}
