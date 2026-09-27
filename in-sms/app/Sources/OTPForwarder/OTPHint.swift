import Foundation

// Best-effort OTP guess for the menu row's "OTP:" prefix only — display
// sugar, not data. The daemon stores and forwards the full SMS body
// untouched (see ARCHITECTURE.md §3.4's revision away from server-side
// extraction); this just re-derives a *hint* client-side so the row reads
// "OTP:482913  Your OTP is 482913...  — 38221 · 14:32" instead of making
// the reader hunt for the number in the preview text.
//
// Two passes: prefer a number near an OTP-ish keyword (higher confidence),
// but fall back to the first standalone 4-8 digit run in the body if no
// keyword match is found — plenty of real OTP messages never say
// "otp"/"code"/"verification" at all ("Use 482913 to login", "482913 is
// your PIN"), and showing a plausible number beats showing "nil" next to
// an SMS that obviously has one.
//
// Built from Regex(String) rather than a /.../ literal: the literal syntax
// gets confused by two adjacent patterns using the (?i:...) inline-modifier
// group, so the plain string form (identical pattern text, just quoted) is
// used instead — same regex, more predictable parsing.
private let otpAfterKeyword = try! Regex(#"(?i:otp|code|verif\w*|pin|passcode|password|auth\w*)\b[^0-9]{0,30}(\d{4,8})"#)
private let otpBeforeKeyword = try! Regex(#"(\d{4,8})[^0-9]{0,30}\b(?i:otp|code|verif\w*|pin|passcode|password|auth\w*)"#)
private let anyDigitRun = try! Regex(#"\d{4,8}"#)

extension SMSMessage {
    /// nil only if no 4-8 digit number exists anywhere in the body.
    var otpHint: String? {
        if let match = try? otpAfterKeyword.firstMatch(in: body), let range = match.output[1].range {
            return String(body[range])
        }
        if let match = try? otpBeforeKeyword.firstMatch(in: body), let range = match.output[1].range {
            return String(body[range])
        }
        if let match = try? anyDigitRun.firstMatch(in: body) {
            return String(body[match.range])
        }
        return nil
    }
}
