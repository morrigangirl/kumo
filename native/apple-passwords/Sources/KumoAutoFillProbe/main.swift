import AppKit
import Foundation

/// A native semantic-field experiment, not a password-vault reader or webpage fill implementation.
@MainActor
private final class AutoFillProbeDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private let username = NSTextField()
    private let password = NSSecureTextField()
    private var window: NSWindow?

    override init() {
        super.init()
        username.contentType = .username
        username.placeholderString = "Empty test username field"
        password.contentType = .password
        password.placeholderString = "Empty test password field"
    }

    func describeFields() throws {
        let description: [String: Any] = [
            "usernameControl": "NSTextField",
            "usernameContentTypeMatches": username.contentType == .username,
            "passwordControl": "NSSecureTextField",
            "passwordContentTypeMatches": password.contentType == .password,
            "containsTestValues": false,
            "credentialReadOrExportImplemented": false,
            "automaticWebsiteMatchingImplemented": false,
            "manualSystemPickerRuntimeVerified": false,
        ]
        let data = try JSONSerialization.data(withJSONObject: description, options: [.prettyPrinted, .sortedKeys])
        print(String(decoding: data, as: UTF8.self))
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let probeWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 610, height: 355),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        probeWindow.title = "Kumo Native AutoFill Probe"
        probeWindow.identifier = NSUserInterfaceItemIdentifier("kumo-native-autofill-probe")
        probeWindow.isRestorable = false
        probeWindow.delegate = self
        let view = NSView(frame: probeWindow.contentView!.bounds)
        probeWindow.contentView = view

        let heading = NSTextField(labelWithString: "Native macOS Password AutoFill")
        heading.font = .boldSystemFont(ofSize: 20)
        heading.frame = NSRect(x: 26, y: 300, width: 560, height: 28)
        view.addSubview(heading)

        let explanation = NSTextField(wrappingLabelWithString:
            "These empty native AppKit fields test the system AutoFill menu. Right-click a field to inspect available actions. Do not unlock Passwords or select a real credential during validation. No website is loaded.")
        explanation.frame = NSRect(x: 26, y: 227, width: 555, height: 62)
        view.addSubview(explanation)

        let usernameLabel = NSTextField(labelWithString: "Test username")
        usernameLabel.frame = NSRect(x: 26, y: 183, width: 135, height: 22)
        view.addSubview(usernameLabel)
        username.frame = NSRect(x: 165, y: 180, width: 415, height: 28)
        view.addSubview(username)

        let passwordLabel = NSTextField(labelWithString: "Test password")
        passwordLabel.frame = NSRect(x: 26, y: 138, width: 135, height: 22)
        view.addSubview(passwordLabel)
        password.frame = NSRect(x: 165, y: 135, width: 415, height: 28)
        view.addSubview(password)

        let boundary = NSTextField(wrappingLabelWithString:
            "This probe has no credential logging, persistence, browser connection, or fill action. Closing clears both fields. A manual picker does not prove automatic website matching.")
        boundary.textColor = .secondaryLabelColor
        boundary.font = .systemFont(ofSize: 12)
        boundary.frame = NSRect(x: 26, y: 69, width: 555, height: 46)
        view.addSubview(boundary)

        let clear = NSButton(title: "Clear fields", target: self, action: #selector(clearFields))
        clear.frame = NSRect(x: 330, y: 19, width: 125, height: 32)
        view.addSubview(clear)
        let close = NSButton(title: "Close", target: self, action: #selector(closeProbe))
        close.frame = NSRect(x: 463, y: 19, width: 125, height: 32)
        close.keyEquivalent = "\r"
        view.addSubview(close)

        probeWindow.initialFirstResponder = username
        self.window = probeWindow
        probeWindow.center()
        probeWindow.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        clearFields()
        return .terminateNow
    }
    func windowWillClose(_ notification: Notification) { clearFields() }

    @objc private func clearFields() {
        // Ordinary AppKit strings are released, not promised to be securely zeroed in memory.
        username.stringValue = ""
        password.stringValue = ""
    }
    @objc private func closeProbe() {
        clearFields()
        NSApplication.shared.terminate(nil)
    }
}

@main
private struct KumoAutoFillProbe {
    @MainActor
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        let delegate = AutoFillProbeDelegate()
        if arguments == ["--describe-fields"] {
            do { try delegate.describeFields() }
            catch {
                FileHandle.standardError.write(Data("Could not describe native fields.\n".utf8))
                exit(1)
            }
            return
        }
        guard arguments.isEmpty else {
            FileHandle.standardError.write(Data("Usage: kumo-autofill-probe [--describe-fields]\n".utf8))
            exit(64)
        }
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }
}
