import AppKit
import Darwin
import Foundation

// Native app bootstrap only. The browser process, windows, tabs and rendering are Chromium.
// execv retains Launch Services' process identity and forwards normal macOS Apple events.
func run() throws {
    let bundle = Bundle.main.bundleURL
    let contents = bundle.appendingPathComponent("Contents")
    let resources = contents.appendingPathComponent("Resources")
    let engine = contents.appendingPathComponent("MacOS/Chromium")
    let fm = FileManager.default
    let support = try fm.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    let profile = support.appendingPathComponent("Kumo", isDirectory: true)
    let extensionURL = resources.appendingPathComponent("KumoExtension", isDirectory: true)
    let flags = [
        "--user-data-dir=\(profile.path)",
        "--no-first-run", "--no-default-browser-check", "--disable-sync",
        "--extension-mime-request-handling=always-prompt-for-install",
        "--load-extension=\(extensionURL.path)"
    ]
    if CommandLine.arguments.contains("--kumo-print-config") {
        let data = try JSONSerialization.data(withJSONObject: ["engine": engine.path, "profile": profile.path, "extension": extensionURL.path, "flags": flags], options: [.prettyPrinted, .sortedKeys])
        FileHandle.standardOutput.write(data)
        return
    }
    guard fm.isExecutableFile(atPath: engine.path) else { throw NSError(domain: "Kumo", code: 1, userInfo: [NSLocalizedDescriptionKey: "Chromium is missing from this application. Rebuild Kumo.app."]) }
    try fm.createDirectory(at: profile, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    // Populate only a fresh Kumo profile. Never alter a running browser's preferences.
    let defaults = profile.appendingPathComponent("Default", isDirectory: true)
    let preferences = defaults.appendingPathComponent("Preferences")
    if !fm.fileExists(atPath: preferences.path) {
        try fm.createDirectory(at: defaults, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let initial: [String: Any] = [
            "browser": ["check_default_browser": false],
            "signin": ["allowed": false],
            "search": ["suggest_enabled": false],
            "session": ["restore_on_startup": 1],
            "credentials_enable_service": false,
            "profile": ["password_manager_enabled": false]
        ]
        try JSONSerialization.data(withJSONObject: initial).write(to: preferences, options: .atomic)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: preferences.path)
    }
    let profileHosts = profile.appendingPathComponent("NativeMessagingHosts", isDirectory: true)
    try fm.createDirectory(at: profileHosts, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let template = resources.appendingPathComponent("native-host-template.json")
    if fm.fileExists(atPath: template.path),
       var host = try JSONSerialization.jsonObject(with: Data(contentsOf: template)) as? [String: Any] {
        host["path"] = resources.appendingPathComponent("kumo-native-host").path
        try JSONSerialization.data(withJSONObject: host, options: [.prettyPrinted]).write(to: profileHosts.appendingPathComponent("com.kumo.agent_bridge.json"), options: .atomic)
    }
    let phishingTemplate = resources.appendingPathComponent("phishing-host-template.json")
    if fm.fileExists(atPath: phishingTemplate.path),
       var host = try JSONSerialization.jsonObject(with: Data(contentsOf: phishingTemplate)) as? [String: Any] {
        host["path"] = contents.appendingPathComponent("Helpers/KumoPhishing.app/Contents/MacOS/KumoPhishingHost").path
        try JSONSerialization.data(withJSONObject: host, options: [.prettyPrinted]).write(to: profileHosts.appendingPathComponent("com.kumo.phishing.json"), options: .atomic)
    }
    // Only URLs are accepted from the external launcher. No sandbox/TLS/debugging flags.
    let urls = CommandLine.arguments.dropFirst().filter { argument in
        guard let url = URL(string: argument) else { return false }
        return ["http", "https", "file"].contains(url.scheme?.lowercased() ?? "")
    }
    let args = [engine.path] + flags + urls
    let pointers = args.map { strdup($0) } + [nil]
    defer { for pointer in pointers { free(pointer) } }
    let code = pointers.withUnsafeBufferPointer { execv(engine.path, $0.baseAddress!) }
    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: "Unable to start Chromium (\(code))."])
}
do { try run() }
catch {
    if isatty(STDERR_FILENO) != 0 { fputs("Kumo: \(error.localizedDescription)\n", stderr) }
    else { let alert = NSAlert(); alert.messageText = "Kumo could not start"; alert.informativeText = error.localizedDescription; alert.runModal() }
    exit(1)
}
