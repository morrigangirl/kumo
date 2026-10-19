import AppKit
import CryptoKit
import Darwin
import Foundation

struct ExtensionFile {
    let relative: String
    let bytes: Int
    let sha256: Data
}
struct ExtensionSnapshot {
    let files: [ExtensionFile]
    let directories: Set<String>
    let digest: String
}
private let maximumExtensionBytes = 64 * 1024 * 1024
private func extensionFailure(_ message: String) -> Error {
    NSError(domain: "Kumo", code: 4, userInfo: [NSLocalizedDescriptionKey: message])
}
private func extensionStat(_ url: URL) throws -> stat {
    var value = stat()
    guard lstat(url.path, &value) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
    return value
}
private func extensionBytes(_ url: URL) throws -> Data {
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw extensionFailure("An extension file cannot be opened safely.") }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    defer { try? handle.close() }
    var state = stat()
    guard fstat(descriptor, &state) == 0, state.st_mode & S_IFMT == S_IFREG, state.st_nlink == 1,
          state.st_size >= 0, state.st_size <= maximumExtensionBytes else { throw extensionFailure("Unsafe or oversized extension file.") }
    let bytes = try handle.read(upToCount: maximumExtensionBytes + 1) ?? Data()
    guard bytes.count == state.st_size else { throw extensionFailure("Extension content changed while being read.") }
    return bytes
}

// Every sealed source file contributes its relative path, size and content
// digest. Chromium's writable DNR indexes never enter the signed source bundle.
func extensionSnapshot(_ source: URL) throws -> ExtensionSnapshot {
    let fm = FileManager.default, root = source
    let rootState = try extensionStat(root)
    guard rootState.st_mode & S_IFMT == S_IFDIR else { throw extensionFailure("The bundled extension must be a real directory.") }
    var failed = false
    guard let iterator = fm.enumerator(at: root, includingPropertiesForKeys: nil, options: [], errorHandler: { _, _ in failed = true; return false }) else {
        throw extensionFailure("The bundled extension cannot be read.")
    }
    var files = [ExtensionFile](), directories = Set<String>(), total = 0
    for case let url as URL in iterator {
        let relative = String(url.path.dropFirst(root.path.count + 1)), state = try extensionStat(url)
        guard !relative.isEmpty, !relative.split(separator: "/").contains("..") else { throw extensionFailure("Invalid extension path.") }
        if state.st_mode & S_IFMT == S_IFDIR { directories.insert(relative); continue }
        guard state.st_mode & S_IFMT == S_IFREG, files.count < 4096 else { throw extensionFailure("Extension symlinks and special files are not supported.") }
        let bytes = try extensionBytes(url); total += bytes.count
        guard total <= maximumExtensionBytes else { throw extensionFailure("The extension exceeds its runtime size limit.") }
        files.append(ExtensionFile(relative: relative, bytes: bytes.count, sha256: Data(SHA256.hash(data: bytes))))
    }
    guard !failed, files.contains(where: { $0.relative == "manifest.json" }) else { throw extensionFailure("The bundled extension is incomplete.") }
    files.sort { $0.relative < $1.relative }
    var hash = SHA256()
    for file in files {
        let name = Data(file.relative.utf8)
        var pathSize = UInt64(name.count).littleEndian, fileSize = UInt64(file.bytes).littleEndian
        withUnsafeBytes(of: &pathSize) { hash.update(data: Data($0)) }
        hash.update(data: name)
        withUnsafeBytes(of: &fileSize) { hash.update(data: Data($0)) }
        hash.update(data: file.sha256)
    }
    return ExtensionSnapshot(files: files, directories: directories, digest: hash.finalize().map { String(format: "%02x", $0) }.joined())
}

// Only browser-owned private directories below otherwise safe ancestors are
// created. Reject symlink parents before mkdir can follow them.
func ensureOwnedRuntimeDirectory(_ directory: URL) throws {
    var current = directory
    while current.path != "/" {
        var state = stat()
        if lstat(current.path, &state) == 0 {
            let stickySystemTemporary = state.st_uid == 0 && state.st_mode & S_ISVTX != 0
            guard state.st_mode & S_IFMT == S_IFDIR, state.st_uid == getuid() || state.st_uid == 0,
                  state.st_mode & 0o022 == 0 || stickySystemTemporary else { throw extensionFailure("Unsafe parent directory for Kumo's extension runtime.") }
        } else if errno != ENOENT { throw extensionFailure("Kumo's extension runtime directory is unavailable.") }
        current.deleteLastPathComponent()
    }
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let state = try extensionStat(directory)
    guard state.st_mode & S_IFMT == S_IFDIR, state.st_uid == getuid() else { throw extensionFailure("Kumo's extension runtime must be user owned.") }
    guard chmod(directory.path, 0o700) == 0 else { throw extensionFailure("Kumo's extension runtime cannot be made private.") }
}

func extensionRuntimeURL(profile: URL, snapshot: ExtensionSnapshot) -> URL {
    profile.appendingPathComponent("ExtensionRuntime", isDirectory: true).appendingPathComponent(snapshot.digest, isDirectory: true)
}

func verifyExtensionRuntime(_ directory: URL, snapshot: ExtensionSnapshot) throws {
    let root = directory, rootState = try extensionStat(root)
    guard rootState.st_mode & S_IFMT == S_IFDIR, rootState.st_uid == getuid(), rootState.st_mode & 0o077 == 0 else { throw extensionFailure("Unsafe existing extension runtime.") }
    let expected = Dictionary(uniqueKeysWithValues: snapshot.files.map { ($0.relative, $0) })
    var found = Set<String>(), failed = false, total = 0, count = 0
    guard let iterator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil, options: [], errorHandler: { _, _ in failed = true; return false }) else { throw extensionFailure("The extension runtime cannot be read.") }
    for case let url as URL in iterator {
        let relative = String(url.path.dropFirst(root.path.count + 1)), state = try extensionStat(url)
        guard state.st_uid == getuid() else { throw extensionFailure("Extension runtime files must stay user owned.") }
        if state.st_mode & S_IFMT == S_IFDIR {
            if snapshot.directories.contains(relative) {
                guard state.st_mode & 0o077 == 0 else { throw extensionFailure("Extension code directories must stay private.") }
            } else {
                guard (relative == "_metadata" || relative == "_metadata/generated_indexed_rulesets"), state.st_mode & 0o022 == 0 else { throw extensionFailure("Unexpected or writable extension cache directory.") }
            }
            continue
        }
        guard state.st_mode & S_IFMT == S_IFREG, state.st_nlink == 1, state.st_size >= 0,
              state.st_size <= maximumExtensionBytes else { throw extensionFailure("Unsafe extension runtime file.") }
        count += 1; total += Int(state.st_size)
        guard count <= 5120, total <= 2 * maximumExtensionBytes else { throw extensionFailure("Extension runtime exceeds its size limit.") }
        if let file = expected[relative] {
            guard state.st_mode & 0o077 == 0 else { throw extensionFailure("Extension code files must stay private.") }
            let bytes = try extensionBytes(url)
            guard bytes.count == file.bytes, Data(SHA256.hash(data: bytes)) == file.sha256 else { throw extensionFailure("Extension runtime content was modified. Remove its versioned directory after quitting Kumo, then relaunch.") }
            found.insert(relative)
        } else {
            guard relative.range(of: "^_metadata/generated_indexed_rulesets/_ruleset[0-9]+$", options: .regularExpression) != nil,
                  state.st_mode & 0o022 == 0 else { throw extensionFailure("Unexpected or writable extension runtime cache file.") }
        }
    }
    guard !failed, found.count == expected.count else { throw extensionFailure("The extension runtime is incomplete.") }
}

func prepareExtensionRuntime(source: URL, profile: URL, snapshot supplied: ExtensionSnapshot? = nil) throws -> URL {
    let fm = FileManager.default, snapshot = try supplied ?? extensionSnapshot(source)
    try ensureOwnedRuntimeDirectory(profile)
    let parent = profile.appendingPathComponent("ExtensionRuntime", isDirectory: true)
    try ensureOwnedRuntimeDirectory(parent)
    let destination = extensionRuntimeURL(profile: profile, snapshot: snapshot)
    var existing = stat()
    if lstat(destination.path, &existing) == 0 { try verifyExtensionRuntime(destination, snapshot: snapshot); return destination }
    guard errno == ENOENT else { throw extensionFailure("The extension runtime cannot be inspected.") }
    let staging = parent.appendingPathComponent(".stage-" + UUID().uuidString, isDirectory: true)
    try fm.createDirectory(at: staging, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? fm.removeItem(at: staging) }
    for directory in snapshot.directories.sorted(by: { $0.count < $1.count }) {
        try fm.createDirectory(at: staging.appendingPathComponent(directory, isDirectory: true), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    for file in snapshot.files {
        let bytes = try extensionBytes(source.appendingPathComponent(file.relative))
        guard bytes.count == file.bytes, Data(SHA256.hash(data: bytes)) == file.sha256 else { throw extensionFailure("Bundled extension changed during preparation.") }
        let output = staging.appendingPathComponent(file.relative)
        let descriptor = open(output.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw extensionFailure("Extension runtime file could not be created.") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do { try handle.write(contentsOf: bytes); try handle.synchronize(); try handle.close() }
        catch { try? handle.close(); throw error }
    }
    try verifyExtensionRuntime(staging, snapshot: snapshot)
    if renamex_np(staging.path, destination.path, UInt32(RENAME_EXCL)) != 0 {
        guard errno == EEXIST else { throw extensionFailure("Extension runtime could not be published atomically.") }
        try verifyExtensionRuntime(destination, snapshot: snapshot)
    }
    return destination
}

// A shared lock survives execv and protects every profile using this installed
// bundle. The independent updater holds EX until replacement finishes.
func acquireBrowserUpdateLock(contents: URL) throws -> Int32 {
    let file = contents.appendingPathComponent("Resources/kumo-update-lock")
    let descriptor = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw extensionFailure("Kumo's update coordination file is missing or unsafe.") }
    do {
        var state = stat()
        let expected = Data("Kumo update coordination v1\n".utf8)
        guard fstat(descriptor, &state) == 0, state.st_mode & S_IFMT == S_IFREG,
              state.st_nlink == 1, state.st_mode & 0o022 == 0, state.st_size == expected.count else {
            throw extensionFailure("Kumo's update coordination file is unsafe.")
        }
        var bytes = [UInt8](repeating: 0, count: expected.count + 1)
        guard Darwin.read(descriptor, &bytes, bytes.count) == expected.count,
              Data(bytes.prefix(expected.count)) == expected else { throw extensionFailure("Invalid update coordination file.") }
        guard flock(descriptor, LOCK_SH | LOCK_NB) == 0 else {
            throw extensionFailure("Kumo is installing an update. Open it again when installation finishes.")
        }
        let flags = fcntl(descriptor, F_GETFD)
        guard flags >= 0, fcntl(descriptor, F_SETFD, flags & ~FD_CLOEXEC) == 0 else {
            throw extensionFailure("Kumo could not retain its update coordination lock.")
        }
        return descriptor
    } catch { close(descriptor); throw error }
}

func launchUpdater(contents: URL, manual: Bool) throws {
    let helper = contents.appendingPathComponent("Helpers/KumoUpdater.app").resolvingSymlinksInPath()
    guard FileManager.default.isExecutableFile(atPath: helper.appendingPathComponent("Contents/MacOS/KumoUpdater").path) else {
        throw extensionFailure("Kumo's native updater is missing. Rebuild the app.")
    }
    if !manual {
        // Development builds do not create an updater process or contact GitHub.
        let file = contents.appendingPathComponent("Resources/kumo-update-config.json")
        guard let config = try? JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any],
              config["enabled"] as? Bool == true else { return }
        if NSRunningApplication.runningApplications(withBundleIdentifier: "app.kumo.browser.updater").contains(where: {
            $0.bundleURL?.resolvingSymlinksInPath() == helper
        }) { return }
    }
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    task.arguments = (manual ? [] : ["-g"]) + ["-a", helper.path, "--args", manual ? "--check" : "--background"]
    task.standardOutput = FileHandle.nullDevice
    task.standardError = FileHandle.nullDevice
    try task.run()
    // This waits only for Launch Services, never for the independent updater.
    task.waitUntilExit()
    guard task.terminationStatus == 0 else { throw extensionFailure("macOS could not open Kumo's updater.") }
}

// Fixed setup actions run relative to this app. They never become Chromium flags.
func runSetup(_ arguments: [String], contents: URL) throws -> Bool {
    let actions: [String: (String, [String], String)] = [
        "--kumo-connect-codex-desktop": ("Resources/setup-agent", ["--provider", "codex-desktop"], "Codex Desktop is connected to Kumo."),
        "--kumo-connect-claude-desktop": ("Resources/setup-agent", ["--provider", "claude-desktop"], "Claude Desktop is connected to Kumo."),
        "--kumo-scanner-setup": ("MacOS/KumoMalwareSetup", [], "Download protection setup finished."),
        "--kumo-scanner-update": ("MacOS/KumoMalwareSetup", ["--update"], "Malware definitions are up to date.")
    ]
    let selected = arguments.filter { actions[$0] != nil }
    guard !selected.isEmpty else { return false }
    guard arguments.count == 1, let action = actions[selected[0]] else {
        throw NSError(domain: "Kumo", code: 2, userInfo: [NSLocalizedDescriptionKey: "Run one Kumo setup action at a time."])
    }
    let task = Process()
    task.executableURL = contents.appendingPathComponent(action.0)
    task.arguments = action.1
    let output = Pipe()
    task.standardOutput = output
    task.standardError = output
    try task.run()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    task.waitUntilExit()
    FileHandle.standardOutput.write(data)
    guard task.terminationReason == .exit, task.terminationStatus == 0 else {
        let detail = String(data: data.suffix(8192), encoding: .utf8) ?? "The setup helper could not complete."
        throw NSError(domain: "Kumo", code: 3, userInfo: [NSLocalizedDescriptionKey: detail])
    }
    if isatty(STDOUT_FILENO) == 0 && ProcessInfo.processInfo.environment["KUMO_SETUP_NONINTERACTIVE"] != "1" {
        let alert = NSAlert()
        alert.messageText = action.2
        let lastLine = String(decoding: data, as: UTF8.self).split(separator: "\n").last.map(String.init) ?? ""
        let result = (try? JSONSerialization.jsonObject(with: Data(lastLine.utf8))) as? [String: Any]
        if result?["status"] as? String == "awaiting-administrator-installation" {
            alert.messageText = "Finish installing ClamAV."
            alert.informativeText = "Complete Apple's Installer, then run Kumo's scanner setup command again to initialize definitions."
        } else {
            alert.informativeText = selected[0].contains("desktop")
                ? "Reload the client's MCP connections or start a new chat to load Kumo's browser tools. Choose which tabs to share in Kumo's agent settings."
                : "Check Privacy settings in Kumo for the current protection status."
        }
        alert.runModal()
    }
    return true
}

// Native app bootstrap only. The browser process, windows, tabs and rendering are Chromium.
// execv retains Launch Services' process identity and forwards normal macOS Apple events.
func run() throws {
    let bundle = Bundle.main.bundleURL
    let contents = bundle.appendingPathComponent("Contents")
    let resources = contents.appendingPathComponent("Resources")
    if CommandLine.arguments.contains("--kumo-check-for-updates") {
        guard CommandLine.arguments.count == 2 else { throw extensionFailure("Run one Kumo setup action at a time.") }
        try launchUpdater(contents: contents, manual: true)
        return
    }
    if try runSetup(Array(CommandLine.arguments.dropFirst()), contents: contents) { return }
    let engine = contents.appendingPathComponent("MacOS/Chromium")
    let fm = FileManager.default
    let support = try fm.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: false)
    let profile = support.appendingPathComponent("Kumo", isDirectory: true)
    let bundledExtension = resources.appendingPathComponent("KumoExtension", isDirectory: true)
    let snapshot = try extensionSnapshot(bundledExtension)
    let extensionURL = extensionRuntimeURL(profile: profile, snapshot: snapshot)
    let flags = [
        "--user-data-dir=\(profile.path)",
        "--no-first-run", "--no-default-browser-check", "--disable-sync",
        "--extension-mime-request-handling=always-prompt-for-install",
        "--load-extension=\(extensionURL.path)"
    ]
    if CommandLine.arguments.contains("--kumo-print-config") {
        let data = try JSONSerialization.data(withJSONObject: ["engine": engine.path, "profile": profile.path, "extension": extensionURL.path, "bundledExtension": bundledExtension.path, "flags": flags], options: [.prettyPrinted, .sortedKeys])
        FileHandle.standardOutput.write(data)
        return
    }
    guard fm.isExecutableFile(atPath: engine.path) else { throw NSError(domain: "Kumo", code: 1, userInfo: [NSLocalizedDescriptionKey: "Chromium is missing from this application. Rebuild Kumo.app."]) }
    // Spawn before acquiring SH so the companion never inherits the browser's
    // lease; it must be able to acquire EX after the browser quits.
    try launchUpdater(contents: contents, manual: false)
    let updateLock = try acquireBrowserUpdateLock(contents: contents)
    defer { close(updateLock) } // execv keeps it open for Chromium's lifetime.
    _ = try prepareExtensionRuntime(source: bundledExtension, profile: profile, snapshot: snapshot)
    // Populate only a fresh Kumo profile. Never alter a running browser's preferences.
    let defaults = profile.appendingPathComponent("Default", isDirectory: true)
    let preferences = defaults.appendingPathComponent("Preferences")
    if !fm.fileExists(atPath: preferences.path) {
        try ensureOwnedRuntimeDirectory(defaults)
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
    try ensureOwnedRuntimeDirectory(profileHosts)
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
    let malwareTemplate = resources.appendingPathComponent("malware-host-template.json")
    if fm.fileExists(atPath: malwareTemplate.path),
       var host = try JSONSerialization.jsonObject(with: Data(contentsOf: malwareTemplate)) as? [String: Any] {
        host["path"] = contents.appendingPathComponent("Helpers/KumoMalware.app/Contents/MacOS/KumoMalwareHost").path
        try JSONSerialization.data(withJSONObject: host, options: [.prettyPrinted]).write(to: profileHosts.appendingPathComponent("com.kumo.malware.json"), options: .atomic)
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
    else if ProcessInfo.processInfo.environment["KUMO_SETUP_NONINTERACTIVE"] == "1" { fputs("Kumo: \(error.localizedDescription)\n", stderr) }
    else { let alert = NSAlert(); alert.messageText = "Kumo could not start"; alert.informativeText = error.localizedDescription; alert.runModal() }
    exit(1)
}
