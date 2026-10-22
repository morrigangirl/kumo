import AppKit
import Darwin
import Foundation

private func bootstrapFailure(_ message: String) -> Error {
    NSError(domain: "Kumo", code: 4, userInfo: [NSLocalizedDescriptionKey: message])
}
private func bootstrapStat(_ url: URL) throws -> stat {
    var value = stat()
    guard lstat(url.path, &value) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
    return value
}

func ensureOwnedRuntimeDirectory(_ directory: URL) throws {
    var current = directory
    while current.path != "/" {
        var state = stat()
        if lstat(current.path, &state) == 0 {
            let stickySystemTemporary = state.st_uid == 0 && state.st_mode & S_ISVTX != 0
            guard state.st_mode & S_IFMT == S_IFDIR, state.st_uid == getuid() || state.st_uid == 0,
                  state.st_mode & 0o022 == 0 || stickySystemTemporary else { throw bootstrapFailure("Unsafe parent directory for Kumo's profile.") }
        } else if errno != ENOENT { throw bootstrapFailure("Kumo's profile directory is unavailable.") }
        current.deleteLastPathComponent()
    }
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let state = try bootstrapStat(directory)
    guard state.st_mode & S_IFMT == S_IFDIR, state.st_uid == getuid() else { throw bootstrapFailure("Kumo's profile must be user owned.") }
    guard chmod(directory.path, 0o700) == 0 else { throw bootstrapFailure("Kumo's profile cannot be made private.") }
}


func acquireBrowserUpdateLock(contents: URL) throws -> Int32 {
    let file = contents.appendingPathComponent("Resources/kumo-update-lock")
    let descriptor = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw bootstrapFailure("Kumo's update coordination file is missing or unsafe.") }
    do {
        var state = stat()
        let expected = Data("Kumo update coordination v1\n".utf8)
        guard fstat(descriptor, &state) == 0, state.st_mode & S_IFMT == S_IFREG,
              state.st_nlink == 1, state.st_mode & 0o022 == 0, state.st_size == expected.count else {
            throw bootstrapFailure("Kumo's update coordination file is unsafe.")
        }
        var bytes = [UInt8](repeating: 0, count: expected.count + 1)
        guard Darwin.read(descriptor, &bytes, bytes.count) == expected.count,
              Data(bytes.prefix(expected.count)) == expected else { throw bootstrapFailure("Invalid update coordination file.") }
        guard flock(descriptor, LOCK_SH | LOCK_NB) == 0 else {
            throw bootstrapFailure("Kumo is installing an update. Open it again when installation finishes.")
        }
        let flags = fcntl(descriptor, F_GETFD)
        guard flags >= 0, fcntl(descriptor, F_SETFD, flags & ~FD_CLOEXEC) == 0 else {
            throw bootstrapFailure("Kumo could not retain its update coordination lock.")
        }
        return descriptor
    } catch { close(descriptor); throw error }
}

func launchUpdater(contents: URL, manual: Bool) throws {
    let helper = contents.appendingPathComponent("Helpers/KumoUpdater.app").resolvingSymlinksInPath()
    guard FileManager.default.isExecutableFile(atPath: helper.appendingPathComponent("Contents/MacOS/KumoUpdater").path) else {
        throw bootstrapFailure("Kumo's native updater is missing. Rebuild the app.")
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
    guard task.terminationStatus == 0 else { throw bootstrapFailure("macOS could not open Kumo's updater.") }
}


// The browser features are compiled Chromium services. This bootstrap prepares
// only its profile and update lease; no product extension or host is loaded.
func retireLegacyHosts(_ directory: URL) throws {
    try ensureOwnedRuntimeDirectory(directory)
    for name in ["com.kumo.agent_bridge.json", "com.kumo.phishing.json", "com.kumo.malware.json"] {
        let file = directory.appendingPathComponent(name)
        var entry = stat()
        if lstat(file.path, &entry) == 0 {
            guard entry.st_uid == getuid(), entry.st_mode & S_IFMT == S_IFREG || entry.st_mode & S_IFMT == S_IFLNK,
                  unlink(file.path) == 0 else { throw bootstrapFailure("A retired Kumo host registration cannot be removed safely.") }
        } else if errno != ENOENT { throw bootstrapFailure("A retired Kumo host registration cannot be inspected.") }
    }
}

func browserArguments(_ arguments: [String], fixedFlags: [String]) throws -> [String] {
    let invalid = bootstrapFailure("Kumo accepts website or file addresses. Configure browser features in Settings.")
    let restarts = arguments.filter { $0 == "--restart" }.count
    let background = arguments.filter { $0 == "--no-startup-window" }.count
    if restarts > 0 || background > 0 {
        // Chromium copies the current switch map on relaunch. A foreground
        // relaunch then appends --restart again, so later restarts contain two.
        // Background relaunch removes the old no-startup-window before adding
        // one, and can retain one restart from an earlier foreground launch.
        // This normalizes exact fixed values; it does not authenticate a caller.
        guard (background == 0 && (1...2).contains(restarts)) ||
              (background == 1 && (0...1).contains(restarts)),
              arguments.count == fixedFlags.count + restarts + background,
              fixedFlags.allSatisfy({ flag in arguments.filter { $0 == flag }.count == 1 }) else { throw invalid }
        return (background == 1 ? ["--no-startup-window"] : []) + (restarts > 0 ? ["--restart"] : [])
    }
    guard arguments.allSatisfy({ value in
        guard !value.hasPrefix("-"), let url = URL(string: value), let scheme = url.scheme?.lowercased() else { return false }
        return ["http", "https", "file"].contains(scheme)
    }) else { throw invalid }
    return arguments
}

func run() throws {
    let contents = Bundle.main.bundleURL.appendingPathComponent("Contents")
    let engine = contents.appendingPathComponent("MacOS/Chromium")
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments.contains("--kumo-check-for-updates") {
        guard arguments == ["--kumo-check-for-updates"] else { throw bootstrapFailure("Use one Kumo action at a time.") }
        try launchUpdater(contents: contents, manual: true)
        FileHandle.standardOutput.write(Data("{\"ok\":true,\"status\":\"updater-opened\",\"message\":\"Kumo’s updater is open.\"}\n".utf8))
        return
    }
    let fm = FileManager.default
    let support = try fm.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: false)
    let profile = support.appendingPathComponent("Kumo", isDirectory: true)
    let flags = ["--user-data-dir=\(profile.path)", "--no-first-run", "--no-default-browser-check", "--disable-sync",
                 "--extension-mime-request-handling=always-prompt-for-install"]
    if arguments == ["--kumo-print-config"] {
        let data = try JSONSerialization.data(withJSONObject: ["engine": engine.path, "profile": profile.path,
            "flags": flags, "nativeSettings": "chrome://settings/kumo", "productExtensionLoaded": false], options: [.prettyPrinted, .sortedKeys])
        FileHandle.standardOutput.write(data); return
    }
    guard !arguments.contains(where: { $0.hasPrefix("--kumo-") }) else { throw bootstrapFailure("Open Kumo Settings to configure browser features.") }
    let forwardedArguments = try browserArguments(arguments, fixedFlags: flags)
    guard fm.isExecutableFile(atPath: engine.path) else { throw bootstrapFailure("The Kumo browser engine is missing. Reinstall Kumo.") }
    try launchUpdater(contents: contents, manual: false)
    let lease = try acquireBrowserUpdateLock(contents: contents)
    defer { close(lease) }
    try ensureOwnedRuntimeDirectory(profile)
    let defaults = profile.appendingPathComponent("Default", isDirectory: true)
    let preferences = defaults.appendingPathComponent("Preferences")
    if !fm.fileExists(atPath: preferences.path) {
        try ensureOwnedRuntimeDirectory(defaults)
        let initial: [String: Any] = ["browser": ["check_default_browser": false], "signin": ["allowed": false],
            "search": ["suggest_enabled": false], "session": ["restore_on_startup": 1],
            "credentials_enable_service": false, "profile": ["password_manager_enabled": false]]
        try JSONSerialization.data(withJSONObject: initial).write(to: preferences, options: .atomic)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: preferences.path)
    }
    try retireLegacyHosts(profile.appendingPathComponent("NativeMessagingHosts", isDirectory: true))
    let command = [engine.path] + flags + forwardedArguments
    var pointers = command.map { strdup($0) } + [nil]
    defer { for pointer in pointers { free(pointer) } }
    pointers.withUnsafeMutableBufferPointer { argv in _ = execv(engine.path, argv.baseAddress!) }
    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
}

do { try run() }
catch {
    let message = (error as NSError).localizedDescription
    FileHandle.standardError.write(Data((message + "\n").utf8))
    if isatty(STDERR_FILENO) == 0 && ProcessInfo.processInfo.environment["KUMO_SETUP_NONINTERACTIVE"] != "1" {
        let alert = NSAlert(); alert.messageText = "Kumo needs attention"; alert.informativeText = message; alert.runModal()
    }
    exit(1)
}
