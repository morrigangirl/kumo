import Foundation
import Darwin
import KumoMalwareCore

enum RootInstaller {
    static func checkHost() throws {
        #if !arch(arm64)
        throw SetupError("This Kumo installer requires a Mac with Apple Silicon.")
        #endif
        let version = ProcessInfo.processInfo.operatingSystemVersion
        guard version.majorVersion >= 13 else { throw SetupError("Kumo requires macOS 13 or later.") }
    }

    static func requireRootSnapshot(_ bundle: URL) throws {
        let parent = bundle.deletingLastPathComponent()
        let state = try directoryState(parent)
        guard parent.deletingLastPathComponent().path == "/private/var/tmp",
              parent.lastPathComponent.hasPrefix("kumo-setup-"), state.st_uid == 0,
              state.st_mode & 0o777 == 0o700 else { throw SetupError("Kumo Setup must run from its protected administrator staging folder.") }
        guard let walk = FileManager.default.enumerator(at: bundle, includingPropertiesForKeys: nil) else { throw SetupError("The administrator snapshot cannot be read.") }
        for case let file as URL in walk {
            var entry = stat()
            guard lstat(file.path, &entry) == 0, entry.st_uid == 0,
                  entry.st_mode & S_IFMT == S_IFLNK || entry.st_mode & 0o022 == 0 else { throw SetupError("The administrator snapshot has unsafe file ownership or permissions.") }
        }
    }

    static func secureDirectory(_ url: URL) throws -> URL {
        let parent = url.deletingLastPathComponent()
        var parentState = try directoryState(parent)
        guard parentState.st_uid == 0, parentState.st_mode & 0o022 == 0 else { throw SetupError("The system application-support folder has unsafe permissions.") }
        if mkdir(url.path, 0o755) != 0 && errno != EEXIST { throw SetupError("Kumo could not create its system support folder.") }
        parentState = try directoryState(url)
        guard parentState.st_uid == 0, parentState.st_mode & 0o022 == 0 else { throw SetupError("Kumo's system support folder has unsafe permissions.") }
        return url
    }

    static func privateDirectory(parent: URL, prefix: String) throws -> URL {
        var template = Array(parent.appendingPathComponent(prefix + "XXXXXXXX").path.utf8CString)
        guard let result = mkdtemp(&template) else { throw SetupError("Kumo could not create a private installation folder.") }
        return URL(fileURLWithPath: String(cString: result), isDirectory: true)
    }

    static func rootOwnership(_ root: URL) throws {
        try secureEntry(root)
        guard let walk = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil) else { throw SetupError("The browser staging folder cannot be read.") }
        for case let file as URL in walk {
            try secureEntry(file)
        }
    }

    static func secureEntry(_ file: URL) throws {
        var state = stat()
        guard lstat(file.path, &state) == 0, lchown(file.path, 0, 0) == 0 else { throw SetupError("Kumo could not secure an installed file.") }
        if state.st_mode & S_IFMT != S_IFLNK {
            guard chmod(file.path, state.st_mode & 0o777 & ~mode_t(0o022)) == 0 else { throw SetupError("Kumo could not secure an installed file's permissions.") }
        }
    }

    static func assertBrowserClosed() throws {
        let processes = try run("/bin/ps", ["-axo", "pid=,comm="], maximumOutput: 2_097_152)
        guard !processes.output.split(separator: "\n").contains(where: { line in
            line.contains("/Applications/Kumo.app/") || line.contains("/Applications/Kumo.app ")
        }) else { throw SetupError("Kumo is still running. Finish any unsaved work, quit Kumo, then click Retry.") }
    }

    static func acquireInstalledLease() throws -> Int32 {
        let path = SetupPolicy.destination.appendingPathComponent("Contents/Resources/kumo-update-lock").path
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return -1 }
            throw SetupError("Kumo's update lock could not be opened safely.")
        }
        do {
            let state = try MalwareIO.descriptorState(fd)
            guard state.st_nlink == 1, state.st_mode & 0o022 == 0, flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw SetupError("Kumo or its updater is still using the installed app. Quit Kumo, then retry.") }
            return fd
        } catch { close(fd); throw error }
    }

    static func installSources(payloads: Payloads, support: URL) throws {
        let sourceDirectory = try secureDirectory(support.appendingPathComponent("Installer Sources", isDirectory: true))
        let versionDirectory = try secureDirectory(sourceDirectory.appendingPathComponent(payloads.manifest.appBuild, isDirectory: true))
        let source = payloads.resources.appendingPathComponent("payload/clamav-source.tar.gz")
        try atomicRootCopy(source, destination: versionDirectory.appendingPathComponent("clamav-source.tar.gz"))
        let notices = payloads.resources.appendingPathComponent("payload/notices", isDirectory: true)
        if FileManager.default.fileExists(atPath: notices.path) {
            let noticeDestination = try secureDirectory(versionDirectory.appendingPathComponent("notices", isDirectory: true))
            guard let walk = FileManager.default.enumerator(at: notices, includingPropertiesForKeys: nil) else { throw SetupError("The installer notices cannot be read.") }
            for case let file as URL in walk {
                let relative = String(file.path.dropFirst(notices.path.count + 1))
                let destination = noticeDestination.appendingPathComponent(relative)
                var state = stat()
                guard lstat(file.path, &state) == 0 else { throw SetupError("An installer notice disappeared.") }
                if state.st_mode & S_IFMT == S_IFDIR { _ = try secureDirectory(destination) }
                else {
                    guard state.st_mode & S_IFMT == S_IFREG, state.st_size <= 4_194_304 else { throw SetupError("An installer notice is unexpectedly large.") }
                    try atomicRootCopy(file, destination: destination)
                }
            }
        }
    }

    static func atomicRootCopy(_ source: URL, destination: URL) throws {
        let temporary = destination.deletingLastPathComponent().appendingPathComponent(".copy-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.copyItem(at: source, to: temporary)
        guard chmod(temporary.path, 0o644) == 0, lchown(temporary.path, 0, 0) == 0,
              rename(temporary.path, destination.path) == 0 else { throw SetupError("Kumo could not save an antivirus license or source file.") }
    }
}
