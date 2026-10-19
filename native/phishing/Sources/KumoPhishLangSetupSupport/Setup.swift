import Foundation
import Darwin
import Security
import CryptoKit

public enum PhishLangIdentity {
    public static let extensionID = "ejmohaggcahgfhmgkdiicnmmlpnhgfmi"
    public static let origin = "chrome-extension://" + extensionID + "/"
    public static let host = "com.kumo.phishlang"
    public static let bundle = "app.kumo.phishlang"
    public static let team = "PV65ZWXCWX"
    public static let appName = "Kumo PhishLang.app"
    static let receipt = ".kumo-phishlang-install.json"
    static var marker: [String: Any] { ["schemaVersion": 1, "bundleIdentifier": bundle, "extensionId": extensionID, "host": host] }
}

public enum PhishLangSetupFailure: Error, LocalizedError, Equatable {
    case usage, unsafePath, unownedItem, invalidPackage, invalidSignature, busy, io
    public var errorDescription: String? {
        switch self {
        case .usage: return "Use install, uninstall or status. Custom targets require --applications-dir, --native-hosts-dir and --extension-dir together."
        case .unsafePath: return "A target contains a symbolic link, hard link, unsafe permissions or unsupported file. No linked target will be changed."
        case .unownedItem: return "An existing item is not an owned Kumo PhishLang installation. It has been preserved."
        case .invalidPackage: return "The add-on package identity or sealed extension is invalid."
        case .invalidSignature: return "The native companion signature or sandbox policy is invalid."
        case .busy: return "Another PhishLang setup is running."
        case .io: return "A local filesystem operation failed. Existing installation backups have been preserved."
        }
    }
}

public struct PhishLangTargets {
    public let applications: URL
    public let hosts: URL
    public let extensionDirectory: URL
    public var application: URL { applications.appendingPathComponent(PhishLangIdentity.appName, isDirectory: true) }
    public var manifest: URL { hosts.appendingPathComponent(PhishLangIdentity.host + ".json") }
    public init(applications: URL, hosts: URL, extensionDirectory: URL) throws {
        for url in [applications, hosts, extensionDirectory] { try SafeDirectory.validatePath(url) }
        let paths = [applications.path, hosts.path, extensionDirectory.path]
        guard Set(paths).count == 3,
              !paths.enumerated().contains(where: { index, path in paths.enumerated().contains { other, candidate in index != other && path.hasPrefix(candidate + "/") } }) else {
            throw PhishLangSetupFailure.unsafePath
        }
        self.applications = applications; self.hosts = hosts; self.extensionDirectory = extensionDirectory
    }
    public static func defaults() throws -> PhishLangTargets {
        guard let entry = getpwuid(getuid()), let path = entry.pointee.pw_dir else { throw PhishLangSetupFailure.unsafePath }
        let home = URL(fileURLWithPath: String(cString: path), isDirectory: true)
        return try PhishLangTargets(applications: home.appendingPathComponent("Applications", isDirectory: true),
            hosts: home.appendingPathComponent("Library/Application Support/Kumo/NativeMessagingHosts", isDirectory: true),
            extensionDirectory: home.appendingPathComponent("Library/Application Support/KumoPhishLang/extension", isDirectory: true))
    }
    public static func parse(arguments: [String]) throws -> (String, PhishLangTargets) {
        guard let action = arguments.first, ["install", "uninstall", "status"].contains(action) else { throw PhishLangSetupFailure.usage }
        if arguments.count == 1 { return (action, try defaults()) }
        guard arguments.count == 7 else { throw PhishLangSetupFailure.usage }
        var values: [String: URL] = [:]
        for index in stride(from: 1, to: arguments.count, by: 2) {
            let key = arguments[index], path = arguments[index + 1]
            guard ["--applications-dir", "--native-hosts-dir", "--extension-dir"].contains(key), values[key] == nil, path.hasPrefix("/") else { throw PhishLangSetupFailure.usage }
            let parts = path.split(separator: "/", omittingEmptySubsequences: false)
            guard !parts.contains("."), !parts.contains(".."), !path.contains("\0"), !path.contains("\n"), !path.contains("\r") else { throw PhishLangSetupFailure.unsafePath }
            values[key] = URL(fileURLWithPath: path, isDirectory: true)
        }
        guard let applications = values["--applications-dir"], let hosts = values["--native-hosts-dir"], let directory = values["--extension-dir"] else { throw PhishLangSetupFailure.usage }
        return (action, try PhishLangTargets(applications: applications, hosts: hosts, extensionDirectory: directory))
    }
}

/// Directory-relative operations keep aliases from redirecting writes or recursive removal.
/// No operation recursively removes an absolute path, and regular files must have one link.
private final class SafeDirectory {
    let fd: Int32
    init(fd: Int32) { self.fd = fd }
    deinit { close(fd) }
    static func validatePath(_ url: URL) throws {
        let path = url.path
        guard path.hasPrefix("/"), path != "/", !path.contains("\0"), !path.contains("\n"), !path.contains("\r"),
              !path.split(separator: "/").contains("."), !path.split(separator: "/").contains("..") else { throw PhishLangSetupFailure.unsafePath }
    }
    static func openAbsolute(_ url: URL, create: Bool = false, managed: Bool = true, protectAncestors: Bool = true) throws -> SafeDirectory {
        try validatePath(url)
        var current = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard current >= 0 else { throw PhishLangSetupFailure.io }
        defer { if current >= 0 { close(current) } }
        for piece in url.path.split(separator: "/") {
            let name = String(piece)
            var child = openat(current, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if child < 0 && errno == ENOENT && create {
                guard mkdirat(current, name, 0o700) == 0 || errno == EEXIST else { throw PhishLangSetupFailure.io }
                child = openat(current, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            guard child >= 0 else { throw PhishLangSetupFailure.unsafePath }
            var state = stat()
            guard fstat(child, &state) == 0, state.st_mode & S_IFMT == S_IFDIR else { close(child); throw PhishLangSetupFailure.unsafePath }
            let trustedOwner = state.st_uid == getuid() || state.st_uid == 0
            let rootStickyTemporary = state.st_uid == 0 && state.st_mode & S_ISVTX != 0
            guard !protectAncestors || trustedOwner && (state.st_mode & 0o022 == 0 || rootStickyTemporary) else { close(child); throw PhishLangSetupFailure.unsafePath }
            close(current); current = child
        }
        if managed {
            var state = stat()
            guard fstat(current, &state) == 0, state.st_uid == getuid(), state.st_mode & 0o022 == 0 else { throw PhishLangSetupFailure.unsafePath }
        }
        let result = SafeDirectory(fd: current); current = -1; return result
    }
    func state(_ name: String) throws -> stat? {
        var value = stat()
        if fstatat(fd, name, &value, AT_SYMLINK_NOFOLLOW) == 0 { return value }
        if errno == ENOENT { return nil }
        throw PhishLangSetupFailure.io
    }
    func child(_ name: String) throws -> SafeDirectory {
        let value = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard value >= 0 else { throw PhishLangSetupFailure.unsafePath }
        var state = stat()
        guard fstat(value, &state) == 0, state.st_uid == getuid(), state.st_mode & 0o022 == 0 else { close(value); throw PhishLangSetupFailure.unsafePath }
        return SafeDirectory(fd: value)
    }
    func make(_ name: String) throws -> SafeDirectory {
        guard mkdirat(fd, name, 0o700) == 0 else { throw PhishLangSetupFailure.io }
        return try child(name)
    }
    func names() throws -> [String] {
        let copied = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copied >= 0 else { throw PhishLangSetupFailure.io }
        guard let stream = fdopendir(copied) else { close(copied); throw PhishLangSetupFailure.io }
        defer { closedir(stream) }
        var names: [String] = []
        while let entry = readdir(stream) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name != ".", name != ".." { names.append(name) }
            guard names.count <= 2048 else { throw PhishLangSetupFailure.unsafePath }
        }
        return names.sorted()
    }
    func regular(_ name: String, flags: Int32 = O_RDONLY) throws -> Int32 {
        let value = openat(fd, name, flags | O_NOFOLLOW | O_CLOEXEC)
        guard value >= 0 else { throw PhishLangSetupFailure.unsafePath }
        var state = stat()
        guard fstat(value, &state) == 0, state.st_mode & S_IFMT == S_IFREG, state.st_uid == getuid(), state.st_nlink == 1,
              state.st_mode & 0o6022 == 0 else { close(value); throw PhishLangSetupFailure.unsafePath }
        return value
    }
    func data(_ name: String, limit: Int = 131_072) throws -> Data {
        let value = try regular(name); defer { close(value) }
        var state = stat(); guard fstat(value, &state) == 0, state.st_size <= limit else { throw PhishLangSetupFailure.unsafePath }
        let handle = FileHandle(fileDescriptor: value, closeOnDealloc: false)
        let data = try handle.read(upToCount: limit + 1) ?? Data()
        guard data.count <= limit else { throw PhishLangSetupFailure.unsafePath }; return data
    }
    func writeNew(_ name: String, data: Data, mode: mode_t = 0o600) throws {
        let value = openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard value >= 0 else { throw PhishLangSetupFailure.io }
        defer { close(value) }
        let handle = FileHandle(fileDescriptor: value, closeOnDealloc: false)
        try handle.write(contentsOf: data)
        guard fsync(value) == 0 else { throw PhishLangSetupFailure.io }
    }
    func validateTree(depth: Int = 0, budget: inout Int64) throws {
        guard depth < 24 else { throw PhishLangSetupFailure.unsafePath }
        for name in try names() {
            guard let entry = try state(name), entry.st_uid == getuid(), entry.st_mode & 0o6022 == 0 else { throw PhishLangSetupFailure.unsafePath }
            switch entry.st_mode & S_IFMT {
            case S_IFDIR: try child(name).validateTree(depth: depth + 1, budget: &budget)
            case S_IFREG:
                let value = try regular(name); defer { close(value) }
                budget -= Int64(entry.st_size); guard budget >= 0 else { throw PhishLangSetupFailure.unsafePath }
            default: throw PhishLangSetupFailure.unsafePath
            }
        }
    }
    func copyContents(to destination: SafeDirectory, depth: Int = 0) throws {
        guard depth < 24 else { throw PhishLangSetupFailure.unsafePath }
        for name in try names() {
            guard let entry = try state(name) else { throw PhishLangSetupFailure.io }
            if entry.st_mode & S_IFMT == S_IFDIR {
                try child(name).copyContents(to: destination.make(name), depth: depth + 1)
            } else {
                let input = try regular(name); defer { close(input) }
                let output = openat(destination.fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, entry.st_mode & 0o111 == 0 ? 0o600 : 0o700)
                guard output >= 0 else { throw PhishLangSetupFailure.io }; defer { close(output) }
                guard fcopyfile(input, output, nil, copyfile_flags_t(COPYFILE_DATA | COPYFILE_XATTR)) == 0,
                      fchmod(output, entry.st_mode & 0o111 == 0 ? 0o600 : 0o700) == 0, fsync(output) == 0 else { throw PhishLangSetupFailure.io }
            }
        }
    }
    func rename(_ source: String, to target: String) throws {
        guard renameatx_np(fd, source, fd, target, UInt32(RENAME_EXCL)) == 0 else { throw PhishLangSetupFailure.io }
    }
    func remove(_ name: String) throws {
        guard let entry = try state(name) else { return }
        if entry.st_mode & S_IFMT == S_IFDIR {
            let directory = try child(name)
            for child in try directory.names() { try directory.remove(child) }
            guard let latest = try state(name), latest.st_ino == entry.st_ino, latest.st_dev == entry.st_dev,
                  unlinkat(fd, name, AT_REMOVEDIR) == 0 else { throw PhishLangSetupFailure.io }
        } else {
            guard entry.st_mode & S_IFMT == S_IFREG, entry.st_uid == getuid(), entry.st_nlink == 1,
                  unlinkat(fd, name, 0) == 0 else { throw PhishLangSetupFailure.unsafePath }
        }
    }
    func lock() throws -> Int32 {
        let value = openat(fd, ".kumo-phishlang-setup.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard value >= 0 else { throw PhishLangSetupFailure.unsafePath }
        var state = stat()
        guard fstat(value, &state) == 0, state.st_mode & S_IFMT == S_IFREG, state.st_uid == getuid(), state.st_nlink == 1, state.st_mode & 0o077 == 0 else { close(value); throw PhishLangSetupFailure.unsafePath }
        guard flock(value, LOCK_EX | LOCK_NB) == 0 else { close(value); throw PhishLangSetupFailure.busy }
        return value
    }
}

public final class PhishLangSetup {
    public typealias SignatureVerifier = (URL) throws -> Void
    let source: URL
    let targets: PhishLangTargets
    let verifySignature: SignatureVerifier
    public init(source: URL, targets: PhishLangTargets, verifySignature: @escaping SignatureVerifier = PhishLangSetup.checkSignature) {
        self.source = source; self.targets = targets; self.verifySignature = verifySignature
    }
    public static func checkSignature(_ application: URL) throws {
        var code: SecStaticCode?
        var requirement: SecRequirement?
        let expression = "anchor apple generic and identifier \"" + PhishLangIdentity.bundle + "\" and certificate leaf[subject.OU] = \"" + PhishLangIdentity.team + "\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
        guard SecStaticCodeCreateWithPath(application as CFURL, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode), requirement) == errSecSuccess else { throw PhishLangSetupFailure.invalidSignature }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dictionary = info as? [String: Any], let flags = dictionary[kSecCodeInfoFlags as String] as? UInt32,
              flags & 0x12000 == 0x12000,
              dictionary[kSecCodeInfoTimestamp as String] is Date,
              let entitlements = dictionary[kSecCodeInfoEntitlementsDict as String] as? [String: Any], entitlements.count == 1,
              let sandbox = entitlements["com.apple.security.app-sandbox"] as? NSNumber,
              CFGetTypeID(sandbox) == CFBooleanGetTypeID(), sandbox.boolValue else { throw PhishLangSetupFailure.invalidSignature }
    }
    private func app(_ url: URL, protectAncestors: Bool = true) throws -> SafeDirectory {
        let directory = try SafeDirectory.openAbsolute(url, protectAncestors: protectAncestors)
        var budget: Int64 = 180_000_000; try directory.validateTree(budget: &budget)
        let contents = try directory.child("Contents")
        guard let info = try PropertyListSerialization.propertyList(from: contents.data("Info.plist"), format: nil) as? [String: Any],
              info["CFBundleIdentifier"] as? String == PhishLangIdentity.bundle,
              info["CFBundleExecutable"] as? String == "KumoPhishingHost",
              info["KumoPhishLangExtensionOrigin"] as? String == PhishLangIdentity.origin,
              info["KumoPhishLangPackageIdentifier"] as? String == PhishLangIdentity.bundle else { throw PhishLangSetupFailure.invalidPackage }
        try verifySignature(url)
        return directory
    }
    private func extensionIdentity(_ directory: SafeDirectory, installed: Bool) throws {
        guard let manifest = try JSONSerialization.jsonObject(with: directory.data("manifest.json")) as? [String: Any],
              let key = manifest["key"] as? String, let bytes = Data(base64Encoded: key) else { throw PhishLangSetupFailure.invalidPackage }
        let value = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined().prefix(32)
        let identifier = value.compactMap { Int(String($0), radix: 16) }.map { String(UnicodeScalar(97 + $0)!) }.joined()
        guard identifier == PhishLangIdentity.extensionID else { throw PhishLangSetupFailure.invalidPackage }
        if installed {
            guard let marker = try JSONSerialization.jsonObject(with: directory.data(PhishLangIdentity.receipt)) as? [String: Any],
                  NSDictionary(dictionary: marker).isEqual(to: PhishLangIdentity.marker) else { throw PhishLangSetupFailure.unownedItem }
        }
    }
    private func hostData() throws -> Data {
        try JSONSerialization.data(withJSONObject: ["name": PhishLangIdentity.host, "description": "Kumo PhishLang local classifier", "type": "stdio",
            "path": targets.application.appendingPathComponent("Contents/MacOS/KumoPhishingHost").path, "allowed_origins": [PhishLangIdentity.origin]], options: [.sortedKeys]) + Data([10])
    }
    private func ownedHost(_ directory: SafeDirectory) throws -> Bool {
        guard try directory.state(PhishLangIdentity.host + ".json") != nil else { return false }
        let actual = try JSONSerialization.jsonObject(with: directory.data(PhishLangIdentity.host + ".json")) as? NSDictionary
        let expected = try JSONSerialization.jsonObject(with: hostData()) as? NSDictionary
        guard actual == expected else { throw PhishLangSetupFailure.unownedItem }; return true
    }
    private func ownedExtension(_ parent: SafeDirectory) throws -> Bool {
        let name = targets.extensionDirectory.lastPathComponent
        guard try parent.state(name) != nil else { return false }
        let directory = try parent.child(name)
        var budget: Int64 = 10_000_000; try directory.validateTree(budget: &budget)
        try extensionIdentity(directory, installed: true); return true
    }
    private func ownedApp(_ parent: SafeDirectory) throws -> Bool {
        guard try parent.state(PhishLangIdentity.appName) != nil else { return false }
        _ = try app(targets.application); return true
    }
    public func status() -> [String: Any] {
        do {
            let apps = try SafeDirectory.openAbsolute(targets.applications)
            let hosts = try SafeDirectory.openAbsolute(targets.hosts)
            let extensions = try SafeDirectory.openAbsolute(targets.extensionDirectory.deletingLastPathComponent())
            let ready = try ownedApp(apps) && ownedHost(hosts) && ownedExtension(extensions)
            return ["ok": true, "installed": ready, "host": PhishLangIdentity.host, "extensionId": PhishLangIdentity.extensionID,
                    "applicationPath": targets.application.path, "extensionPath": targets.extensionDirectory.path]
        } catch {
            return ["ok": true, "installed": false, "host": PhishLangIdentity.host, "extensionId": PhishLangIdentity.extensionID]
        }
    }
    public func install() throws -> [String: Any] {
        // Downloads may live on a shared writable volume. Source ancestry still
        // rejects aliases; only target ancestry must be protected from renaming.
        // The copied app is strictly signature-checked again in the owned stage
        // before any installed item is replaced.
        let original = try app(source, protectAncestors: false)
        let sealedExtension = try original.child("Contents").child("Resources").child("Extension")
        try extensionIdentity(sealedExtension, installed: false)
        let apps = try SafeDirectory.openAbsolute(targets.applications, create: true)
        let lock = try apps.lock(); defer { close(lock) }
        let hosts = try SafeDirectory.openAbsolute(targets.hosts, create: true)
        let extensions = try SafeDirectory.openAbsolute(targets.extensionDirectory.deletingLastPathComponent(), create: true)
        let oldApp = try ownedApp(apps), oldHost = try ownedHost(hosts), oldExtension = try ownedExtension(extensions)
        let token = UUID().uuidString.lowercased()
        let appStage = ".kumo-phishlang-app-" + token, extensionStage = ".kumo-phishlang-extension-" + token, hostStage = ".kumo-phishlang-host-" + token
        let appBackup = appStage + ".previous", extensionBackup = extensionStage + ".previous", hostBackup = hostStage + ".previous"
        var backedApp = false, backedExtension = false, backedHost = false
        var installedApp = false, installedExtension = false
        do {
            try original.copyContents(to: apps.make(appStage))
            let stagedApp = try app(targets.applications.appendingPathComponent(appStage, isDirectory: true))
            let stagedExtension = try stagedApp.child("Contents").child("Resources").child("Extension")
            let extensionCopy = try extensions.make(extensionStage)
            // Copy from the signature-checked owned stage. The downloaded source
            // can be moved or changed after staging without supplying unsigned JS.
            try stagedExtension.copyContents(to: extensionCopy)
            try extensionCopy.writeNew(PhishLangIdentity.receipt, data: JSONSerialization.data(withJSONObject: PhishLangIdentity.marker, options: [.sortedKeys]))
            try extensionIdentity(extensionCopy, installed: true)
            try hosts.writeNew(hostStage, data: hostData())
            if oldApp { try apps.rename(PhishLangIdentity.appName, to: appBackup); backedApp = true }
            if oldExtension { try extensions.rename(targets.extensionDirectory.lastPathComponent, to: extensionBackup); backedExtension = true }
            if oldHost { try hosts.rename(PhishLangIdentity.host + ".json", to: hostBackup); backedHost = true }
            try apps.rename(appStage, to: PhishLangIdentity.appName); installedApp = true
            try extensions.rename(extensionStage, to: targets.extensionDirectory.lastPathComponent); installedExtension = true
            try hosts.rename(hostStage, to: PhishLangIdentity.host + ".json")
        } catch {
            if installedExtension { try? extensions.remove(targets.extensionDirectory.lastPathComponent) }
            if installedApp { try? apps.remove(PhishLangIdentity.appName) }
            if backedApp { try? apps.rename(appBackup, to: PhishLangIdentity.appName) }
            if backedExtension { try? extensions.rename(extensionBackup, to: targets.extensionDirectory.lastPathComponent) }
            if backedHost { try? hosts.rename(hostBackup, to: PhishLangIdentity.host + ".json") }
            try? apps.remove(appStage); try? extensions.remove(extensionStage); try? hosts.remove(hostStage)
            throw error
        }
        if backedApp { try apps.remove(appBackup) }
        if backedExtension { try extensions.remove(extensionBackup) }
        if backedHost { try hosts.remove(hostBackup) }
        return ["ok": true, "status": "installed", "applicationPath": targets.application.path, "extensionPath": targets.extensionDirectory.path,
                "host": PhishLangIdentity.host, "extensionId": PhishLangIdentity.extensionID,
                "nextStep": "In Kumo, open chrome://extensions, turn on Developer mode, choose Load unpacked and select extensionPath. Then enable protection in the add-on settings."]
    }
    public func uninstall() throws -> [String: Any] {
        // Missing complete installations are a successful no-op; aliases or foreign items fail closed.
        let apps = try SafeDirectory.openAbsolute(targets.applications, create: true)
        let lock = try apps.lock(); defer { close(lock) }
        let hosts = try SafeDirectory.openAbsolute(targets.hosts, create: true)
        let extensions = try SafeDirectory.openAbsolute(targets.extensionDirectory.deletingLastPathComponent(), create: true)
        let hasApp = try ownedApp(apps), hasHost = try ownedHost(hosts), hasExtension = try ownedExtension(extensions)
        if hasHost { try hosts.remove(PhishLangIdentity.host + ".json") }
        if hasExtension { try extensions.remove(targets.extensionDirectory.lastPathComponent) }
        if hasApp { try apps.remove(PhishLangIdentity.appName) }
        return ["ok": true, "status": "uninstalled", "host": PhishLangIdentity.host,
                "nextStep": "Remove Kumo PhishLang from chrome://extensions if it remains listed."]
    }
}
