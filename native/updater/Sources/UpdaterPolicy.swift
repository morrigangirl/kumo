import Foundation
import Darwin
import Security

public enum UpdatePolicyError: Error, LocalizedError, Equatable {
    case invalidConfiguration, invalidHost, unsafeLock, browserRunning, invalidSignature, invalidProcessInventory
    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration: return "Kumo's signed release update configuration is invalid."
        case .invalidHost: return "The updater must run from its original signed Kumo application."
        case .unsafeLock: return "Kumo's update coordination file cannot be verified."
        case .browserRunning: return "Quit every Kumo window and profile before installing. Kumo is still running or another update is in progress."
        case .invalidSignature: return "Automatic app updates require a verified Carson Press LLC Developer ID release."
        case .invalidProcessInventory: return "Kumo could not safely inspect the running browser processes."
        }
    }
}

public struct ReleaseConfiguration: Decodable {
    public static let repository = "morrigangirl/kumo"
    public static let feedURL = "https://github.com/morrigangirl/kumo/releases/latest/download/appcast.xml"
    public static let teamID = "PV65ZWXCWX"
    public let schemaVersion: Int
    public let repository: String
    public let version: String
    public let build: String
    public let feedURL: String
    public let publicEDKey: String?
    public let enabled: Bool?
    public let teamId: String?
    public var configured: Bool { enabled == true && publicEDKey != nil }
    public init(data: Data) throws {
        guard data.count <= 16_384 else { throw UpdatePolicyError.invalidConfiguration }
        self = try JSONDecoder().decode(Self.self, from: data)
        guard schemaVersion == 1, repository == Self.repository, feedURL == Self.feedURL,
              teamId == nil || teamId == Self.teamID,
              version.range(of: #"^[0-9]+\.[0-9]+\.[0-9]+$"#, options: .regularExpression) != nil,
              build.range(of: #"^[1-9][0-9]{0,17}$"#, options: .regularExpression) != nil else { throw UpdatePolicyError.invalidConfiguration }
        if let key = publicEDKey {
            guard let bytes = Data(base64Encoded: key), bytes.count == 32, bytes.base64EncodedString() == key else {
                throw UpdatePolicyError.invalidConfiguration
            }
        }
    }
}

public struct UpdateHost {
    public let application: URL
    public let companion: URL
    public let configuration: ReleaseConfiguration
    public init(companion: URL) throws {
        let companion = companion.standardizedFileURL
        guard companion == companion.resolvingSymlinksInPath(), companion.lastPathComponent == "KumoUpdater.app",
              companion.deletingLastPathComponent().lastPathComponent == "Helpers",
              companion.deletingLastPathComponent().deletingLastPathComponent().lastPathComponent == "Contents" else {
            throw UpdatePolicyError.invalidHost
        }
        let application = companion.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        guard application.pathExtension == "app", let bundle = Bundle(url: application), bundle.bundleIdentifier == "app.kumo.browser",
              let ownBundle = Bundle(url: companion), ownBundle.bundleIdentifier == "app.kumo.browser.updater" else {
            throw UpdatePolicyError.invalidHost
        }
        let data = try readRegularFile(application.appendingPathComponent("Contents/Resources/kumo-update-config.json"), maximum: 16_384)
        let configuration = try ReleaseConfiguration(data: data)
        guard bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String == configuration.version,
              bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String == configuration.build else {
            throw UpdatePolicyError.invalidConfiguration
        }
        self.application = application; self.companion = companion; self.configuration = configuration
    }
    public func verifyProduction() throws {
        guard configuration.configured, let bundle = Bundle(url: application),
              bundle.object(forInfoDictionaryKey: "SUFeedURL") as? String == ReleaseConfiguration.feedURL,
              bundle.object(forInfoDictionaryKey: "SUPublicEDKey") as? String == configuration.publicEDKey,
              bundle.object(forInfoDictionaryKey: "SURequireSignedFeed") as? Bool == true,
              bundle.object(forInfoDictionaryKey: "SUVerifyUpdateBeforeExtraction") as? Bool == true,
              bundle.object(forInfoDictionaryKey: "SUSignedFeedFailureExpirationInterval") as? Int == 0,
              bundle.object(forInfoDictionaryKey: "SUAllowsAutomaticUpdates") as? Bool == false,
              bundle.object(forInfoDictionaryKey: "SUEnableSystemProfiling") as? Bool == false else {
            throw UpdatePolicyError.invalidConfiguration
        }
        try Self.verifyDeveloperID(application, identifier: "app.kumo.browser", nested: true)
        try Self.verifyDeveloperID(companion, identifier: "app.kumo.browser.updater", nested: true)
    }
    public static func verifyDeveloperID(_ url: URL, identifier: String, nested: Bool) throws {
        guard ["app.kumo.browser", "app.kumo.browser.updater"].contains(identifier) else { throw UpdatePolicyError.invalidSignature }
        let text = "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(ReleaseConfiguration.teamID)\""
        var code: SecStaticCode?, requirement: SecRequirement?
        guard SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &code) == errSecSuccess,
              SecRequirementCreateWithString(text as CFString, SecCSFlags(), &requirement) == errSecSuccess,
              let code, let requirement else { throw UpdatePolicyError.invalidSignature }
        let flags = (1 << 29) | kSecCSCheckAllArchitectures | kSecCSStrictValidate | (nested ? kSecCSCheckNestedCode : 0)
        guard SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: flags), requirement) == errSecSuccess else {
            throw UpdatePolicyError.invalidSignature
        }
    }
}

public func readRegularFile(_ url: URL, maximum: Int) throws -> Data {
    let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw UpdatePolicyError.invalidHost }
    defer { close(fd) }
    var state = stat()
    guard fstat(fd, &state) == 0, state.st_mode & S_IFMT == S_IFREG, state.st_nlink == 1,
          state.st_size >= 0, state.st_size <= maximum else { throw UpdatePolicyError.invalidHost }
    var bytes = [UInt8](repeating: 0, count: maximum + 1)
    let count = Darwin.read(fd, &bytes, bytes.count)
    guard count == state.st_size else { throw UpdatePolicyError.invalidHost }
    return Data(bytes.prefix(count))
}

// This descriptor locks a sealed, read-only resource. It never rewrites the app.
// Every Kumo launcher holds SH across execv; this EX blocks all profiles/users
// of the same installation until Sparkle has completed the atomic replacement.
public final class UpdateLease {
    public static let contents = Data("Kumo update coordination v1\n".utf8)
    private var descriptor: Int32 = -1
    public init(application: URL) throws {
        let file = application.appendingPathComponent("Contents/Resources/kumo-update-lock")
        descriptor = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw UpdatePolicyError.unsafeLock }
        do {
            var state = stat()
            guard fstat(descriptor, &state) == 0, state.st_mode & S_IFMT == S_IFREG, state.st_nlink == 1,
                  state.st_size == Self.contents.count, state.st_mode & 0o022 == 0 else { throw UpdatePolicyError.unsafeLock }
            var bytes = [UInt8](repeating: 0, count: Self.contents.count + 1)
            guard Darwin.read(descriptor, &bytes, bytes.count) == Self.contents.count,
                  Data(bytes.prefix(Self.contents.count)) == Self.contents else { throw UpdatePolicyError.unsafeLock }
            guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else { throw UpdatePolicyError.browserRunning }
        } catch { close(descriptor); descriptor = -1; throw error }
    }
    public func release() { if descriptor >= 0 { close(descriptor); descriptor = -1 } }
    deinit { release() }
}

// Match exact directory boundaries; neither another installed Kumo copy nor an
// arbitrary path containing "Kumo.app" grants an exclusion from this inventory.
public func updateProcessBlocksInstall(executable: URL, application: URL, companion: URL) -> Bool {
    let path = executable.standardizedFileURL.path, host = application.standardizedFileURL.path
    let updater = companion.standardizedFileURL.path
    return path.hasPrefix(host + "/Contents/") && !path.hasPrefix(updater + "/Contents/")
}

public func runningBrowserProcesses(application: URL, companion: URL) throws -> [pid_t] {
    let needed = proc_listallpids(nil, 0)
    guard needed > 0, needed < 100_000 else { throw UpdatePolicyError.invalidProcessInventory }
    var pids = [pid_t](repeating: 0, count: Int(needed) + 1024)
    let count = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
    guard count > 0, count < pids.count else { throw UpdatePolicyError.invalidProcessInventory }
    var blockers = [pid_t]()
    for pid in pids.prefix(Int(count)) where pid > 0 && pid != getpid() {
        var bytes = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(pid, &bytes, UInt32(bytes.count))
        if length <= 0 { continue } // Exited or protected macOS system process.
        let path = String(cString: bytes)
        if updateProcessBlocksInstall(executable: URL(fileURLWithPath: path), application: application, companion: companion) {
            blockers.append(pid)
        }
    }
    return blockers
}

public func validReleaseArchiveURL(_ url: URL, expectedBuild: String? = nil) -> Bool {
    guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false), parts.scheme == "https", parts.host == "github.com",
          parts.user == nil, parts.password == nil, parts.port == nil, parts.query == nil, parts.fragment == nil else { return false }
    let segments = parts.percentEncodedPath.split(separator: "/", omittingEmptySubsequences: false)
    guard segments.count == 7, segments[0].isEmpty, segments[1] == "morrigangirl", segments[2] == "kumo", segments[3] == "releases", segments[4] == "download" else { return false }
    let tag = String(segments[5])
    guard tag.range(of: #"^v[0-9]+\.[0-9]+\.[0-9]+-[1-9][0-9]{0,17}$"#, options: .regularExpression) != nil,
          let split = tag.lastIndex(of: "-") else { return false }
    let version = String(tag[tag.index(after: tag.startIndex)..<split]), build = String(tag[tag.index(after: split)...])
    return (expectedBuild == nil || expectedBuild == build) && segments[6] == "Kumo-\(version)-\(build)-macos-arm64.zip"
}

public enum InstallationStage: CaseIterable { case notDownloaded, downloaded, installing }
public enum InstallationChoice: CaseIterable { case install, dismiss, skip }

// Installing-stage Dismiss preserves Sparkle's installer and may install when
// the target exits. Kumo must cancel instead. An inherited/resumed installer
// without this process's exclusive coordination lease is never authorized.
public func safeInstallationChoice(_ choice: InstallationChoice, stage: InstallationStage, leaseHeld: Bool) -> InstallationChoice {
    if stage == .installing && (!leaseHeld || choice != .install) { return .skip }
    return choice
}

public struct InstallationLeasePolicy {
    public enum Phase: Equatable { case idle, authorized, extracting, unconfirmed, completed }
    public enum Event { case authorized, extractionStarted, installerLaunched, noInstallerLaunched, cycleEnded, revalidationFailed, installationCompleted }
    public private(set) var phase: Phase = .idle
    public private(set) var installerHandedOff = false
    public private(set) var ambiguousOutcome = false
    public init() {}
    public var mayReleaseWithoutCompletion: Bool { phase == .idle || phase == .authorized || phase == .completed }
    @discardableResult public mutating func record(_ event: Event) -> Bool {
        switch event {
        case .authorized:
            if phase == .idle || phase == .completed { phase = .authorized; installerHandedOff = false; ambiguousOutcome = false }
        case .extractionStarted: phase = ambiguousOutcome ? .unconfirmed : .extracting
        case .installerLaunched: installerHandedOff = true
        case .noInstallerLaunched:
            phase = installerHandedOff || ambiguousOutcome ? .unconfirmed : .idle
        case .cycleEnded, .revalidationFailed:
            if phase == .extracting || phase == .unconfirmed { phase = .unconfirmed; ambiguousOutcome = true }
            else if phase != .completed { phase = .idle }
        case .installationCompleted: phase = .completed; ambiguousOutcome = false
        }
        return mayReleaseWithoutCompletion
    }
}

// Recover a lost completion callback only after the expected, strictly signed
// replacement is actually installed. A valid OLD bundle never releases a lease.
public func verifyCommittedReplacement(application: URL, companion: URL, oldBuild: String, expectedBuild: String) throws -> Bool {
    guard expectedBuild != oldBuild else { return false }
    let config = try ReleaseConfiguration(data: readRegularFile(application.appendingPathComponent("Contents/Resources/kumo-update-config.json"), maximum: 16_384))
    guard config.configured, config.build == expectedBuild else { return false }
    let info = try PropertyListSerialization.propertyList(from: readRegularFile(application.appendingPathComponent("Contents/Info.plist"), maximum: 65_536), format: nil) as? [String: Any]
    guard info?["CFBundleIdentifier"] as? String == "app.kumo.browser", info?["CFBundleVersion"] as? String == expectedBuild,
          info?["CFBundleShortVersionString"] as? String == config.version else { return false }
    try UpdateHost.verifyDeveloperID(application, identifier: "app.kumo.browser", nested: true)
    try UpdateHost.verifyDeveloperID(companion, identifier: "app.kumo.browser.updater", nested: true)
    return true
}

// Pinned Sparkle 2.10.0 constructs this exact error only when its installer
// launcher reports canceled authorization before submitting the installer.
// A matching number in another domain/underlying error is not this evidence.
public func isDefinitivePrelaunchCancellation(_ error: Error?) -> Bool {
    guard let error = error as NSError?, error.domain == "SUSparkleErrorDomain", error.code == 4007 else { return false }
    return true
}

public func validatedHandoffParent(_ value: String, actualParent: pid_t) throws -> pid_t {
    guard value.range(of: #"^[1-9][0-9]{0,9}$"#, options: .regularExpression) != nil,
          let pid = Int32(value), pid > 1, pid == actualParent else { throw UpdatePolicyError.invalidHost }
    return pid
}
