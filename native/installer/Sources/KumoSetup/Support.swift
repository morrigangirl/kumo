import Foundation
import AppKit
import CryptoKit
import Security
import Darwin
import KumoMalwareCore

struct SetupError: LocalizedError {
    let message: String
    let recoveryReason: String?
    init(_ message: String, recoveryReason: String? = nil) {
        self.message = message
        self.recoveryReason = recoveryReason
    }
    var errorDescription: String? { message }
}

func friendlyError(_ error: Error) -> String {
    guard let failure = error as? MalwareFailure else { return error.localizedDescription }
    switch failure {
    case .missingRuntime: return "The antivirus engine is missing. Click Retry to repair the installation."
    case .invalidRuntime: return "The antivirus engine failed its integrity check. Click Retry to repair the installation."
    case .missingDatabase: return "Virus definitions could not be prepared. Click Retry to try again."
    case .staleDatabase: return "Virus definitions need an update. Connect to the internet, then click Retry."
    case .invalidDatabase: return "Virus definitions could not be verified or updated. Check your internet connection, then click Retry."
    case .timeout: return "The antivirus check took too long. Click Retry to check it again."
    default: return "Kumo could not finish preparing download protection. Click Retry to try again."
    }
}

struct InstallerManifest: Codable {
    let schemaVersion: Int
    let teamId: String
    let appBundleId: String
    let appVersion: String
    let appBuild: String
    let appCDHash: String
    let files: [String: String]
    let definitionsBuiltAt: String
    let vendorPackageSHA256: String
    let vendorPackageBytes: Int64
    let vendorInstallerLeafSHA256: String

    func validate() throws {
        guard schemaVersion == 1, teamId == SetupPolicy.team,
              appBundleId == "app.kumo.browser", !appVersion.isEmpty,
              !appBuild.isEmpty, appBuild.utf8.allSatisfy({ (48...57).contains($0) }),
              appCDHash.count == 40, appCDHash.lowercased().utf8.allSatisfy(SetupPolicy.hex),
              vendorPackageSHA256 == SetupPolicy.vendorHash,
              vendorPackageBytes == 166_772_489,
              vendorInstallerLeafSHA256.uppercased() == SetupPolicy.vendorLeaf,
              !files.isEmpty, files.count < 100_000,
              files.allSatisfy({ SetupPolicy.safePayloadPath($0.key) && MalwareProtocol.validHash($0.value) }) else {
            throw SetupError("The installer manifest is invalid. Download a fresh copy of Kumo Setup.")
        }
        for name in ["payload/Kumo.app/Contents/Info.plist", "payload/clamav.pkg", "payload/definitions/main.cvd", "payload/definitions/daily.cvd", "payload/definitions/bytecode.cvd", "payload/clamav-source.tar.gz"] {
            guard files[name] != nil else { throw SetupError("The installer is missing a required payload: \(name).") }
        }
    }
}

enum SetupPolicy {
    static let team = "PV65ZWXCWX"
    static let vendorHash = "df7fa753e2f9f67f3bc99b2a40a3be7ef559088c68ad6bdf66b4b5764e965bd6"
    static let vendorLeaf = "C59ADFCCF1102477877F0B2A8355F3441A1365CA3F0B13CA82B8F94E4EF1FA67"
    static let destination = URL(fileURLWithPath: "/Applications/Kumo.app", isDirectory: true)
    static let requirement = "anchor apple generic and identifier \"app.kumo.setup\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"PV65ZWXCWX\""
    static func hex(_ byte: UInt8) -> Bool { (48...57).contains(byte) || (97...102).contains(byte) }
    static func safePayloadPath(_ path: String) -> Bool {
        !path.contains("\0") && !path.contains("\n") && !path.contains("\r") &&
        path.hasPrefix("payload/") && !path.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0.isEmpty || $0 == "." || $0 == ".." })
    }
    static func strictTrue(_ value: Any?) -> Bool {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return false }
        return number.boolValue
    }
    static func ready(_ value: [String: Any]) -> Bool {
        strictTrue(value["installed"]) && strictTrue(value["available"]) && strictTrue(value["automaticUpdates"]) && value["reason"] as? String == "ready"
    }
    static func rootAllowed(real: uid_t = getuid(), effective: uid_t = geteuid()) -> Bool { real == 0 && effective == 0 }
    static func userAllowed(real: uid_t, effective: uid_t, console: uid_t) -> Bool { real >= 501 && real == effective && real == console }
    static func quoteShell(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    static func quoteAppleScript(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(of: "\r", with: "\\r").replacingOccurrences(of: "\n", with: "\\n") + "\""
    }
}

func run(_ executable: String, _ arguments: [String], timeout: Double = 180, maximumOutput: Int = 262_144) throws -> CommandResult {
    let result = try FixedCommand.run(URL(fileURLWithPath: executable), arguments, timeout: timeout, maximumOutput: maximumOutput)
    guard result.code == 0, !result.timedOut, !result.outputLimited else {
        throw SetupError("\(URL(fileURLWithPath: executable).lastPathComponent) could not finish. \(result.output.suffix(3000))")
    }
    return result
}

func consoleUID() throws -> uid_t {
    var state = stat()
    guard lstat("/dev/console", &state) == 0, state.st_uid >= 501,
          let account = getpwuid(state.st_uid), let name = account.pointee.pw_name,
          !["root", "loginwindow", "_mbsetupuser"].contains(String(cString: name)) else {
        throw SetupError("Log in to your Mac normally, then open Kumo Setup from that account.")
    }
    return state.st_uid
}

func directoryState(_ url: URL) throws -> stat {
    var state = stat()
    guard lstat(url.path, &state) == 0, state.st_mode & S_IFMT == S_IFDIR else { throw SetupError("A required folder is missing or is a symbolic link: \(url.path)") }
    return state
}

func buildMetadata(_ app: URL) throws -> [String: Any] {
    let resources = app.appendingPathComponent("Contents/Resources", isDirectory: true)
    let candidates = [resources.appendingPathComponent("kumo-build-info.json"),
                      resources.appendingPathComponent("KumoExtension/build-info.json")]
    let present = candidates.filter { path in
        var state = stat()
        return lstat(path.path, &state) == 0
    }
    guard present.count == 1 else { throw SetupError("The browser has missing or ambiguous build metadata.") }
    let fd = open(present[0].path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw SetupError("The browser build metadata cannot be opened safely.") }
    let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    defer { try? file.close() }
    var state = stat()
    guard fstat(fd, &state) == 0, state.st_mode & S_IFMT == S_IFREG,
          state.st_nlink == 1, state.st_size <= 2 * 1024 * 1024,
          let data = try file.read(upToCount: 2 * 1024 * 1024 + 1), data.count <= 2 * 1024 * 1024,
          let metadata = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw SetupError("The browser build metadata is invalid.")
    }
    return metadata
}

func verifyCode(_ app: URL, identifier: String, expectedCDHash: String? = nil) throws {
    let requirement = "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(SetupPolicy.team)\""
    _ = try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", "--test-requirement", "=" + requirement, app.path], timeout: 300)
    if let expectedCDHash {
        let result = try run("/usr/bin/codesign", ["--display", "--verbose=4", app.path])
        guard result.output.split(separator: "\n").contains(where: { $0.lowercased() == "cdhash=" + expectedCDHash.lowercased() }) else {
            throw SetupError("Kumo's signed identity does not match this installer.")
        }
    }
}

final class Payloads {
    let bundle: URL
    let resources: URL
    let manifest: InstallerManifest
    var app: URL { resources.appendingPathComponent("payload/Kumo.app", isDirectory: true) }
    var vendor: URL { resources.appendingPathComponent("payload/clamav.pkg") }
    var definitions: URL { resources.appendingPathComponent("payload/definitions", isDirectory: true) }
    init(bundle: URL = Bundle.main.bundleURL) throws {
        self.bundle = bundle
        self.resources = bundle.appendingPathComponent("Contents/Resources", isDirectory: true)
        let data = try Data(contentsOf: resources.appendingPathComponent("installer-manifest.json"))
        guard data.count <= 32 * 1024 * 1024 else { throw SetupError("The installer manifest is too large.") }
        self.manifest = try JSONDecoder().decode(InstallerManifest.self, from: data)
        try manifest.validate()
    }
    func verify(progress: (String) -> Void = { _ in }) throws {
        progress("Verifying Kumo Setup…")
        try verifyCode(bundle, identifier: "app.kumo.setup")
        progress("Checking bundled files…")
        let payload = resources.appendingPathComponent("payload", isDirectory: true)
        _ = try directoryState(payload)
        var actual: Set<String> = []
        guard let enumerator = FileManager.default.enumerator(at: payload, includingPropertiesForKeys: nil, options: [], errorHandler: { _, _ in false }) else { throw SetupError("The installer payload cannot be read.") }
        for case let item as URL in enumerator {
            var state = stat()
            guard lstat(item.path, &state) == 0 else { throw SetupError("An installer file disappeared.") }
            let relative = String(item.path.dropFirst(resources.path.count + 1))
            guard SetupPolicy.safePayloadPath(relative) else { throw SetupError("The installer contains an unsafe file path.") }
            switch state.st_mode & S_IFMT {
            case S_IFDIR: break
            case S_IFLNK:
                let prefix = app.path + "/"
                let target = item.resolvingSymlinksInPath().path
                guard item.path.hasPrefix(prefix), target.hasPrefix(prefix), FileManager.default.fileExists(atPath: target) else { throw SetupError("The installer contains an external or broken symbolic link.") }
            case S_IFREG:
                guard state.st_nlink == 1, let expected = manifest.files[relative], try MalwareIO.hashFile(item).0 == expected else { throw SetupError("An installer file failed its integrity check: \(relative).") }
                actual.insert(relative)
            default: throw SetupError("The installer contains an unsupported file type.")
            }
        }
        guard actual == Set(manifest.files.keys) else { throw SetupError("The installer has missing or unexpected files.") }
        progress("Verifying the signed browser…")
        try verifyApp(app)
        progress("Verifying Cisco's antivirus package…")
        let hash = try MalwareIO.hashFile(vendor)
        guard hash.0 == manifest.vendorPackageSHA256, hash.1 == manifest.vendorPackageBytes else { throw SetupError("The antivirus installer failed its integrity check.") }
        let signature = try run("/usr/sbin/pkgutil", ["--check-signature", vendor.path])
        let normalized = signature.output.filter { !$0.isWhitespace }
        guard signature.output.contains("Status: signed by a developer certificate issued by Apple for distribution"),
              signature.output.contains("Developer ID Installer: Cisco (DE8Y96K9QP)"),
              normalized.uppercased().contains(SetupPolicy.vendorLeaf) else { throw SetupError("Cisco's antivirus package signature is not trusted.") }
    }
    func verifyApp(_ candidate: URL) throws {
        try verifyCode(candidate, identifier: manifest.appBundleId, expectedCDHash: manifest.appCDHash)
        let infoData = try Data(contentsOf: candidate.appendingPathComponent("Contents/Info.plist"))
        guard let info = try PropertyListSerialization.propertyList(from: infoData, format: nil) as? [String: Any],
              info["CFBundleIdentifier"] as? String == manifest.appBundleId,
              info["CFBundleShortVersionString"] as? String == manifest.appVersion,
              info["CFBundleVersion"] as? String == manifest.appBuild else { throw SetupError("The bundled browser version does not match its manifest.") }
        let build = try buildMetadata(candidate)
        guard let phishing = build["phishingProtection"] as? [String: Any], SetupPolicy.strictTrue(phishing["included"]),
              let malware = build["malwareProtection"] as? [String: Any], SetupPolicy.strictTrue(malware["downloadAntivirusIncluded"]),
              FileManager.default.isExecutableFile(atPath: candidate.appendingPathComponent("Contents/Helpers/KumoPhishing.app/Contents/MacOS/KumoPhishingHost").path),
              FileManager.default.fileExists(atPath: candidate.appendingPathComponent("Contents/Helpers/KumoPhishing.app/Contents/Resources/PhishLang/PhishLang.mlmodelc").path) else {
            throw SetupError("This browser is missing its download antivirus or bundled PhishLang protection.")
        }
    }
}
