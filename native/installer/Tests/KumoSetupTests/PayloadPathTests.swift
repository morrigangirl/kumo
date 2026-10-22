import Foundation
import CryptoKit
import Darwin
import XCTest
@testable import KumoSetup

final class PayloadPathTests: XCTestCase {
    final class Fixture {
        let root: URL
        let bundle: URL
        let resources: URL
        var files: [String: String] = [:]
        init() throws {
            root = FileManager.default.temporaryDirectory.appendingPathComponent("kumo-payload-path-" + UUID().uuidString, isDirectory: true)
            bundle = root.appendingPathComponent("Kumo Setup.app", isDirectory: true)
            resources = bundle.appendingPathComponent("Contents/Resources", isDirectory: true)
            for name in ["payload/Kumo.app/Contents/Info.plist", "payload/clamav.pkg", "payload/definitions/main.cvd",
                         "payload/definitions/daily.cvd", "payload/definitions/bytecode.cvd", "payload/clamav-source.tar.gz"] {
                try write(name)
            }
            try saveManifest()
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func write(_ relative: String) throws {
            let file = resources.appendingPathComponent(relative)
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = Data("Harmless synthetic payload, never executed.\n".utf8)
            try data.write(to: file)
            files[relative] = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        }
        func saveManifest() throws {
            let manifest = InstallerManifest(schemaVersion: 1, teamId: SetupPolicy.team, appBundleId: "app.kumo.browser",
                appVersion: "0.2.0", appBuild: "202610210004", appCDHash: String(repeating: "a", count: 40), files: files,
                definitionsBuiltAt: "2026-10-21T06:26:00Z", vendorPackageSHA256: SetupPolicy.vendorHash,
                vendorPackageBytes: 166_772_489, vendorInstallerLeafSHA256: SetupPolicy.vendorLeaf)
            try JSONEncoder().encode(manifest).write(to: resources.appendingPathComponent("installer-manifest.json"))
        }
        func link(_ relative: String, target: String) throws {
            try FileManager.default.createSymbolicLink(atPath: resources.appendingPathComponent(relative).path, withDestinationPath: target)
        }
        func aliases() throws -> [URL] {
            guard let pointer = realpath(bundle.path, nil) else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
            defer { free(pointer) }
            let canonical = String(cString: pointer)
            guard canonical.hasPrefix("/private/var/") else { throw XCTSkip("Native /var temporary-directory aliases required") }
            return [URL(fileURLWithPath: String(canonical.dropFirst("/private".count)), isDirectory: true),
                    URL(fileURLWithPath: canonical, isDirectory: true)]
        }
    }

    func testBothNativeTempAliasesVerifyRelativeInternalFileAndDirectoryLinks() throws {
        let fixture = try Fixture()
        try fixture.write("payload/Kumo.app/Contents/real-directory/target")
        try fixture.link("payload/Kumo.app/Contents/file-link", target: "real-directory/target")
        try fixture.link("payload/Kumo.app/Contents/directory-link", target: "real-directory")
        try fixture.saveManifest()
        let aliases = try fixture.aliases()
        XCTAssertNotEqual(aliases[0].path, aliases[1].path)
        for alias in aliases {
            XCTAssertNoThrow(try Payloads(bundle: alias).verifyFileInventory(), alias.path)
        }
    }

    func testBothAliasesRejectBrokenExternalAndPrefixLookalikeLinks() throws {
        for kind in ["broken", "external", "prefix-lookalike"] {
            let fixture = try Fixture()
            let target: String
            switch kind {
            case "broken": target = "missing-target"
            case "external":
                let outside = fixture.root.appendingPathComponent("outside")
                try Data("outside".utf8).write(to: outside)
                target = outside.path
            default:
                try fixture.write("payload/Kumo.app-lookalike/target")
                target = "../../Kumo.app-lookalike/target"
            }
            try fixture.link("payload/Kumo.app/Contents/link", target: target)
            try fixture.saveManifest()
            for alias in try fixture.aliases() {
                XCTAssertThrowsError(try Payloads(bundle: alias).verifyFileInventory(), kind + " " + alias.path)
            }
        }
    }

    func testOutsideAppLeafIsClassifiedBeforeResolvingItsTarget() throws {
        let fixture = try Fixture()
        let daily = fixture.resources.appendingPathComponent("payload/definitions/daily.cvd")
        try FileManager.default.removeItem(at: daily)
        // All synthetic files share the same bytes/hash. Resolving this leaf
        // before lstat would incorrectly accept it as a manifest regular file.
        try fixture.link("payload/definitions/daily.cvd", target: "main.cvd")
        for alias in try fixture.aliases() {
            XCTAssertThrowsError(try Payloads(bundle: alias).verifyFileInventory(), alias.path)
        }
    }

    func testSymlinkCannotReplaceCanonicalAppDirectoryAnchor() throws {
        let fixture = try Fixture()
        let app = fixture.resources.appendingPathComponent("payload/Kumo.app")
        try FileManager.default.moveItem(at: app, to: fixture.resources.appendingPathComponent("payload/Kumo.app-lookalike"))
        try fixture.link("payload/Kumo.app", target: "Kumo.app-lookalike")
        for alias in try fixture.aliases() {
            XCTAssertThrowsError(try Payloads(bundle: alias).verifyFileInventory(), alias.path)
        }
    }

    func testCanonicalAliasesStillRejectChangedMissingAndUnexpectedFiles() throws {
        for kind in ["changed", "missing", "unexpected"] {
            let fixture = try Fixture()
            let daily = fixture.resources.appendingPathComponent("payload/definitions/daily.cvd")
            switch kind {
            case "changed": try Data("tampered".utf8).write(to: daily)
            case "missing": try FileManager.default.removeItem(at: daily)
            default: try Data("unexpected".utf8).write(to: fixture.resources.appendingPathComponent("payload/unexpected"))
            }
            for alias in try fixture.aliases() {
                XCTAssertThrowsError(try Payloads(bundle: alias).verifyFileInventory(), kind + " " + alias.path)
            }
        }
    }
}
