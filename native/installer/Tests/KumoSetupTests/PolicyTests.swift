import Foundation
import AppKit
import XCTest
import Darwin
@testable import KumoSetup

final class PolicyTests: XCTestCase {
    func testPackageUpgradeRejectsAppAndEngineDowngrades() {
        XCTAssertTrue(PackageInstaller.allowsUpgrade(oldBuild: "202610210003", newBuild: "202610220001", oldEngine: "156.0.8078.47", newEngine: "156.0.8078.47"))
        XCTAssertTrue(PackageInstaller.allowsUpgrade(oldBuild: "1", newBuild: "2", oldEngine: "156.0.8078.47", newEngine: "157.0.1.1"))
        XCTAssertFalse(PackageInstaller.allowsUpgrade(oldBuild: "2", newBuild: "1", oldEngine: "156.0.8078.47", newEngine: "157.0.1.1"))
        XCTAssertFalse(PackageInstaller.allowsUpgrade(oldBuild: "1", newBuild: "2", oldEngine: "156.0.8078.47", newEngine: "155.0.9999.99"))
        XCTAssertFalse(PackageInstaller.allowsUpgrade(oldBuild: "1", newBuild: "2", oldEngine: "unknown", newEngine: "156.0.8078.47"))
    }

    func testCanonicalBuildMetadataAndAmbiguity() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("kumo-metadata-test-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let resources = directory.appendingPathComponent("Contents/Resources")
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        let canonical = resources.appendingPathComponent("kumo-build-info.json")
        try Data("{\"native\":true}".utf8).write(to: canonical)
        XCTAssertTrue(SetupPolicy.strictTrue(try buildMetadata(directory)["native"]))
        let legacy = resources.appendingPathComponent("KumoExtension/build-info.json")
        try FileManager.default.createDirectory(at: legacy.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("{\"native\":true}".utf8).write(to: legacy)
        XCTAssertThrowsError(try buildMetadata(directory))
        try FileManager.default.removeItem(at: canonical)
        XCTAssertTrue(SetupPolicy.strictTrue(try buildMetadata(directory)["native"]))
    }
    func testReadinessRequiresActualJSONBooleansAndReadyReason() {
        let ready: [String: Any] = ["installed": true, "available": true, "automaticUpdates": true, "reason": "ready"]
        XCTAssertTrue(SetupPolicy.ready(ready))
        for field in ["installed", "available", "automaticUpdates"] {
            for value: Any in [false, 0, 1, "true", NSNull()] {
                var changed = ready
                changed[field] = value
                XCTAssertFalse(SetupPolicy.ready(changed), "Accepted non-boolean readiness for \(field)")
            }
            var missing = ready
            missing.removeValue(forKey: field)
            XCTAssertFalse(SetupPolicy.ready(missing))
        }
        var wrongReason = ready
        wrongReason["reason"] = "definitions-missing"
        XCTAssertFalse(SetupPolicy.ready(wrongReason))
    }

    func testRootAndUserModesCannotRunUnderTheWrongAccount() {
        XCTAssertTrue(SetupPolicy.rootAllowed(real: 0, effective: 0))
        for (real, effective): (uid_t, uid_t) in [(501, 0), (0, 501), (501, 501)] {
            XCTAssertFalse(SetupPolicy.rootAllowed(real: real, effective: effective))
        }
        XCTAssertTrue(SetupPolicy.userAllowed(real: 501, effective: 501, console: 501))
        for (real, effective, console): (uid_t, uid_t, uid_t) in [
            (0, 0, 501), (501, 0, 501), (502, 502, 501), (501, 501, 502), (500, 500, 500),
        ] {
            XCTAssertFalse(SetupPolicy.userAllowed(real: real, effective: effective, console: console))
        }
    }

    func testManifestPathsCannotEscapeOrInjectControlCharacters() {
        for path in ["payload/Kumo.app/Contents/Info.plist", "payload/definitions/daily-28160.cvd.sign", "payload/a folder/a file"] {
            XCTAssertTrue(SetupPolicy.safePayloadPath(path), path)
        }
        for path in ["/payload/a", "payload", "payload/", "payload//a", "payload/./a", "payload/../a",
                     "payload/a/../b", "other/a", "payload/a\0b", "payload/a\nb", "payload/a\rb"] {
            XCTAssertFalse(SetupPolicy.safePayloadPath(path), path)
        }
    }

    func testDefinitionNamesCannotSelectUnrelatedFiles() {
        for name in ["main.cvd", "daily.cvd", "bytecode.cvd", "daily-28160.cvd.sign"] {
            XCTAssertTrue(UserInitializer.allowedDefinition(name), name)
        }
        for name in ["freshclam.dat", "../daily.cvd", "/tmp/daily.cvd", "other.cvd", "daily-1.cvd.sign\n", "daily--1.cvd.sign"] {
            XCTAssertFalse(UserInitializer.allowedDefinition(name), name)
        }
    }

    func manifest(files: [String: String]? = nil, team: String = "PV65ZWXCWX", appBuild: String = "202610210003") -> InstallerManifest {
        let required = ["payload/Kumo.app/Contents/Info.plist", "payload/clamav.pkg", "payload/definitions/main.cvd",
                        "payload/definitions/daily.cvd", "payload/definitions/bytecode.cvd", "payload/clamav-source.tar.gz"]
        return InstallerManifest(
            schemaVersion: 1, teamId: team, appBundleId: "app.kumo.browser", appVersion: "0.1.2",
            appBuild: appBuild, appCDHash: String(repeating: "a", count: 40),
            files: files ?? Dictionary(uniqueKeysWithValues: required.map { ($0, String(repeating: "b", count: 64)) }),
            definitionsBuiltAt: "2026-10-21T06:26:00Z", vendorPackageSHA256: SetupPolicy.vendorHash,
            vendorPackageBytes: 166_772_489, vendorInstallerLeafSHA256: SetupPolicy.vendorLeaf
        )
    }

    func testMissingRequiredPayloadOrWrongTrustIdentityCannotValidate() throws {
        let valid = manifest()
        XCTAssertNoThrow(try valid.validate())
        for required in valid.files.keys {
            var incomplete = valid.files
            incomplete.removeValue(forKey: required)
            XCTAssertThrowsError(try manifest(files: incomplete).validate(), required)
        }
        XCTAssertThrowsError(try manifest(team: "OTHERTEAM1").validate())
        XCTAssertThrowsError(try manifest(appBuild: "../untrusted").validate())
        var traversal = valid.files
        traversal["payload/../outside"] = String(repeating: "b", count: 64)
        XCTAssertThrowsError(try manifest(files: traversal).validate())
        var badHash = valid.files
        badHash["payload/clamav.pkg"] = "not-a-hash"
        XCTAssertThrowsError(try manifest(files: badHash).validate())
    }

    func testShellQuotingPreservesSpacesQuotesDollarsBackticksAndNewlines() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("kumo-quoting-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let marker = directory.appendingPathComponent("must-not-exist")
        let literal = "a folder ' single quote \" double $HOME `printf injected` $(touch " + marker.path + ");\\end\nnext line"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "printf '%s' " + SetupPolicy.quoteShell(literal)]
        let output = Pipe()
        process.standardOutput = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), literal)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    func testAppleScriptQuotingRoundTripsLiteralStringMetacharacters() throws {
        let literal = "a folder ' $HOME `literal` $(literal) a\"b\\c\nd\re"
        let script = try XCTUnwrap(NSAppleScript(source: "return " + SetupPolicy.quoteAppleScript(literal)))
        var error: NSDictionary?
        let returned = script.executeAndReturnError(&error)
        XCTAssertNil(error)
        XCTAssertEqual(returned.stringValue, literal)
    }

    func testSignedProductionScannerCompletesBenignScanWhenRequested() throws {
        guard let path = ProcessInfo.processInfo.environment["KUMO_INSTALLER_QA_SCANNER"], !path.isEmpty else {
            throw XCTSkip("Set KUMO_INSTALLER_QA_SCANNER to opt in to a harmless scan using the installed vendor runtime.")
        }
        XCTAssertTrue(path.hasPrefix("/"), "The production scanner path must be absolute.")
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: path))
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("kumo-benign-scan-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        try UserInitializer.benignScan(scanner: URL(fileURLWithPath: path), base: directory)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [], "The harmless test file must be removed.")
    }
}
