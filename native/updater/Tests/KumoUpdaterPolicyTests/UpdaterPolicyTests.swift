import XCTest
import Foundation
import Darwin
@testable import KumoUpdaterPolicy

final class UpdaterPolicyTests: XCTestCase {
    var root: URL!
    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("kumo-updater-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: root) }
    func configuration(_ changes: [String: Any] = [:]) throws -> Data {
        var value: [String: Any] = ["schemaVersion": 1, "repository": "morrigangirl/kumo", "version": "0.1.0", "build": "202610190001",
                                  "feedURL": ReleaseConfiguration.feedURL, "publicEDKey": NSNull()]
        value.merge(changes) { _, new in new }; return try JSONSerialization.data(withJSONObject: value)
    }
    func fixture(_ changes: [String: Any] = [:]) throws -> (URL, URL) {
        let app = root.appendingPathComponent("Kumo.app"), companion = app.appendingPathComponent("Contents/Helpers/KumoUpdater.app")
        try FileManager.default.createDirectory(at: companion.appendingPathComponent("Contents"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: app.appendingPathComponent("Contents/Resources"), withIntermediateDirectories: true)
        let info: [String: Any] = ["CFBundleIdentifier": "app.kumo.browser", "CFBundleVersion": "202610190001", "CFBundleShortVersionString": "0.1.0"]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: app.appendingPathComponent("Contents/Info.plist"))
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": "app.kumo.browser.updater"], format: .xml, options: 0).write(to: companion.appendingPathComponent("Contents/Info.plist"))
        try configuration(changes).write(to: app.appendingPathComponent("Contents/Resources/kumo-update-config.json"))
        try UpdateLease.contents.write(to: app.appendingPathComponent("Contents/Resources/kumo-update-lock"))
        return (app, companion)
    }
    func testDevelopmentConfigurationDisablesUpdatesWithoutKey() throws {
        let (app, companion) = try fixture()
        let host = try UpdateHost(companion: companion)
        XCTAssertEqual(host.application.path, app.path); XCTAssertFalse(host.configuration.configured)
        XCTAssertThrowsError(try host.verifyProduction())
    }
    func testConfiguredPublicKeyNeverEnablesUnsignedDevelopmentBundle() throws {
        let (app, companion) = try fixture(["publicEDKey": Data(repeating: 1, count: 32).base64EncodedString(), "enabled": true])
        let infoURL = app.appendingPathComponent("Contents/Info.plist")
        var info = try PropertyListSerialization.propertyList(from: Data(contentsOf: infoURL), format: nil) as! [String: Any]
        info.merge(["SUFeedURL": ReleaseConfiguration.feedURL, "SUPublicEDKey": Data(repeating: 1, count: 32).base64EncodedString(),
                    "SURequireSignedFeed": true, "SUVerifyUpdateBeforeExtraction": true, "SUSignedFeedFailureExpirationInterval": 0,
                    "SUAllowsAutomaticUpdates": false, "SUEnableSystemProfiling": false]) { _, new in new }
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: infoURL)
        let host = try UpdateHost(companion: companion)
        XCTAssertTrue(host.configuration.configured)
        XCTAssertThrowsError(try host.verifyProduction()) { XCTAssertEqual($0 as? UpdatePolicyError, .invalidSignature) }
    }
    func testConfigurationPinsRepositoryAndFeedAndTeam() throws {
        for change in [["repository": "other/kumo"], ["feedURL": "http://github.com/morrigangirl/kumo/releases/latest/download/appcast.xml"],
                       ["feedURL": "https://github.com/morrigangirl/kumo.evil/releases/latest/download/appcast.xml"], ["teamId": "AAAAAAAAAA"]] {
            XCTAssertThrowsError(try ReleaseConfiguration(data: configuration(change)))
        }
    }
    func testConfigurationRequiresExactEd25519PublicKeyEncoding() throws {
        for key in ["", Data(repeating: 0, count: 31).base64EncodedString(), Data(repeating: 0, count: 33).base64EncodedString(), "\n" + Data(repeating: 1, count: 32).base64EncodedString()] {
            XCTAssertThrowsError(try ReleaseConfiguration(data: configuration(["publicEDKey": key])))
        }
        XCTAssertTrue(try ReleaseConfiguration(data: configuration(["publicEDKey": Data(repeating: 1, count: 32).base64EncodedString(), "enabled": true])).configured)
    }
    func testConfigurationRejectsMalformedVersionsAndOversizedJSON() throws {
        for change in [["version": "0.1.0; open x"], ["build": "0"], ["build": "1.1"], ["schemaVersion": 2]] as [[String: Any]] {
            XCTAssertThrowsError(try ReleaseConfiguration(data: configuration(change)))
        }
        XCTAssertThrowsError(try ReleaseConfiguration(data: Data(repeating: 32, count: 16_385)))
    }
    func testHelperMustBeOriginalNestedBundleAndVersionMustMatch() throws {
        let (_, companion) = try fixture(["build": "202610190002"])
        XCTAssertThrowsError(try UpdateHost(companion: companion))
        XCTAssertThrowsError(try UpdateHost(companion: root.appendingPathComponent("KumoUpdater.app")))
        let alias = root.appendingPathComponent("Alias.app")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: companion)
        XCTAssertThrowsError(try UpdateHost(companion: alias))
    }
    func testProcessInventoryExcludesOnlyOwnCompanionWithPathBoundaries() throws {
        let (app, companion) = try fixture()
        XCTAssertTrue(updateProcessBlocksInstall(executable: app.appendingPathComponent("Contents/MacOS/Chromium"), application: app, companion: companion))
        XCTAssertTrue(updateProcessBlocksInstall(executable: app.appendingPathComponent("Contents/Frameworks/Chromium Helper.app/Contents/MacOS/Chromium Helper"), application: app, companion: companion))
        XCTAssertFalse(updateProcessBlocksInstall(executable: companion.appendingPathComponent("Contents/MacOS/KumoUpdater"), application: app, companion: companion))
        XCTAssertTrue(updateProcessBlocksInstall(executable: URL(fileURLWithPath: companion.path + "-evil/Contents/MacOS/evil"), application: app, companion: companion))
        XCTAssertFalse(updateProcessBlocksInstall(executable: URL(fileURLWithPath: app.path + "-other/Contents/MacOS/Chromium"), application: app, companion: companion))
    }
    func testLeaseRejectsSymlinksHardlinksWritableOrWrongResource() throws {
        let (app, _) = try fixture(), lock = app.appendingPathComponent("Contents/Resources/kumo-update-lock")
        try Data("bad\n".utf8).write(to: lock); XCTAssertThrowsError(try UpdateLease(application: app))
        try UpdateLease.contents.write(to: lock)
        XCTAssertEqual(chmod(lock.path, 0o666), 0); XCTAssertThrowsError(try UpdateLease(application: app))
        XCTAssertEqual(chmod(lock.path, 0o644), 0)
        let duplicate = root.appendingPathComponent("hardlink"); XCTAssertEqual(link(lock.path, duplicate.path), 0)
        XCTAssertThrowsError(try UpdateLease(application: app)); try FileManager.default.removeItem(at: duplicate)
        let target = root.appendingPathComponent("target"); try FileManager.default.moveItem(at: lock, to: target)
        try FileManager.default.createSymbolicLink(at: lock, withDestinationURL: target); XCTAssertThrowsError(try UpdateLease(application: app))
    }
    func compileProbe() throws -> URL {
        let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Fixtures/lease-probe.c")
        let binary = root.appendingPathComponent("lease-probe"), compiler = Process()
        compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun"); compiler.arguments = ["clang", "-Wall", "-Werror", source.path, "-o", binary.path]
        try compiler.run(); compiler.waitUntilExit(); XCTAssertEqual(compiler.terminationStatus, 0); return binary
    }
    func testCompiledBrowserSharedLeaseSurvivesExecAndBlocksInstaller() throws {
        let (app, companion) = try fixture(), compiled = try compileProbe(), child = Process(), input = Pipe(), output = Pipe()
        let binary = app.appendingPathComponent("Contents/MacOS/Chromium")
        try FileManager.default.createDirectory(at: binary.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: compiled, to: binary)
        child.executableURL = binary; child.arguments = ["inherit", app.appendingPathComponent("Contents/Resources/kumo-update-lock").path]
        child.standardInput = input; child.standardOutput = output
        try child.run()
        defer { if child.isRunning { child.terminate(); child.waitUntilExit() } }
        XCTAssertEqual(String(decoding: output.fileHandleForReading.availableData, as: UTF8.self), "ready\n")
        XCTAssertThrowsError(try UpdateLease(application: app))
        XCTAssertEqual(try runningBrowserProcesses(application: app, companion: companion), [child.processIdentifier])
        try input.fileHandleForWriting.close(); child.waitUntilExit(); XCTAssertEqual(child.terminationStatus, 0)
        let lease = try UpdateLease(application: app); lease.release()
    }
    func testCompiledBrowserCannotLaunchWhileInstallerHasExclusiveLease() throws {
        let (app, _) = try fixture(), binary = try compileProbe(), lease = try UpdateLease(application: app)
        let child = Process(); child.executableURL = binary; child.arguments = ["try-sh", app.appendingPathComponent("Contents/Resources/kumo-update-lock").path]
        try child.run(); child.waitUntilExit(); XCTAssertEqual(child.terminationStatus, 73)
        XCTAssertThrowsError(try UpdateLease(application: app)); lease.release()
        let next = Process(); next.executableURL = binary; next.arguments = child.arguments
        try next.run(); next.waitUntilExit(); XCTAssertEqual(next.terminationStatus, 0)
    }
    func testPriorAmbiguousInstallerCannotBeReleasedByLaterAuthorizationCancel() throws {
        var policy = InstallationLeasePolicy(); policy.record(.authorized); policy.record(.extractionStarted); policy.record(.cycleEnded)
        XCTAssertTrue(policy.ambiguousOutcome)
        policy.record(.authorized); policy.record(.extractionStarted)
        XCTAssertFalse(policy.record(.noInstallerLaunched)); XCTAssertEqual(policy.phase, .unconfirmed)
        XCTAssertFalse(policy.record(.cycleEnded)); XCTAssertTrue(policy.ambiguousOutcome)
        XCTAssertTrue(policy.record(.installationCompleted))
    }
    func testHandoffRequiresExactLiveParentAndBoundedPID() throws {
        XCTAssertEqual(try validatedHandoffParent("123", actualParent: 123), 123)
        for value in ["1", "0", "-123", "0123", "123 extra", "2147483648", "9999999999999999999", "124"] {
            XCTAssertThrowsError(try validatedHandoffParent(value, actualParent: 123))
        }
    }
    func testDefinitiveAuthorizationCancelReleasesOnlyBeforeInstallerHandoff() throws {
        let canceled = NSError(domain: "SUSparkleErrorDomain", code: 4007)
        XCTAssertTrue(isDefinitivePrelaunchCancellation(canceled))
        XCTAssertFalse(isDefinitivePrelaunchCancellation(NSError(domain: "OtherDomain", code: 4007)))
        XCTAssertFalse(isDefinitivePrelaunchCancellation(NSError(domain: "SUSparkleErrorDomain", code: 4005)))
        XCTAssertFalse(isDefinitivePrelaunchCancellation(NSError(domain: "SUSparkleErrorDomain", code: 4005, userInfo: [NSUnderlyingErrorKey: canceled])))
        XCTAssertFalse(isDefinitivePrelaunchCancellation(nil))
        var beforeLaunch = InstallationLeasePolicy(); beforeLaunch.record(.authorized); beforeLaunch.record(.extractionStarted)
        XCTAssertTrue(beforeLaunch.record(.noInstallerLaunched))
        XCTAssertTrue(beforeLaunch.record(.cycleEnded)); XCTAssertEqual(beforeLaunch.phase, .idle)
        var afterHandoff = InstallationLeasePolicy(); afterHandoff.record(.authorized); afterHandoff.record(.extractionStarted); afterHandoff.record(.installerLaunched)
        XCTAssertFalse(afterHandoff.record(.noInstallerLaunched))
        XCTAssertFalse(afterHandoff.record(.cycleEnded)); XCTAssertEqual(afterHandoff.phase, .unconfirmed)
    }
    func testExtractionErrorAndCancellationNeverReleaseLeaseWithoutCompletion() throws {
        for ending in [InstallationLeasePolicy.Event.cycleEnded, .revalidationFailed] {
            var policy = InstallationLeasePolicy()
            policy.record(.authorized); policy.record(.extractionStarted)
            XCTAssertFalse(policy.record(ending)); XCTAssertEqual(policy.phase, .unconfirmed)
            XCTAssertFalse(policy.record(.cycleEnded))
            XCTAssertFalse(policy.record(.authorized))
            XCTAssertTrue(policy.record(.installationCompleted)); XCTAssertEqual(policy.phase, .completed)
        }
    }
    func testPredownloadCancelAndRevalidationFailureReleaseLease() throws {
        for ending in [InstallationLeasePolicy.Event.cycleEnded, .revalidationFailed] {
            var policy = InstallationLeasePolicy(); policy.record(.authorized)
            XCTAssertTrue(policy.record(ending)); XCTAssertEqual(policy.phase, .idle)
        }
    }
    func testLostCompletionRecoveryRejectsOldAndUnsignedReplacement() throws {
        let (app, companion) = try fixture(["publicEDKey": Data(repeating: 1, count: 32).base64EncodedString(), "enabled": true])
        XCTAssertFalse(try verifyCommittedReplacement(application: app, companion: companion, oldBuild: "202610190001", expectedBuild: "202610190001"))
        XCTAssertFalse(try verifyCommittedReplacement(application: app, companion: companion, oldBuild: "202610180001", expectedBuild: "202610200001"))
        XCTAssertThrowsError(try verifyCommittedReplacement(application: app, companion: companion, oldBuild: "202610180001", expectedBuild: "202610190001"))
    }
    func testAllStageChoiceAndLeaseCombinationsNeverPreserveAnUnguardedInstaller() throws {
        for stage in InstallationStage.allCases {
            for choice in InstallationChoice.allCases {
                for held in [false, true] {
                    let result = safeInstallationChoice(choice, stage: stage, leaseHeld: held)
                    if stage == .installing {
                        XCTAssertEqual(result, choice == .install && held ? .install : .skip)
                        XCTAssertNotEqual(result, .dismiss)
                    } else { XCTAssertEqual(result, choice) }
                }
            }
        }
    }
    func testArchiveURLRequiresImmutableMatchingGitHubReleaseTagAndFilename() throws {
        let valid = "https://github.com/morrigangirl/kumo/releases/download/v0.2.0-202610200001/Kumo-0.2.0-202610200001-macos-arm64.zip"
        XCTAssertTrue(validReleaseArchiveURL(URL(string: valid)!, expectedBuild: "202610200001"))
        XCTAssertFalse(validReleaseArchiveURL(URL(string: valid)!, expectedBuild: "202610200002"))
        for url in [valid.replacingOccurrences(of: "https:", with: "http:"), valid + "?download=1", valid + "#fragment", valid.replacingOccurrences(of: "github.com", with: "github.com.evil"), valid.replacingOccurrences(of: "github.com", with: "user@github.com"), valid.replacingOccurrences(of: "/v0.2.0-", with: "/latest-"), valid.replacingOccurrences(of: "Kumo-0.2.0", with: "Kumo-0.1.0"), valid.replacingOccurrences(of: "/download/", with: "/download//"), valid.replacingOccurrences(of: "Kumo-", with: "%2e%2e%2fKumo-"), valid.replacingOccurrences(of: "-macos-arm64.zip", with: ".pkg")] {
            XCTAssertFalse(validReleaseArchiveURL(URL(string: url)!))
        }
    }
    func testRealProcessInventoryCanRunWithoutReadingProfiles() throws {
        let (app, companion) = try fixture()
        XCTAssertEqual(try runningBrowserProcesses(application: app, companion: companion), [])
    }
}
