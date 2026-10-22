import Foundation
import Darwin
import XCTest
@testable import KumoSetup

final class DefinitionTransactionTests: XCTestCase {
    enum FixtureFailure: Error { case update, finalScan }
    private func fixture(_ body: (URL, URL, URL) throws -> Void) throws {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("kumo-definition-transaction-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: base) }
        let incoming = base.appendingPathComponent(".definitions-owned"), destination = base.appendingPathComponent("database")
        try directory(incoming, contents: "incoming")
        try body(base, incoming, destination)
    }
    private func directory(_ path: URL, contents: String) throws {
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try Data(contents.utf8).write(to: path.appendingPathComponent("daily.cvd"))
    }
    private func contents(_ path: URL) throws -> String { try String(contentsOf: path.appendingPathComponent("daily.cvd"), encoding: .utf8) }

    func testFailureAfterPublishingRestoresExactPriorDirectory() throws {
        try fixture { _, incoming, destination in
            try directory(destination, contents: "previous")
            var before = stat(); XCTAssertEqual(lstat(destination.path, &before), 0)
            let transaction = try DefinitionDirectoryTransaction(prepared: incoming, destination: destination)
            XCTAssertThrowsError(try transaction.perform {
                XCTAssertEqual(try self.contents(destination), "incoming")
                XCTAssertEqual(try self.contents(incoming), "previous", "Old data remains until full readiness")
                throw FixtureFailure.update
            })
            var after = stat(); XCTAssertEqual(lstat(destination.path, &after), 0)
            XCTAssertEqual(after.st_ino, before.st_ino)
            XCTAssertEqual(try contents(destination), "previous")
            XCTAssertFalse(FileManager.default.fileExists(atPath: incoming.path))
        }
    }

    func testFinalReadinessFailureRestoresEvenAfterNewDefinitionsWereUpdated() throws {
        try fixture { _, incoming, destination in
            try directory(destination, contents: "previous")
            let transaction = try DefinitionDirectoryTransaction(prepared: incoming, destination: destination)
            XCTAssertThrowsError(try transaction.perform {
                try Data("updated incoming".utf8).write(to: destination.appendingPathComponent("daily.cvd"))
                XCTAssertEqual(try self.contents(incoming), "previous")
                throw FixtureFailure.finalScan
            })
            XCTAssertEqual(try contents(destination), "previous")
        }
    }

    func testSuccessCommitsOnlyAfterFullReadinessAndRemovesOldBackup() throws {
        try fixture { _, incoming, destination in
            try directory(destination, contents: "previous")
            let transaction = try DefinitionDirectoryTransaction(prepared: incoming, destination: destination)
            var finalReadinessRan = false
            try transaction.perform {
                XCTAssertEqual(try self.contents(incoming), "previous")
                finalReadinessRan = true
            }
            XCTAssertTrue(finalReadinessRan)
            XCTAssertEqual(try contents(destination), "incoming")
            XCTAssertFalse(FileManager.default.fileExists(atPath: incoming.path))
            XCTAssertThrowsError(try transaction.perform {})
        }
    }

    func testFirstInstallFailureWithdrawsNewDirectory() throws {
        try fixture { _, incoming, destination in
            let transaction = try DefinitionDirectoryTransaction(prepared: incoming, destination: destination)
            XCTAssertThrowsError(try transaction.perform { throw FixtureFailure.finalScan })
            XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: incoming.path))
        }
    }

    func testFirstInstallSuccessPublishesWithoutInventingPreviousDirectory() throws {
        try fixture { _, incoming, destination in
            let transaction = try DefinitionDirectoryTransaction(prepared: incoming, destination: destination)
            try transaction.perform { XCTAssertFalse(FileManager.default.fileExists(atPath: incoming.path)) }
            XCTAssertEqual(try contents(destination), "incoming")
        }
    }

    func testChangedDestinationBeforePublicationIsNeverOverwritten() throws {
        try fixture { base, incoming, destination in
            try directory(destination, contents: "previous")
            let transaction = try DefinitionDirectoryTransaction(prepared: incoming, destination: destination)
            let moved = base.appendingPathComponent("moved-previous")
            try FileManager.default.moveItem(at: destination, to: moved)
            try directory(destination, contents: "unrelated replacement")
            XCTAssertThrowsError(try transaction.perform { XCTFail("Must not run readiness") })
            XCTAssertEqual(try contents(destination), "unrelated replacement")
            XCTAssertEqual(try contents(moved), "previous")
            XCTAssertEqual(try contents(incoming), "incoming")
        }
    }

    func testUnsafeRollbackPreservesBackupAndDoesNotClobberReplacement() throws {
        try fixture { base, incoming, destination in
            try directory(destination, contents: "previous")
            let transaction = try DefinitionDirectoryTransaction(prepared: incoming, destination: destination)
            let moved = base.appendingPathComponent("moved-new")
            XCTAssertThrowsError(try transaction.perform {
                try FileManager.default.moveItem(at: destination, to: moved)
                try self.directory(destination, contents: "unrelated replacement")
                throw FixtureFailure.finalScan
            }) { error in XCTAssertTrue(error.localizedDescription.contains("transaction is preserved")) }
            XCTAssertEqual(try contents(destination), "unrelated replacement")
            XCTAssertEqual(try contents(incoming), "previous", "Unsafe rollback must retain the previous backup")
            XCTAssertEqual(try contents(moved), "incoming")
        }
    }

    func testChangedParentPreventsRollbackAndPreservesBothTrees() throws {
        try fixture { base, incoming, destination in
            try directory(destination, contents: "previous")
            let transaction = try DefinitionDirectoryTransaction(prepared: incoming, destination: destination)
            let moved = base.appendingPathExtension("moved")
            defer { try? FileManager.default.removeItem(at: moved) }
            XCTAssertThrowsError(try transaction.perform {
                try FileManager.default.moveItem(at: base, to: moved)
                try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
                try self.directory(destination, contents: "unrelated replacement")
                throw FixtureFailure.finalScan
            }) { error in
                XCTAssertTrue(error.localizedDescription.contains(moved.appendingPathComponent(incoming.lastPathComponent).path))
            }
            XCTAssertEqual(try contents(destination), "unrelated replacement")
            XCTAssertEqual(try contents(moved.appendingPathComponent(incoming.lastPathComponent)), "previous")
            XCTAssertEqual(try contents(moved.appendingPathComponent(destination.lastPathComponent)), "incoming")
        }
    }

    func testSymlinksAndDifferentParentAreRejected() throws {
        try fixture { base, incoming, destination in
            let elsewhere = base.appendingPathComponent("elsewhere")
            try directory(elsewhere, contents: "outside")
            try FileManager.default.createSymbolicLink(at: destination, withDestinationURL: elsewhere)
            XCTAssertThrowsError(try DefinitionDirectoryTransaction(prepared: incoming, destination: destination))
            XCTAssertThrowsError(try DefinitionDirectoryTransaction(prepared: incoming, destination: elsewhere.appendingPathComponent("database")))
            XCTAssertEqual(try contents(elsewhere), "outside")
        }
    }
}

final class RetiredInstallerRouteTests: XCTestCase {
    func testActualHelperDeclaresRetiredStandaloneAndFullDefinitionRollbackPolicy() throws {
        let executable = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("KumoSetup")
        let process = Process(), output = Pipe()
        process.executableURL = executable; process.arguments = ["--package-policy"]
        process.standardOutput = output; process.environment = ["PATH": "/usr/bin:/bin"]
        try process.run()
        let bytes = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        let policy = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        XCTAssertEqual(policy["standaloneInstaller"] as? Bool, false)
        XCTAssertEqual(policy["definitionRollbackUntilUserReady"] as? Bool, true)
    }

    func testActualHelperRejectsDirectOpenAndRetiredAdminModeWithoutPayloads() throws {
        let executable = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("KumoSetup")
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: executable.path))
        for arguments in [[], ["--install-root"]] {
            let process = Process(), output = Pipe(), errors = Pipe()
            process.executableURL = executable; process.arguments = arguments
            process.standardOutput = output; process.standardError = errors
            process.environment = ["PATH": "/usr/bin:/bin"]
            try process.run()
            let bytes = output.fileHandleForReading.readDataToEndOfFile()
            _ = errors.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
            XCTAssertNotEqual(process.terminationStatus, 0)
            let result = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            XCTAssertEqual(result["ok"] as? Bool, false)
            XCTAssertTrue((result["reason"] as? String)?.contains("standard Kumo .pkg installer") == true)
        }
    }
}

final class DefinitionRecoveryMessageTests: XCTestCase {
    private let recovery = DefinitionDirectoryTransaction.recoveryPrefix + "/owned/private/definitions-backup" + DefinitionDirectoryTransaction.recoverySuffix
    private func output(_ values: [String: Any]) throws -> String {
        String(decoding: try JSONSerialization.data(withJSONObject: values), as: UTF8.self)
    }
    func testOnlyStructuredRecoverySurvivesBrowserRollbackMessage() throws {
        let json = try output(["ok": false, "status": "failed", "reason": "DO_NOT_FORWARD_ARGV_SECRET", "recoveryReason": recovery])
        let parsed = PackageInstaller.initializationRecoveryReason("generic command output\n" + json + "\ntrailing stderr\n")
        XCTAssertEqual(parsed, recovery)
        let message = PackageInstaller.restoredFailureMessage(recoveryReason: parsed)
        XCTAssertTrue(message.contains(recovery))
        XCTAssertTrue(message.contains("previous browser state was restored"))
        XCTAssertFalse(message.contains("DO_NOT_FORWARD_ARGV_SECRET"))
    }
    func testGenericOversizedControlOrUntrustedShapeCannotReachInstallerMessage() throws {
        XCTAssertNil(PackageInstaller.initializationRecoveryReason(recovery))
        for reason in ["generic process output", recovery + "\n", DefinitionDirectoryTransaction.recoveryPrefix + String(repeating: "x", count: 2049) + DefinitionDirectoryTransaction.recoverySuffix] {
            let json = try output(["ok": false, "status": "failed", "reason": "ignored", "recoveryReason": reason])
            XCTAssertNil(PackageInstaller.initializationRecoveryReason(json))
            XCTAssertFalse(PackageInstaller.restoredFailureMessage(recoveryReason: reason).contains(reason))
        }
        for ok: Any in [true, 0, "false"] {
            XCTAssertNil(PackageInstaller.initializationRecoveryReason(try output(["ok": ok, "status": "failed", "reason": "ignored", "recoveryReason": recovery])))
        }
        XCTAssertNil(PackageInstaller.initializationRecoveryReason(try output(["ok": false, "status": "failed", "reason": "ignored", "recoveryReason": recovery, "extra": true])))
    }
}
