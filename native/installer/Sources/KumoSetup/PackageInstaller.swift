import Foundation
import Darwin
import KumoMalwareCore

// Apple Installer has already installed the authenticated Cisco components.
// This entry point never starts another Installer session or installs a pkg.
enum PackageInstaller {
    static let receipts = ["com.cisco.ClamAV.libraries", "com.cisco.ClamAV.programs", "com.cisco.ClamAV.documentation"]

    static func allowsUpgrade(oldBuild: String, newBuild: String, oldEngine: String, newEngine: String) -> Bool {
        guard let old = UInt64(oldBuild), let new = UInt64(newBuild), new >= old else { return false }
        func version(_ text: String) -> [UInt64]? {
            let parts = text.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count == 4, parts.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy({ (48...57).contains($0) }) }) else { return nil }
            let values = parts.compactMap { UInt64($0) }
            return values.count == 4 ? values : nil
        }
        guard let previous = version(oldEngine), let incoming = version(newEngine) else { return false }
        for (before, after) in zip(previous, incoming) where before != after { return after > before }
        return true
    }

    static func requireNativePayload(_ app: URL) throws {
        let metadata = try buildMetadata(app)
        guard FileManager.default.fileExists(atPath: app.appendingPathComponent("Contents/Resources/kumo-build-info.json").path),
              let native = metadata["nativeIntegration"] as? [String: Any], SetupPolicy.strictTrue(native["included"]),
              let extensionRequired = native["extensionRequired"] as? NSNumber,
              CFGetTypeID(extensionRequired) == CFBooleanGetTypeID(), !extensionRequired.boolValue,
              let agent = metadata["agentRuntime"] as? [String: Any], SetupPolicy.strictTrue(agent["included"]), SetupPolicy.strictTrue(agent["jitless"]),
              let phishing = metadata["phishingProtection"] as? [String: Any], SetupPolicy.strictTrue(phishing["enabledByDefault"]),
              FileManager.default.isExecutableFile(atPath: app.appendingPathComponent("Contents/Resources/agent-bridge/bin/node").path),
              FileManager.default.fileExists(atPath: app.appendingPathComponent("Contents/Resources/agent-bridge/LICENSE.node").path),
              FileManager.default.fileExists(atPath: app.appendingPathComponent("Contents/Resources/agent-bridge/runtime.json").path) else {
            throw SetupError("This package requires the native Kumo browser and its bundled agent runtime.")
        }
    }

    static func verifyVendorAlreadyInstalled(app: URL) throws {
        for identifier in receipts {
            let result = try run("/usr/sbin/pkgutil", ["--pkg-info-plist", identifier])
            guard let data = result.output.data(using: .utf8),
                  let value = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  value["pkgid"] as? String == identifier, value["pkg-version"] as? String == "1.5.4",
                  value["volume"] as? String == "/" else {
                throw SetupError("Apple Installer has not finished the required antivirus components.")
            }
        }
        let lock = try ClamAVLock(url: app.appendingPathComponent("Contents/Resources/clamav-lock.json"))
        try ClamAVRuntime(lock: lock).verify()
    }

    static func stagedBrowserLease(_ app: URL) throws -> Int32 {
        let file = app.appendingPathComponent("Contents/Resources/kumo-update-lock")
        let descriptor = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw SetupError("The staged browser update lock is missing.") }
        do {
            let state = try MalwareIO.descriptorState(descriptor)
            let expected = Data("Kumo update coordination v1\n".utf8)
            var bytes = [UInt8](repeating: 0, count: expected.count + 1)
            guard state.st_uid == 0, state.st_nlink == 1, state.st_mode & 0o022 == 0,
                  state.st_size == expected.count,
                  Darwin.read(descriptor, &bytes, bytes.count) == expected.count,
                  Data(bytes.prefix(expected.count)) == expected,
                  flock(descriptor, LOCK_EX | LOCK_NB) == 0 else { throw SetupError("The staged browser update lock cannot be verified.") }
            return descriptor
        } catch { close(descriptor); throw error }
    }

    static func persistentSetup(payloads: Payloads) throws -> URL {
        let base = URL(fileURLWithPath: "/Library/Application Support/Kumo/Setup", isDirectory: true)
        let bundle = base.appendingPathComponent(payloads.manifest.appBuild, isDirectory: true).appendingPathComponent("Kumo Setup.app", isDirectory: true)
        var parent = bundle
        while parent.path != "/" {
            let state = try directoryState(parent)
            guard state.st_uid == 0, state.st_mode & 0o022 == 0 else { throw SetupError("The installed setup helper has unsafe ownership or permissions.") }
            parent.deleteLastPathComponent()
        }
        let details = try run("/usr/bin/codesign", ["--display", "--verbose=4", payloads.bundle.path])
        let prefix = "CDHash="
        guard let hash = details.output.split(separator: "\n").first(where: { $0.hasPrefix(prefix) }).map({ String($0.dropFirst(prefix.count)) }),
              hash.count == 40, hash.lowercased().utf8.allSatisfy(SetupPolicy.hex) else { throw SetupError("The setup helper's signed identity cannot be read.") }
        try verifyCode(bundle, identifier: "app.kumo.setup", expectedCDHash: hash)
        let installed = try Payloads(bundle: bundle)
        guard installed.manifest.appBuild == payloads.manifest.appBuild,
              installed.manifest.appCDHash == payloads.manifest.appCDHash else { throw SetupError("The user setup helper differs from this package.") }
        return bundle
    }

    static func initializeConsoleUser(payloads: Payloads, user: uid_t) throws {
        let setup = try persistentSetup(payloads: payloads)
        let executable = setup.appendingPathComponent("Contents/MacOS/KumoSetup")
        let result = try FixedCommand.run(URL(fileURLWithPath: "/bin/launchctl"), ["asuser", String(user), "/usr/bin/sudo", "-u", "#" + String(user), "--", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", executable.path, "--initialize-user"], timeout: 1200, maximumOutput: 1_048_576)
        guard result.code == 0, !result.timedOut, !result.outputLimited else {
            let recovery = !result.timedOut && !result.outputLimited ? initializationRecoveryReason(result.output) : nil
            throw SetupError("The logged-in account's protection setup did not confirm readiness.", recoveryReason: recovery)
        }
        guard let last = result.output.split(separator: "\n").last,
              let response = try JSONSerialization.jsonObject(with: Data(last.utf8)) as? [String: Any],
              SetupPolicy.strictTrue(response["ok"]), response["status"] as? String == "ready",
              SetupPolicy.strictTrue(response["benignScanPassed"]), SetupPolicy.strictTrue(response["automaticUpdates"]),
              try consoleUID() == user else {
            throw SetupError("The logged-in account's protection setup did not confirm readiness.")
        }
    }

    static func validRecoveryReason(_ reason: String?) -> String? {
        guard let reason, reason.utf8.count <= 2048,
              reason.hasPrefix(DefinitionDirectoryTransaction.recoveryPrefix),
              reason.hasSuffix(DefinitionDirectoryTransaction.recoverySuffix),
              !reason.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        return reason
    }

    static func initializationRecoveryReason(_ output: String) -> String? {
        // Forward only our signed helper's bounded structured recovery notice.
        // Generic command output, process errors and arbitrary reasons never
        // become part of the Installer-facing rollback message.
        for line in output.split(separator: "\n").suffix(16).reversed() {
            guard line.utf8.count <= 8192,
                  let value = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                  Set(value.keys) == Set(["ok", "status", "reason", "recoveryReason"]),
                  let ok = value["ok"] as? NSNumber, CFGetTypeID(ok) == CFBooleanGetTypeID(), !ok.boolValue,
                  value["status"] as? String == "failed",
                  let reason = validRecoveryReason(value["recoveryReason"] as? String) else { continue }
            return reason
        }
        return nil
    }

    static func restoredFailureMessage(recoveryReason: String?) -> String {
        let message = "Kumo protection setup did not complete. The previous browser state was restored. Cisco's separate antivirus components remain installed. Retry the installer to continue."
        return validRecoveryReason(recoveryReason).map { message + " " + $0 } ?? message
    }

    static func install(payloads: Payloads) throws {
        guard SetupPolicy.rootAllowed() else { throw SetupError("System installation requires macOS administrator authorization.") }
        let user = try consoleUID()
        try RootInstaller.requireRootSnapshot(payloads.bundle)
        try RootInstaller.checkHost()
        try payloads.verify()
        try requireNativePayload(payloads.app)
        // Both receipt and actual pinned runtime must succeed BEFORE publication.
        try verifyVendorAlreadyInstalled(app: payloads.app)
        try RootInstaller.assertBrowserClosed()
        let previousLease = try RootInstaller.acquireInstalledLease()
        defer { if previousLease >= 0 { close(previousLease) } }
        let support = try RootInstaller.secureDirectory(URL(fileURLWithPath: "/Library/Application Support/Kumo", isDirectory: true))
        let stage = try RootInstaller.privateDirectory(parent: support, prefix: ".package-")
        var cleanup = true
        defer { if cleanup { try? FileManager.default.removeItem(at: stage) } }
        let staged = stage.appendingPathComponent("Kumo.app", isDirectory: true)
        _ = try run("/usr/bin/ditto", ["--rsrc", "--extattr", "--noacl", payloads.app.path, staged.path], timeout: 600)
        try RootInstaller.rootOwnership(staged)
        try payloads.verifyApp(staged)
        // Acquire the NEW sealed resource's EX lease before rename. It follows
        // the published app atomically and prevents browser launch until ready.
        let newLease = try stagedBrowserLease(staged)
        defer { close(newLease) }
        let destination = SetupPolicy.destination
        var previous = stat()
        let hadPrevious = lstat(destination.path, &previous) == 0
        if hadPrevious {
            guard previous.st_mode & S_IFMT == S_IFDIR else { throw SetupError("The existing Kumo application is not an ordinary folder.") }
            try verifyCode(destination, identifier: "app.kumo.browser")
            let oldInfo = try PropertyListSerialization.propertyList(from: Data(contentsOf: destination.appendingPathComponent("Contents/Info.plist")), format: nil) as? [String: Any]
            let oldMetadata = try buildMetadata(destination)
            let newMetadata = try buildMetadata(payloads.app)
            guard let oldBuild = oldInfo?["CFBundleVersion"] as? String,
                  let oldEngine = oldMetadata["engineVersion"] as? String,
                  let newEngine = newMetadata["engineVersion"] as? String,
                  allowsUpgrade(oldBuild: oldBuild, newBuild: payloads.manifest.appBuild, oldEngine: oldEngine, newEngine: newEngine) else {
                throw SetupError("This package would downgrade the installed browser or its security engine.")
            }
            if oldBuild == payloads.manifest.appBuild {
                try verifyCode(destination, identifier: "app.kumo.browser", expectedCDHash: payloads.manifest.appCDHash)
            }
        } else if errno != ENOENT { throw SetupError("The installed browser cannot be inspected safely.") }
        try RootInstaller.installSources(payloads: payloads, support: support)
        try RootInstaller.assertBrowserClosed()
        let flags = hadPrevious ? UInt32(RENAME_SWAP) : UInt32(RENAME_EXCL)
        guard renamex_np(staged.path, destination.path, flags) == 0 else { throw SetupError("Kumo could not be published in Applications. Quit Kumo, then retry.") }
        do {
            try payloads.verifyApp(destination)
            try initializeConsoleUser(payloads: payloads, user: user)
            try payloads.verifyApp(destination)
            // Only now can the old application be removed from the private stage.
        } catch {
            do {
                try payloads.verifyApp(destination)
                if hadPrevious {
                    try verifyCode(staged, identifier: "app.kumo.browser")
                    guard renamex_np(staged.path, destination.path, UInt32(RENAME_SWAP)) == 0 else { throw SetupError("The previous browser could not be restored.") }
                    try verifyCode(destination, identifier: "app.kumo.browser")
                } else {
                    guard renamex_np(destination.path, staged.path, UInt32(RENAME_EXCL)) == 0 else { throw SetupError("The incomplete browser installation could not be withdrawn.") }
                }
            } catch {
                cleanup = false
                throw SetupError("Kumo could not confirm setup or restore its previous app automatically. The protected transaction is preserved at \(stage.path). Cisco's separate antivirus components remain installed.")
            }
            let recovery = (error as? SetupError)?.recoveryReason
            throw SetupError(restoredFailureMessage(recoveryReason: recovery), recoveryReason: validRecoveryReason(recovery))
        }
    }
}
