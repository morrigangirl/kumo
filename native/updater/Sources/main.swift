import AppKit
import CryptoKit
import Foundation
import Sparkle

@MainActor
final class GuardedUserDriver: SPUStandardUserDriver {
    let host: UpdateHost
    var lease: UpdateLease?
    var installApproved = false
    var leasePolicy = InstallationLeasePolicy()
    var expectedBuild: String?
    var recoveryNoticeShown = false
    var didInstall: ((Bool) -> Void)?
    init(host: UpdateHost) {
        self.host = host
        super.init(hostBundle: Bundle(url: host.application)!, delegate: nil)
    }
    // Sparkle's stock installer only tracks one browser PID. Kumo instead
    // requires all profiles to be closed, holds its cross-user installation
    // lock throughout extraction/replacement, and never force-quits browsing.
    func acquireInstallPermission() -> Bool {
        do {
            try host.verifyProduction()
            if lease == nil { lease = try UpdateLease(application: host.application) }
            guard try runningBrowserProcesses(application: host.application, companion: host.companion).isEmpty else {
                throw UpdatePolicyError.browserRunning
            }
            leasePolicy.record(.authorized)
            installApproved = true
            return true
        } catch {
            if leasePolicy.record(.revalidationFailed) { lease?.release(); lease = nil }
            let alert = NSAlert(); alert.messageText = "Kumo cannot install this update yet"
            alert.informativeText = error.localizedDescription + "\n\nAfter quitting Kumo, check for updates again."
            alert.addButton(withTitle: "OK"); alert.runModal()
            return false
        }
    }
    override func showUpdateFound(with appcastItem: SUAppcastItem, state: SPUUserUpdateState, reply: @escaping (SPUUserUpdateChoice) -> Void) {
        if state.stage == .installing && lease == nil {
            // A previous updater cannot leave an install-on-quit operation
            // active after its coordination lock disappeared. Cancel it now.
            reply(.skip); return
        }
        super.showUpdateFound(with: appcastItem, state: state) { [weak self] choice in
            guard let self else { reply(.skip); return }
            let stage: InstallationStage = state.stage == .installing ? .installing : (state.stage == .downloaded ? .downloaded : .notDownloaded)
            let selected: InstallationChoice = choice == .install ? .install : (choice == .dismiss ? .dismiss : .skip)
            let safe = safeInstallationChoice(selected, stage: stage, leaseHeld: self.lease != nil)
            if stage == .installing && safe == .skip {
                reply(.skip)
            } else if safe == .install && !self.acquireInstallPermission() {
                reply(stage == .installing ? .skip : .dismiss)
            } else { reply(choice) }
        }
    }
    override func showDownloadDidStartExtractingUpdate() {
        leasePolicy.record(.extractionStarted)
        super.showDownloadDidStartExtractingUpdate()
    }
    override func showReadyToInstallAndRelaunch() async -> SPUUserUpdateChoice {
        let choice = await super.showReadyToInstallAndRelaunch()
        // Sparkle's Dismiss choice can leave a staged installer active. Kumo
        // cancels instead; a pending install must never outlive its EX lease.
        if choice != .install || !acquireInstallPermission() {
            return .skip
        }
        return .install
    }
    func finishCycle(error: Error?) {
        // XPC failure does not prove Sparkle's installer stopped. Once
        // extraction began, preserve the lock until confirmed replacement.
        if isDefinitivePrelaunchCancellation(error) { leasePolicy.record(.noInstallerLaunched) }
        if leasePolicy.record(.cycleEnded) {
            lease?.release(); lease = nil; installApproved = false
        } else if lease != nil && !recoveryNoticeShown {
            recoveryNoticeShown = true
            DispatchQueue.main.async {
                let alert = NSAlert(); alert.messageText = "Kumo is waiting for update confirmation"
                alert.informativeText = "The installer did not confirm completion. Keep this updater running and Kumo closed while the installed release is verified. Kumo will reopen only after the signed replacement is confirmed."
                alert.addButton(withTitle: "Keep Waiting"); alert.runModal()
            }
        }
    }
    func recoverVerifiedReplacement() {
        guard lease != nil, leasePolicy.phase == .unconfirmed, let expectedBuild,
              (try? verifyCommittedReplacement(application: host.application, companion: host.companion,
                    oldBuild: host.configuration.build, expectedBuild: expectedBuild)) == true else { return }
        completeInstallation(relaunched: false)
    }
    func completeInstallation(relaunched: Bool) {
        guard leasePolicy.phase != .completed else { return }
        leasePolicy.record(.installationCompleted)
        lease?.release(); lease = nil
        didInstall?(installApproved && !relaunched)
    }
    override func showUpdateInstalledAndRelaunched(_ relaunched: Bool, acknowledgement: @escaping () -> Void) {
        // This callback is emitted after Sparkle's actual stage3 replacement.
        completeInstallation(relaunched: relaunched)
        acknowledgement()
    }

}

@MainActor
final class UpdaterDelegate: NSObject, NSApplicationDelegate, SPUUpdaterDelegate {
    let host: UpdateHost
    let manual: Bool
    var driver: GuardedUserDriver!
    var updater: SPUUpdater!
    var observer: NSObjectProtocol?
    var lifetimeTimer: Timer?
    var parentWaitTimer: Timer?
    var handoffProcess: Process?
    var handoffOutput: Pipe?
    var handoffBuffer = Data()
    var handoffAcknowledged = false
    let bootstrapParentPID: pid_t?
    let notification: Notification.Name
    init(host: UpdateHost, manual: Bool, bootstrapParentPID: pid_t? = nil) {
        self.host = host; self.manual = manual; self.bootstrapParentPID = bootstrapParentPID
        let digest = SHA256.hash(data: Data(host.application.path.utf8)).map { String(format: "%02x", $0) }.joined()
        self.notification = Notification.Name("app.kumo.browser.updater.check." + digest)
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        guard let parent = bootstrapParentPID else { startUpdater(relaunchBrowser: false); return }
        // The old companion waits for this acknowledgement before exiting,
        // so validating the actual parent cannot race with orphan adoption.
        FileHandle.standardOutput.write(Data("KUMO-UPDATER-HANDOFF-READY\n".utf8))
        let deadline = Date().addingTimeInterval(30)
        parentWaitTimer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] timer in
            MainActor.assumeIsolated {
                guard let self else { timer.invalidate(); return }
                if getppid() != parent {
                    timer.invalidate(); self.startUpdater(relaunchBrowser: true)
                } else if Date() >= deadline { timer.invalidate(); NSApp.terminate(nil) }
            }
        }
    }
    func startUpdater(relaunchBrowser: Bool) {
        do {
            try host.verifyProduction()
            let others = NSRunningApplication.runningApplications(withBundleIdentifier: "app.kumo.browser.updater").filter {
                $0.processIdentifier != ProcessInfo.processInfo.processIdentifier && $0.bundleURL?.resolvingSymlinksInPath() == host.companion
            }
            if !others.isEmpty {
                if manual { DistributedNotificationCenter.default().postNotificationName(self.notification, object: nil, userInfo: nil, deliverImmediately: true) }
                NSApp.terminate(nil); return
            }
            guard let bundle = Bundle(url: host.application) else { throw UpdatePolicyError.invalidHost }
            driver = GuardedUserDriver(host: host)
            driver.didInstall = { [weak self] reopen in self?.finishAfterInstall(reopenBrowser: reopen) }
            updater = SPUUpdater(hostBundle: bundle, applicationBundle: bundle, userDriver: driver, delegate: self)
            updater.userAgentString = "Kumo/" + host.configuration.version
            observer = DistributedNotificationCenter.default().addObserver(forName: self.notification, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.checkManually() }
            }
            try updater.start()
            if manual { checkManually() }
            if relaunchBrowser {
                let configuration = NSWorkspace.OpenConfiguration(); configuration.activates = true
                NSWorkspace.shared.openApplication(at: host.application, configuration: configuration) { _, _ in }
            }
            // One background companion per installation remains only while a
            // browser process or an active update session exists. No daemon.
            lifetimeTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self else { return }
                    self.driver.recoverVerifiedReplacement()
                    guard !self.updater.sessionInProgress, self.driver.lease == nil else { return }
                    if (try? runningBrowserProcesses(application: self.host.application, companion: self.host.companion).isEmpty) == true {
                        NSApp.terminate(nil)
                    }
                }
            }
        } catch { fail(error) }
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        checkManually(); return false
    }
    func checkManually() {
        guard let driver, let updater else { return }
        guard driver.leasePolicy.phase != .unconfirmed else { driver.finishCycle(error: nil); return }
        NSApp.activate(ignoringOtherApps: true)
        if updater.canCheckForUpdates { updater.checkForUpdates() }
    }
    func updater(_ updater: SPUUpdater, mayPerform updateCheck: SPUUpdateCheck) throws {
        guard driver.leasePolicy.phase != .unconfirmed else { throw UpdatePolicyError.browserRunning }
    }
    func feedURLString(for updater: SPUUpdater) -> String? { ReleaseConfiguration.feedURL }
    func allowedSystemProfileKeys(for updater: SPUUpdater) -> [String]? { [] }
    func updaterShouldPromptForPermissionToCheck(forUpdates updater: SPUUpdater) -> Bool { false }
    func updater(_ updater: SPUUpdater, shouldDownloadReleaseNotesForUpdate updateItem: SUAppcastItem) -> Bool { false }
    func updater(_ updater: SPUUpdater, shouldProceedWithUpdate updateItem: SUAppcastItem, updateCheck: SPUUpdateCheck) throws {
        // An unsigned/informational/package feed cannot turn this browser
        // updater into a generic installer or arbitrary URL downloader.
        guard let url = updateItem.fileURL, validReleaseArchiveURL(url, expectedBuild: updateItem.versionString),
              updateItem.installationType == "application", !updateItem.isInformationOnlyUpdate else {
            throw UpdatePolicyError.invalidConfiguration
        }
        driver.expectedBuild = updateItem.versionString
    }
    func updater(_ updater: SPUUpdater, didExtractUpdate updateItem: SUAppcastItem) {
        driver.leasePolicy.record(.installerLaunched)
    }
    func updater(_ updater: SPUUpdater, didFinishUpdateCycleFor updateCheck: SPUUpdateCheck, error: Error?) {
        driver.finishCycle(error: error)
    }
    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) {
        driver.finishCycle(error: error)
    }
    func finishAfterInstall(reopenBrowser: Bool) {
        lifetimeTimer?.invalidate()
        guard reopenBrowser else { NSApp.terminate(nil); return }
        let child = Process(), output = Pipe()
        child.executableURL = host.companion.appendingPathComponent("Contents/MacOS/KumoUpdater")
        child.arguments = ["--handoff", String(getpid())]
        child.standardInput = FileHandle.nullDevice; child.standardOutput = output; child.standardError = FileHandle.nullDevice
        handoffProcess = child; handoffOutput = output
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let bytes = handle.availableData
            DispatchQueue.main.async {
                guard let self, !self.handoffAcknowledged else { return }
                self.handoffBuffer.append(bytes)
                if self.handoffBuffer == Data("KUMO-UPDATER-HANDOFF-READY\n".utf8) {
                    self.handoffAcknowledged = true
                    handle.readabilityHandler = nil
                    NSApp.terminate(nil)
                } else if bytes.isEmpty || self.handoffBuffer.count > 4096 { self.handoffFailed() }
            }
        }
        do { try child.run() }
        catch { output.fileHandleForReading.readabilityHandler = nil; handoffFailed(); return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
            guard let self, !self.handoffAcknowledged else { return }; self.handoffFailed()
        }
    }
    func handoffFailed() {
        guard !handoffAcknowledged else { return }
        handoffAcknowledged = true; handoffOutput?.fileHandleForReading.readabilityHandler = nil
        let alert = NSAlert(); alert.messageText = "Kumo finished installing"
        alert.informativeText = "The updated browser could not restart automatically. Open Kumo again to start the browser and its update checker."
        alert.addButton(withTitle: "OK"); alert.runModal(); NSApp.terminate(nil)
    }
    func fail(_ error: Error) {
        if manual {
            let alert = NSAlert(); alert.messageText = "Kumo app updates are unavailable"
            alert.informativeText = error.localizedDescription
            alert.addButton(withTitle: "OK"); alert.runModal()
        }
        NSApp.terminate(nil)
    }
}

@main
struct KumoUpdaterMain {
    @MainActor static func main() {

        let arguments = Array(CommandLine.arguments.dropFirst())
        let ordinary = arguments.count == 1 && ["--status", "--check", "--background"].contains(arguments[0])
        var parentPID: pid_t?
        if arguments.count == 2 && arguments[0] == "--handoff" {
            parentPID = try? validatedHandoffParent(arguments[1], actualParent: getppid())
        }
        guard ordinary || parentPID != nil else {
            FileHandle.standardError.write(Data("Usage: KumoUpdater --status|--check|--background\n".utf8)); exit(64)
        }
        let mode = arguments[0]
        do {
            let host = try UpdateHost(companion: Bundle.main.bundleURL)
            var enabled = false
            var reason = "release-signing-not-configured"
            if host.configuration.configured {
                do { try host.verifyProduction(); enabled = true; reason = "ready" }
                catch { reason = "developer-id-verification-failed" }
            }
            if mode == "--status" {
                let result: [String: Any] = ["schemaVersion": 1, "provider": "github-releases", "repository": ReleaseConfiguration.repository,
                    "feedURL": ReleaseConfiguration.feedURL, "available": enabled, "reason": reason,
                    "version": host.configuration.version, "build": host.configuration.build, "sparkleVersion": "2.10.0",
                    "requiresUserInstallation": true, "requiresAllProfilesClosed": true]
                let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
                FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10])); exit(0)
            }
            guard enabled else {
                if mode == "--check" {
                    let alert = NSAlert(); alert.messageText = "Kumo app updates are not enabled for this development build"
                    alert.informativeText = "Production updates are delivered through signed GitHub Releases. This build needs the release signing key and a notarized Developer ID release before updates can be enabled."
                    alert.addButton(withTitle: "OK"); alert.runModal()
                }
                exit(0)
            }
            let app = NSApplication.shared
            app.setActivationPolicy(.accessory)
            let delegate = UpdaterDelegate(host: host, manual: mode == "--check", bootstrapParentPID: parentPID)
            app.delegate = delegate
            withExtendedLifetime(delegate) { app.run() }
        } catch {
            if mode == "--status" {
                FileHandle.standardOutput.write(Data("{\"available\":false,\"reason\":\"invalid-update-host\",\"schemaVersion\":1}\n".utf8))
            } else { FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8)) }
            exit(1)
        }

    }
}
