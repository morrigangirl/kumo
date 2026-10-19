import XCTest
import Foundation
import Darwin
@testable import KumoPhishLangSetupSupport

final class SetupTests: XCTestCase {
    var root: URL!
    var source: URL!
    var targets: PhishLangTargets!
    let publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApLVvwe+Q6t32O+mmzfQyI7CaWMKxhKpbxo4A41OX+CGRyOheoK1rwJ2X8qy5o1j43mKPiEjmg7w/r2hP2HUOKM6Oix5y9zsA5z09Y9w3d05FhXkHNh4PZmhxdJkpRBOdrXymWb07C5jLh+vjAiQGkIcvcmirxtzoNKwEwTZB53Rmc/ybn6h+X9AgKzK+I1G4gxqIOxrt0MEZkZNOiyPIAArenaNOpkMAtzj4QK9YTyNxKbJprn5CwJbpNfWZyymqdBOCSaH5bXjzCmIonXD8CBhEY5QKB7JqEImMgKEw4gqO8yXtWO+yzI33x97eJXYnXYzRJ6KuM/EmO6EUY/4GcQIDAQAB"

    override func setUpWithError() throws {
        root = URL(fileURLWithPath: "/private/tmp/kumo-phishlang-setup-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        source = root.appendingPathComponent("Downloaded package with spaces/" + PhishLangIdentity.appName, isDirectory: true)
        let contents = source.appendingPathComponent("Contents", isDirectory: true)
        let extensionDirectory = contents.appendingPathComponent("Resources/Extension", isDirectory: true)
        try FileManager.default.createDirectory(at: extensionDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(at: contents.appendingPathComponent("MacOS"), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": PhishLangIdentity.bundle,
            "CFBundleExecutable": "KumoPhishingHost", "KumoPhishLangExtensionOrigin": PhishLangIdentity.origin,
            "KumoPhishLangPackageIdentifier": PhishLangIdentity.bundle], format: .xml, options: 0).write(to: contents.appendingPathComponent("Info.plist"))
        try Data("synthetic executable".utf8).write(to: contents.appendingPathComponent("MacOS/KumoPhishingHost"))
        try JSONSerialization.data(withJSONObject: ["key": publicKey, "manifest_version": 3, "name": "Synthetic extension", "version": "0.1.0"]).write(to: extensionDirectory.appendingPathComponent("manifest.json"))
        try Data("synthetic shared content".utf8).write(to: extensionDirectory.appendingPathComponent("phishing-content.js"))
        targets = try PhishLangTargets(applications: root.appendingPathComponent("User Applications", isDirectory: true),
            hosts: root.appendingPathComponent("Kumo profile/NativeMessagingHosts", isDirectory: true),
            extensionDirectory: root.appendingPathComponent("stable addon/extension", isDirectory: true))
    }
    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }
    func setup(verifier: @escaping PhishLangSetup.SignatureVerifier = { _ in }) -> PhishLangSetup {
        PhishLangSetup(source: source, targets: targets, verifySignature: verifier)
    }
    func createTargets() throws {
        for directory in [targets.applications, targets.hosts, targets.extensionDirectory.deletingLastPathComponent()] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
    }
    func testInstallerCopiesSealedExtensionAndRegistersOnlyDedicatedHost() throws {
        try createTargets()
        let unrelated = targets.hosts.appendingPathComponent("com.kumo.malware.json")
        try Data("preserve unrelated host".utf8).write(to: unrelated)
        let result = try setup().install()
        XCTAssertEqual(result["status"] as? String, "installed")
        XCTAssertEqual(setup().status()["installed"] as? Bool, true)
        let host = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: targets.manifest)) as? [String: Any])
        XCTAssertEqual(host["name"] as? String, PhishLangIdentity.host)
        XCTAssertEqual(host["allowed_origins"] as? [String], [PhishLangIdentity.origin])
        XCTAssertEqual(host["path"] as? String, targets.application.appendingPathComponent("Contents/MacOS/KumoPhishingHost").path)
        XCTAssertEqual(try String(contentsOf: targets.extensionDirectory.appendingPathComponent("phishing-content.js")), "synthetic shared content")
        XCTAssertEqual(try String(contentsOf: unrelated), "preserve unrelated host")
        // The installed resources remain usable after the original downloaded package is removed.
        try FileManager.default.removeItem(at: source.deletingLastPathComponent())
        XCTAssertEqual(setup().status()["installed"] as? Bool, true)
        XCTAssertEqual(try setup().uninstall()["status"] as? String, "uninstalled")
        XCTAssertFalse(FileManager.default.fileExists(atPath: targets.application.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: targets.extensionDirectory.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: targets.manifest.path))
        XCTAssertEqual(try String(contentsOf: unrelated), "preserve unrelated host")
        XCTAssertEqual(try setup().uninstall()["status"] as? String, "uninstalled")
    }
    func testReinstallRefreshesOnlyOwnedFiles() throws {
        _ = try setup().install()
        let content = source.appendingPathComponent("Contents/Resources/Extension/phishing-content.js")
        try Data("new sealed bytes".utf8).write(to: content)
        _ = try setup().install()
        XCTAssertEqual(try String(contentsOf: targets.extensionDirectory.appendingPathComponent("phishing-content.js")), "new sealed bytes")
        XCTAssertEqual(setup().status()["installed"] as? Bool, true)
        for parent in [targets.applications, targets.hosts, targets.extensionDirectory.deletingLastPathComponent()] {
            XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: parent.path).contains { $0.hasSuffix(".previous") || $0.hasPrefix(".kumo-phishlang-app-") })
        }
    }
    func testSignatureFailureCannotInstallOrUninstallOwnedFiles() throws {
        XCTAssertThrowsError(try setup(verifier: { _ in throw PhishLangSetupFailure.invalidSignature }).install())
        XCTAssertFalse(FileManager.default.fileExists(atPath: targets.manifest.path))
        _ = try setup().install()
        XCTAssertThrowsError(try setup(verifier: { _ in throw PhishLangSetupFailure.invalidSignature }).uninstall())
        XCTAssertTrue(FileManager.default.fileExists(atPath: targets.manifest.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: targets.extensionDirectory.path))
    }
    func testForeignAppHostAndExtensionArePreserved() throws {
        try createTargets()
        for directory in [targets.application, targets.extensionDirectory] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            let sentinel = directory.appendingPathComponent("preserve")
            try Data("foreign directory".utf8).write(to: sentinel)
            XCTAssertThrowsError(try setup().install())
            XCTAssertThrowsError(try setup().uninstall())
            XCTAssertEqual(try String(contentsOf: sentinel), "foreign directory")
            try FileManager.default.removeItem(at: directory)
        }
        try Data("foreign host".utf8).write(to: targets.manifest)
        XCTAssertThrowsError(try setup().install())
        XCTAssertThrowsError(try setup().uninstall())
        XCTAssertEqual(try String(contentsOf: targets.manifest), "foreign host")
    }
    func testSymlinkAppAndHostParentsNeverTouchTargets() throws {
        try createTargets()
        let outside = root.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        let sentinel = outside.appendingPathComponent("preserve")
        try Data("outside bytes".utf8).write(to: sentinel)
        try FileManager.default.createSymbolicLink(at: targets.application, withDestinationURL: outside)
        XCTAssertThrowsError(try setup().install())
        XCTAssertThrowsError(try setup().uninstall())
        XCTAssertEqual(try String(contentsOf: sentinel), "outside bytes")
        try FileManager.default.removeItem(at: targets.application)
        try FileManager.default.removeItem(at: targets.hosts)
        try FileManager.default.createSymbolicLink(at: targets.hosts, withDestinationURL: outside)
        XCTAssertThrowsError(try setup().install())
        XCTAssertEqual(try String(contentsOf: sentinel), "outside bytes")
    }
    func testSourceAliasesAndHardLinksFailBeforeAnyInstall() throws {
        let content = source.appendingPathComponent("Contents/Resources/Extension/phishing-content.js")
        let outside = root.appendingPathComponent("outside.txt")
        try Data("outside bytes".utf8).write(to: outside)
        try FileManager.default.removeItem(at: content)
        try FileManager.default.createSymbolicLink(at: content, withDestinationURL: outside)
        XCTAssertThrowsError(try setup().install())
        try FileManager.default.removeItem(at: content)
        XCTAssertEqual(link(outside.path, content.path), 0)
        XCTAssertThrowsError(try setup().install())
        XCTAssertEqual(try String(contentsOf: outside), "outside bytes")
        XCTAssertFalse(FileManager.default.fileExists(atPath: targets.manifest.path))
    }
    func testHardLinkedHostIsPreservedEvenWhenJSONMatches() throws {
        _ = try setup().install()
        let outside = root.appendingPathComponent("host-hardlink.json")
        XCTAssertEqual(link(targets.manifest.path, outside.path), 0)
        XCTAssertThrowsError(try setup().uninstall())
        XCTAssertTrue(FileManager.default.fileExists(atPath: targets.application.path))
        XCTAssertEqual(try Data(contentsOf: outside), try Data(contentsOf: targets.manifest))
    }
    func testUninstallRefusesLinkedExtensionContentBeforeDeletingAnyLayer() throws {
        _ = try setup().install()
        let outside = root.appendingPathComponent("outside.txt")
        try Data("outside bytes".utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(at: targets.extensionDirectory.appendingPathComponent("alias.txt"), withDestinationURL: outside)
        XCTAssertThrowsError(try setup().uninstall())
        XCTAssertTrue(FileManager.default.fileExists(atPath: targets.manifest.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: targets.application.path))
        XCTAssertEqual(try String(contentsOf: outside), "outside bytes")
    }
    func testDownloadedSourceMutationCannotReplaceVerifiedStagedExtension() throws {
        var calls = 0
        let installer = setup { _ in
            calls += 1
            if calls == 2 {
                try Data("unsigned changed source".utf8).write(to: self.source.appendingPathComponent("Contents/Resources/Extension/phishing-content.js"))
            }
        }
        _ = try installer.install()
        XCTAssertEqual(try String(contentsOf: targets.extensionDirectory.appendingPathComponent("phishing-content.js")), "synthetic shared content")
        XCTAssertEqual(try String(contentsOf: targets.application.appendingPathComponent("Contents/Resources/Extension/phishing-content.js")), "synthetic shared content")
    }
    func testForeignHostAppearingDuringStagingIsNotOverwrittenAndRollsBack() throws {
        var calls = 0
        let installer = setup { _ in
            calls += 1
            if calls == 2 { try Data("raced foreign host".utf8).write(to: self.targets.manifest) }
        }
        XCTAssertThrowsError(try installer.install())
        XCTAssertEqual(try String(contentsOf: targets.manifest), "raced foreign host")
        XCTAssertFalse(FileManager.default.fileExists(atPath: targets.application.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: targets.extensionDirectory.path))
    }
    func testPartialTargetOverridesAndOverlappingDirectoriesAreRejected() throws {
        XCTAssertThrowsError(try PhishLangTargets.parse(arguments: ["install", "--applications-dir", root.path]))
        XCTAssertThrowsError(try PhishLangTargets.parse(arguments: ["install", "--applications-dir", root.path, "--applications-dir", root.path, "--extension-dir", root.path]))
        XCTAssertThrowsError(try PhishLangTargets.parse(arguments: ["install", "--applications-dir", root.path + "/../escape", "--native-hosts-dir", root.path + "/hosts", "--extension-dir", root.path + "/extension"]))
        XCTAssertThrowsError(try PhishLangTargets(applications: root, hosts: root.appendingPathComponent("hosts"), extensionDirectory: root.appendingPathComponent("extension")))
    }
    func testWritableTargetAncestorIsRejected() throws {
        try createTargets()
        let parent = targets.hosts.deletingLastPathComponent()
        XCTAssertEqual(chmod(parent.path, 0o777), 0)
        XCTAssertThrowsError(try setup().install())
        XCTAssertFalse(FileManager.default.fileExists(atPath: targets.manifest.path))
    }
    func testUnexpectedOriginInSealedPlistIsRejected() throws {
        let info = source.appendingPathComponent("Contents/Info.plist")
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": PhishLangIdentity.bundle, "CFBundleExecutable": "KumoPhishingHost",
            "KumoPhishLangExtensionOrigin": "chrome-extension://eldkgppmnhligdekahicdcdndcoongio/",
            "KumoPhishLangPackageIdentifier": PhishLangIdentity.bundle], format: .xml, options: 0).write(to: info)
        XCTAssertThrowsError(try setup().install())
        XCTAssertFalse(FileManager.default.fileExists(atPath: targets.manifest.path))
    }
}
