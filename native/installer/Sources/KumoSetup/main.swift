import Foundation
import Darwin
import KumoMalwareCore

func jsonResult(_ object: [String: Any]) {
    if let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(data + Data([10]))
    }
}

func selfTest() throws -> Int {
    var checks = 0
    func expect(_ value: @autoclosure () -> Bool) throws {
        guard value() else { throw SetupError("An internal installer policy test failed at check \(checks + 1).") }; checks += 1
    }
    for path in ["payload/Kumo.app/Contents/Info.plist", "payload/definitions/daily.cvd"] { try expect(SetupPolicy.safePayloadPath(path)) }
    for path in ["/payload/a", "payload/../a", "payload/./a", "payload//a", "payload/a/", "payload/a\n", "payload/a\0"] { try expect(!SetupPolicy.safePayloadPath(path)) }
    try expect(SetupPolicy.strictTrue(true)); try expect(!SetupPolicy.strictTrue(false)); try expect(!SetupPolicy.strictTrue(1)); try expect(!SetupPolicy.strictTrue("true"))
    let ready: [String: Any] = ["installed": true, "available": true, "automaticUpdates": true, "reason": "ready"]
    try expect(SetupPolicy.ready(ready))
    for key in ["installed", "available", "automaticUpdates"] {
        var value = ready; value[key] = 1; try expect(!SetupPolicy.ready(value))
        value[key] = false; try expect(!SetupPolicy.ready(value))
    }
    try expect(!SetupPolicy.rootAllowed(real: 501, effective: 0)); try expect(!SetupPolicy.rootAllowed(real: 0, effective: 501)); try expect(SetupPolicy.rootAllowed(real: 0, effective: 0))
    try expect(SetupPolicy.userAllowed(real: 501, effective: 501, console: 501)); try expect(!SetupPolicy.userAllowed(real: 501, effective: 0, console: 501)); try expect(!SetupPolicy.userAllowed(real: 502, effective: 502, console: 501)); try expect(!SetupPolicy.userAllowed(real: 0, effective: 0, console: 0))
    try expect(UserInitializer.allowedDefinition("daily-28160.cvd.sign")); try expect(!UserInitializer.allowedDefinition("freshclam.dat")); try expect(!UserInitializer.allowedDefinition("../daily.cvd"))
    try expect(SetupPolicy.quoteShell("a'b$(id)") == "'a'\\''b$(id)'")
    return checks
}

let arguments = Array(CommandLine.arguments.dropFirst())
if !arguments.isEmpty {
    do {
        guard arguments.count == 1 else { throw SetupError("Use one installer action at a time.") }
        switch arguments[0] {
        case "--self-test": jsonResult(["ok": true, "status": "self-test-passed", "checks": try selfTest(), "mutations": false])
        case "--package-policy": jsonResult(["ok": true, "packageMode": 1, "nestedInstaller": false, "rollbackUntilUserReady": true, "standaloneInstaller": false, "definitionRollbackUntilUserReady": true, "canonicalMetadata": "Contents/Resources/kumo-build-info.json", "mutations": false])
        case "--verify-payloads":
            let payloads = try Payloads(); try payloads.verify()
            jsonResult(["ok": true, "status": "payloads-verified", "appVersion": payloads.manifest.appVersion, "appBuild": payloads.manifest.appBuild, "files": payloads.manifest.files.count])
        case "--install-root":
            throw SetupError("Open the standard Kumo .pkg installer to install or repair Kumo. The standalone administrator installer has been retired.")
        case "--install-package-root":
            guard SetupPolicy.rootAllowed() else { throw SetupError("System installation requires macOS administrator authorization.") }
            let payloads = try Payloads(); try PackageInstaller.install(payloads: payloads)
            jsonResult(["ok": true, "status": "package-installed", "benignScanPassed": true, "automaticUpdates": true])
        case "--initialize-user":
            guard SetupPolicy.userAllowed(real: getuid(), effective: geteuid(), console: try consoleUID()) else { throw SetupError("Open Kumo Setup from the account currently logged into this Mac.") }
            let payloads = try Payloads(); try UserInitializer.initialize(payloads: payloads)
            jsonResult(["ok": true, "status": "ready", "benignScanPassed": true, "automaticUpdates": true])
        default: throw SetupError("Unknown Kumo Setup action.")
        }
    } catch {
        var response: [String: Any] = ["ok": false, "status": "failed", "reason": friendlyError(error)]
        if let recovery = (error as? SetupError)?.recoveryReason { response["recoveryReason"] = recovery }
        jsonResult(response)
        FileHandle.standardError.write(Data((friendlyError(error) + "\n").utf8))
        exit(1)
    }
} else {
    let reason = "Open the standard Kumo .pkg installer to install or repair Kumo. This internal helper does not install applications when opened directly."
    jsonResult(["ok": false, "status": "failed", "reason": reason])
    FileHandle.standardError.write(Data((reason + "\n").utf8))
    exit(64)
}
