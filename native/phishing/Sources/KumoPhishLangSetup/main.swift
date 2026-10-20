import Foundation
import Darwin
import KumoPhishLangSetupSupport

do {
    let (action, targets) = try PhishLangTargets.parse(arguments: Array(CommandLine.arguments.dropFirst()))
    let executable = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
    let source = executable.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent(PhishLangIdentity.appName, isDirectory: true)
    let setup = PhishLangSetup(source: source, targets: targets)
    let result: [String: Any]
    switch action {
    case "install": result = try setup.install()
    case "uninstall": result = try setup.uninstall()
    default: result = setup.status()
    }
    try FileHandle.standardOutput.write(contentsOf: JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys]) + Data([10]))
} catch {
    fputs("Kumo PhishLang: \(error.localizedDescription)\n", stderr)
    exit(error as? PhishLangSetupFailure == .usage ? 64 : 1)
}
