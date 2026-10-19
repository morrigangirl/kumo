import Foundation
import Darwin
import KumoPhishingCore

let arguments = CommandLine.arguments
let diagnostic = arguments.count == 4 && ["--self-test", "--benchmark"].contains(arguments[1]) && arguments[2] == "--resources"
guard diagnostic || HostProtocol.authorized(arguments: arguments) else { exit(64) }

let resources: URL
if diagnostic {
    resources = URL(fileURLWithPath: arguments[3], isDirectory: true)
} else {
    // Resolve the installed binary rather than trusting the working directory or web-supplied paths.
    resources = URL(fileURLWithPath: arguments[0]).resolvingSymlinksInPath()
        .deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Resources/PhishLang", isDirectory: true)
}
let service = PhishingService(resources: resources)
if diagnostic {
    do {
        let input = try HostProtocol.readDiagnostic(from: .standardInput)
        var response = service.handle(input)
        var usage = rusage()
        if getrusage(RUSAGE_SELF, &usage) == 0 { response["peakResidentBytes"] = usage.ru_maxrss }
        let bytes = try JSONSerialization.data(withJSONObject: response, options: [.sortedKeys])
        try FileHandle.standardOutput.write(contentsOf: bytes + Data([10]))
        exit(response["ok"] as? Bool == true ? 0 : 1)
    } catch { exit(65) }
}

do {
    while let input = try HostProtocol.readFrame(from: .standardInput) {
        let response = service.handle(input)
        try FileHandle.standardOutput.write(contentsOf: HostProtocol.framed(response))
    }
} catch {
    // Never echo hostile page text or parser/model diagnostics into browser logs.
    exit(65)
}
