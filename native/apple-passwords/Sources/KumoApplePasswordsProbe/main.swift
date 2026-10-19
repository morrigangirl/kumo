import Foundation
import KumoApplePasswords

@main
struct KumoApplePasswordsProbe {
    @MainActor
    static func main() async {
        let arguments = Array(CommandLine.arguments.dropFirst())
        let integration = ApplePasswordsIntegration()
        do {
            switch arguments {
            case [], ["status"]:
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let output = try encoder.encode(integration.capabilities())
                print(String(decoding: output, as: UTF8.self))
            case ["open-passwords"]:
                try await integration.openPasswordsApplication()
                print("Opened Apple Passwords. Unlock and credential selection remain under macOS control.")
            case ["help"], ["--help"], ["-h"]:
                print("""
                Usage: kumo-apple-passwords [status|open-passwords|help]
                  status          Report public API availability; does not request consent or read credentials.
                  open-passwords  Open the Apple Passwords app using macOS Launch Services.

                Browser passkey consent must be requested by the signed browser itself.
                This helper does not retrieve or fill website passwords.
                """)
            default:
                FileHandle.standardError.write(Data("Unknown command. Run kumo-apple-passwords help.\n".utf8))
                exit(64)
            }
        } catch {
            FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}
