# Kumo Apple Passwords capability bridge

This macOS Swift package exposes a capability diagnostic, the public browser passkey permission request, and a normal Apple Passwords application launcher. It is an integration foundation, not website password AutoFill. See [the platform boundary](../../docs/apple-passwords.md).

It also includes a native manual AutoFill probe using real `NSTextField` and `NSSecureTextField` controls with `.username` and `.password` content types. On the validated Mac, both empty controls displayed an enabled system AutoFill → Passwords action. No password picker was opened, unlocked, or completed. This is a promising route for a native browser fill sheet without the Chrome extension. It does not yet fill Chromium pages or match website domains automatically.

Build the app bundle and launch it to inspect only its empty fields:

```sh
sh native/apple-passwords/build-probe-app.sh
open "native/apple-passwords/.build/Kumo AutoFill Probe.app"
```

The probe has no credential logging, persistence, browser connection, or form-submission action. It clears both controls on close. Ordinary AppKit strings are released; secure memory zeroing is not claimed. During validation, inspect the context menu only and do not select real credentials.

Run structural and SDK checks without a password prompt:

```sh
native/apple-passwords/.build/debug/kumo-autofill-probe --describe-fields
python3 native/apple-passwords/audit-public-sdk.py
```

Build and inspect without prompting for access:

```sh
swift build --package-path native/apple-passwords
swift run --package-path native/apple-passwords kumo-apple-passwords status
```

Open Passwords only on an explicit user action:

```sh
swift run --package-path native/apple-passwords kumo-apple-passwords open-passwords
```

The library's `requestBrowserPasskeyAuthorization()` uses Apple's consent UI and should run inside the signed browser process. Apple's browser passkey managed entitlement must be approved and included in its provisioning profile. A command line helper has a different app identity and cannot grant permission to the browser. No entitlement file is supplied to imply that local signing grants Apple's managed capability.

Chromium already has a native macOS WebAuthn implementation. Keep that implementation, origin checks, and its browser passkey flow; connect the library only to browser-owned status/settings UI. Do not replace Chromium's WebAuthn security validation with a generic RPC or expose this module to untrusted pages or automation agents.

The package targets macOS 13 and needs a recent SDK to compile the macOS 26.2 passkey device-configuration check. Public API availability is checked at runtime. The diagnostic's authorization state describes the process running it, not a separately signed Kumo application. A supported API or a configured device alone does not prove entitlement approval, successful authentication, or Apple Passwords website fill.

Validation on 2026-10-18: `swift build` passed using Xcode's macOS 26.5 SDK and Swift 6.3.2. The default `xcrun` SDK is 27.0; its public headers/Swift interfaces were separately inspected. The compiled `status` command returned valid JSON without requesting authorization; this Mac reported the browser API available, a configured passkey device, authorization `notDetermined`, and the Passwords app installed. `help` returned success and an unknown command returned exit code 64. The launcher and authorization request were compiled but not invoked. Native passkey completion and password fill were not tested or claimed. All three compile-only SDK audit checks passed against the selected Xcode 26.5 SDK. The native AppKit probe was visually inspected on macOS 27.0.1 and both empty fields showed enabled AutoFill → Passwords actions; the picker was not selected or unlocked.

After the Xcode update and license acceptance, the whole Swift package and three compile-only API checks passed again with Xcode 27.1, SDK 27.0 and Swift 6.4. The rebuilt diagnostic's `status` command returned the same availability/authorization results without requesting consent or reading credentials. The native Chromium panel's 93 synthetic assertions also passed against the newly selected SDK. No Passwords picker or credential transaction was opened.
