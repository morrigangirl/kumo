#!/usr/bin/env python3
"""Compile declarations only. Never runs credential APIs or queries a user's keychain."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def command(*args):
    return subprocess.run(args, capture_output=True, text=True, check=False)


sdk_result = command("xcrun", "--show-sdk-path")
if sdk_result.returncode:
    raise SystemExit(sdk_result.stderr)
inspected_sdk = Path(sdk_result.stdout.strip())
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--sdk", type=Path, help="SDK for compile-only probes; defaults to the selected Xcode toolchain's SDK")
options = parser.parse_args()
compiler_result = command("xcrun", "--find", "swiftc")
if compiler_result.returncode:
    raise SystemExit(compiler_result.stderr)
compiler = Path(compiler_result.stdout.strip())
toolchain_sdk = compiler.parents[4] / "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
sdk = options.sdk or (toolchain_sdk if toolchain_sdk.exists() else inspected_sdk)
settings = json.loads((sdk / "SDKSettings.json").read_text())

probes = {
    "native_semantic_fields_and_scoped_password_request": {
        "expected": "accepted",
        "source": """
import AppKit
import AuthenticationServices
import Security
@MainActor func neverInvoked() {
    let username = NSTextField()
    username.contentType = .username
    let password = NSSecureTextField()
    password.contentType = .password
    _ = ASAuthorizationPasswordProvider().createRequest()
    _ = kSecAttrAccessGroup
    _ = kSecUseDataProtectionKeychain
}
""",
    },
    "browserenginekit_autofill_type_on_native_macos": {
        "expected": "rejected",
        "diagnosticContains": "cannot find type 'BEAutoFillTextSuggestion'",
        "source": """
import BrowserEngineKit
func neverInvoked(_ suggestion: BEAutoFillTextSuggestion) {}
""",
    },
    "credential_data_manager_password_save_on_macos": {
        "expected": "rejected",
        "diagnosticContains": "unavailable in macOS",
        "source": """
import AppKit
import AuthenticationServices
@available(macOS 26.2, *)
@MainActor func neverInvoked(_ window: NSWindow) async throws {
    let credential = ASPasswordCredential(user: "synthetic", password: "synthetic")
    let scope = ASAutoFillURLScope(host: "example.invalid")
    try await ASCredentialDataManager().save(password: credential, for: scope, anchor: window)
}
""",
    },
}

report = {
    "sdkVersion": settings.get("Version"),
    "sdkPath": str(sdk),
    "xcrunDefaultSDKVersion": json.loads((inspected_sdk / "SDKSettings.json").read_text()).get("Version"),
    "xcrunDefaultSDKPath": str(inspected_sdk),
    "compilerPath": str(compiler),
    "credentialAPIsExecuted": False,
    "keychainQueriesExecuted": False,
    "probes": {},
}
all_expected = True
with tempfile.TemporaryDirectory(prefix="kumo-sdk-audit-") as directory:
    for name, probe in probes.items():
        source_path = Path(directory) / (name + ".swift")
        source_path.write_text(probe["source"])
        result = command(str(compiler), "-typecheck", "-sdk", str(sdk), str(source_path))
        outcome = "accepted" if result.returncode == 0 else "rejected"
        expected = outcome == probe["expected"]
        if "diagnosticContains" in probe:
            expected = expected and probe["diagnosticContains"] in result.stderr
        all_expected = all_expected and expected
        report["probes"][name] = {
            "outcome": outcome,
            "matchesAuditedExpectation": expected,
            "diagnostic": "\n".join(
                line.replace(str(source_path), "<compile-only-probe>")
                for line in result.stderr.splitlines()
                if "error:" in line
            ),
        }

report["matchesAuditedExpectations"] = all_expected
print(json.dumps(report, indent=2, sort_keys=True))
raise SystemExit(0 if all_expected else 1)
