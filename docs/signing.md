# Signing a Kumo release

Kumo's selected production team is **Carson Press LLC**, Team ID
`PV65ZWXCWX`, with bundle identifier `app.kumo.browser`. These public values
live in `config/apple-signing.json`. Selecting the team does not create a
certificate, enable a managed capability, or sign the app.

Local preview packaging requires the selected team's valid Apple Development
identity. There is no ad-hoc fallback: macOS library validation requires a
consistent team identity across Chromium and its framework. This remains a
development build. `scripts/sign-release.py`
implements the separate production step: it signs **every nested native code item** with
the chosen Carson Press Developer ID Application identity, retaining Chromium's
per-process entitlements and runtime policies.

App distribution and updates use [Kumo GitHub Releases](github-releases.md).
The separate native updater contains pinned Sparkle code and requires signed
feeds and archives. Its network checks remain disabled in development builds.
The release signer enables it only in a staging copy prepared with
`--notary-profile`; notarization must succeed before that copy is published.
Signing without notarization keeps update checks disabled. The GitHub release
tool requires notarization and verifies the finished archive before upload.

## Readiness and a reviewable plan

These commands read public certificate metadata, provisioning-profile metadata
when explicitly supplied, and the packaged app. They do not sign, upload,
register an App ID, export keys, or change the app:

```sh
python3 scripts/check-signing.py
python3 scripts/sign-release.py --doctor
python3 scripts/sign-release.py --dry-run
```

The doctor and dry run exit with status 1 when a prerequisite is missing. The
JSON report includes the exact team, identity candidates, ordered code items,
entitlement keys, signing flags, and blockers. Dry run also shows the commands
with temporary-path placeholders. It never creates a release staging copy.

At implementation time, this Mac had an Apple Development identity for the
selected team, but **no valid Developer ID Application identity** for it and
**no approved Kumo browser-passkey profile**. The current packaged app was the
upstream preview. These are release prerequisites, not tasks the script silently
performs. The Apple Developer portal, certificates, and profiles are never
changed by these tools.

## Sign a separate completed source build

First finish Chromium compilation and package the resulting app. Production
signing requires its embedded `build-info.json` to contain
`sourceCompiledLocally: true` and a verified `sourceBuildReceipt`, a valid strict
input signature, Kumo's expected bundle identifier, and its Swift launcher.
Both `engineVersion` and `sourceTargetVersion` must exactly match the current
source lock. Quit the input app before release preparation. An existing output
is always refused.

The source driver records the completed-build receipt only after Ninja and
upstream signing succeed. Packaging checks the original engine, framework, and
Info.plist hashes against it, checks the staged copy again before mutation, and
embeds a copy without local filesystem paths. The release signer checks its
strict shape, canonical checksum, version, source-lock hash, and current build
input fingerprint. These receipt hashes describe the checked source output
before Kumo re-signing; the final app's code signature protects the packaged
result. A supplied app or a Boolean alone cannot establish a completed source
build. This prevents accidental stale or arbitrary input claims and is not an
attestation against someone who can edit the workspace or receipt.

Once the selected team's **Developer ID Application** identity and private key
are already installed in Keychain, run:

```sh
python3 scripts/sign-release.py --dry-run \
  --identity 'THE_40_CHARACTER_IDENTITY_SHA1' \
  --output dist/releases/Kumo.app

python3 scripts/sign-release.py --sign \
  --identity 'THE_40_CHARACTER_IDENTITY_SHA1' \
  --output dist/releases/Kumo.app
```

Use the SHA-1 printed by `security find-identity -v -p codesigning`, not an
Apple Development or Developer ID Installer certificate. An exact identity
name also works; ambiguous matches fail. With only one eligible identity, the
identity option may be omitted. The tool checks that the identity is valid and
has the selected certificate OU and Developer ID Application certificate OID.
It uses Keychain through `codesign`; it never exports or reads private-key data.
Keychain can present its normal signing-access prompt.

The script copies the completed app beside the requested output, checks that
its CodeDirectory hash still matches the inspected input, and signs the copy
from the deepest children outward. It detects actual Mach-O files and code
bundles, follows no directory symlinks, and rejects symlinks outside the app.
Framework version aliases are not signed repeatedly. The framework, dylibs,
tools, helper apps, actual `Chromium` executable, and outer `Kumo` launcher are
all covered. Nested identifiers are retained where present; both primary
executables use CodeDirectory identifier `app.kumo.browser`.

After verifying the original copy, packaging and release signing remove
inherited app notarization tickets before changing signatures. Only real
`Contents/CodeResources` files with the ticket's `s8ch` magic are removed;
`Contents/_CodeSignature/CodeResources` resource seals and legacy symlinks are
preserved. An upstream ticket cannot authorize Kumo's changed code hashes.

Existing Chromium entitlements and policy flags are retained, with the pinned
upstream recipe's JIT entitlement supplied for Renderer and GPU helpers.
Hardened Runtime is enabled throughout. No broad JIT, unsigned-memory,
DYLD-environment, or library-validation exceptions are added. Debugger
entitlements and old App ID/team claims are removed; unsupported private or
identity-bound capabilities stop the operation for review. This tool never uses
`codesign --deep` to sign. Deep verification is used after explicit signing.

Every code item must then pass strict verification for all architectures,
Apple's Developer ID anchor requirement, the selected team OU, a secure
timestamp, its planned identifier/flags, and its exact planned entitlements.
The complete app passes deep strict verification again. Only then does Darwin's
exclusive atomic rename publish the separate output. A failure removes staging
and leaves the original app and any earlier release intact. A process guard
checks the input, output, and staging app before publication; it never kills
browser processes.

Signing alone produces a Developer ID-signed app. Without the notarization
option below, it is **not represented as a notarized release**.

## Optional approved browser-passkey capability

Apple's managed browser entitlement is
`com.apple.developer.web-browser.public-key-credential`. It authorizes passkey
registration/assertion for arbitrary relying parties; it is not permission to
read all saved website passwords.

Apple must approve this capability for the organization's Kumo App ID, and the
corresponding **Developer ID macOS distribution profile** must already be
available. Then supply that file explicitly:

```sh
python3 scripts/sign-release.py --dry-run \
  --identity 'THE_40_CHARACTER_IDENTITY_SHA1' \
  --profile /absolute/path/Kumo-Developer-ID.provisionprofile

python3 scripts/sign-release.py --sign \
  --identity 'THE_40_CHARACTER_IDENTITY_SHA1' \
  --profile /absolute/path/Kumo-Developer-ID.provisionprofile \
  --output dist/releases/Kumo.app
```

The public CMS payload is decoded with Apple's `security cms`. Validation
requires the selected team, exact `PV65ZWXCWX.app.kumo.browser` App ID, macOS
platform, a future expiration, all-device distribution, no development/debug
permission, the browser-passkey entitlement set to true, and inclusion of the
chosen signing certificate in `DeveloperCertificates`. The exact validated
profile bytes are embedded as `Contents/embedded.provisionprofile`. Its App ID,
team, and browser-passkey claims are added only to the two primary signatures.
Helper processes receive no browser-passkey claim.

Without `--profile`, old embedded profiles are removed from the release copy
and **no managed browser-passkey entitlement is granted**. An App ID setting,
certificate, edited plist, or ad-hoc signature cannot substitute for Apple's
approval. The profile checks are prerequisite checks, not proof that macOS has
accepted a live passkey request; that still needs runtime QA of the resulting
approved, signed app. The native user-mediated Apple Passwords sheet is a
separate feature described in `apple-passwords.md`.

## Optional notarization and stapling

Use an **existing** `notarytool` Keychain profile. This tool accepts its profile
name only; there are no password, token, Apple ID, or environment-dump options.
For example, after inspecting the same plan:

```sh
python3 scripts/sign-release.py --dry-run \
  --identity 'THE_40_CHARACTER_IDENTITY_SHA1' \
  --notary-profile 'Carson Press Notary'

python3 scripts/sign-release.py --sign \
  --identity 'THE_40_CHARACTER_IDENTITY_SHA1' \
  --notary-profile 'Carson Press Notary' \
  --output dist/releases/Kumo.app
```

This option uploads **only the signed staging copy**, archived with `ditto`,
using `xcrun notarytool submit --keychain-profile … --wait --output-format json`.
It requires both a successful command and an `Accepted` response with a
submission ID. It then runs `stapler staple`, `stapler validate`, Gatekeeper
assessment, and repeat signature/team checks before publication. Rejection,
network/authentication failure, or a stapling failure leaves no published output.
Notarization is an upload to Apple and occurs only with `--sign` plus the
explicit `--notary-profile` option. The script does not create Keychain
credentials or print the full service response.

## Validation and remaining release QA

The script's syntax, CLI help, metadata-only doctor/dry-run, profile rejection
rules, entitlement cleanup, code ordering, and atomic no-overwrite publication
can be tested without a signing identity. The production certificate/signing,
managed-profile authorization, notarization, stapling, Gatekeeper launch, and
live passkey success paths remain unexecuted until the missing prerequisites
exist. Successful static signature verification does not replace launching the
release and checking navigation, helpers/JIT, extensions, native Passwords, and
approved passkeys on the target macOS version.

References:

- [Apple: Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac/)
- [Apple: Inside Code Signing — Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
- [Apple: Browser public-key credential entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.web-browser.public-key-credential)
- [Apple: Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
- [Apple: Migrating to the latest notarization tool](https://developer.apple.com/documentation/technotes/tn3147-migrating-to-the-latest-notarization-tool)
- Pinned local reference: `build/source/recipe/sign_and_package_app.sh` and
  `build/source/recipe/entitlements/`.
