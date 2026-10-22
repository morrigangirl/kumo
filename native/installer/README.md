# Kumo Installer

The user-facing installer is a standard Apple **`.pkg`** for Apple Silicon Macs
running macOS 13 or later. The user opens it in Apple Installer and approves
macOS administrator authorization. Its ordered components install Cisco's
antivirus runtime before Kumo's signed helper verifies that runtime and publishes
the browser in `/Applications/Kumo.app`. The current console account's virus
definitions and automatic updates must be ready, including a real harmless scan,
before installation reports success. Kumo must be closed before installation.

[Kumo 0.2.0, build 202610210004](https://github.com/morrigangirl/kumo/releases/tag/v0.2.0-202610210004)
provides the [complete notarized installer](https://github.com/morrigangirl/kumo/releases/download/v0.2.0-202610210004/Kumo-0.2.0-202610210004-macos-arm64.pkg).
The [production audit](../../docs/security-audits/2026-10-22/0.2.0-production-release.md)
records the exact source, native/runtime, Apple and public-release checks.
Building, signing, expanding, verifying or notarizing a package does not install
it or establish installation on a clean/older Mac, upgrade/recovery or 8 GB
hardware qualification. The examples below create fresh local outputs; never
overwrite a published release asset or reuse its tag/build for a correction.

The payload contains the native Chromium-based browser, the local PhishLang
model and sandboxed helper, the bundled agent runtime, Cisco ClamAV 1.5.4,
current signed virus definitions, and upstream source/license notices. Product
settings and protections belong to the browser; no Kumo extension or website
extension-access grant is required. Ordinary third-party extensions remain
supported.

PhishLang is experimental and **enabled by default** for new profiles and
previously unset preferences. Existing explicit opt-outs are preserved during
migration. Eligible page samples stay local and exclude filled form values and
other private fields. An enabled preference is distinct from model readiness;
Kumo reports unavailable or initializing protection honestly. Desktop AI browser
access remains separately controlled in Kumo Settings.

## Developer payload and signing identities

`Kumo Setup.app` is the signed internal helper used inside the standard
package. Opening it directly or requesting its retired standalone administrator
mode fails with guidance to use the standard `.pkg`; there is one privileged
installation transaction. The application
needs a **Developer ID Application** identity. The outer standard package needs
an additional **Developer ID Installer** identity. Use `--sign-for-package` for
the nested Setup: it signs and verifies the payload, creates no standalone ZIP
and does not separately notarize Setup. The outermost standard `.pkg` must pass
Apple notarization, stapling and Gatekeeper checks before public distribution.
The browser inside it remains independently signed and notarized.

The standard package uses Cisco's libraries, programs and documentation as
separate ordered components. They are extracted only after the exact original
Cisco product hash and signature verify. Their payload, scripts, BOM and metadata
are preserved through re-flattening and final package expansion. The new inner
component archives are not independently Cisco-signed; the intact Cisco-signed
original is retained inside the sealed Setup payload for provenance. Kumo's
outer Installer signature covers the resulting product.

## Build

Prepare a completed, Developer ID-signed, notarized Apple Silicon Kumo production
app with its native integration, bundled agent runtime, download scanner and
PhishLang included. Native builds have one canonical metadata file at
`Contents/Resources/kumo-build-info.json`; ambiguous canonical and historical
records are rejected. The standard package builder intentionally rejects an old
extension-based app or a helper lacking its dedicated package mode, retired
standalone-install policy and full-readiness definition rollback policy.

Obtain the exact original Cisco package from `config/clamav-lock.json`. The
matching official source archive is `clamav-1.5.4.tar.gz`, 63,702,396 bytes, SHA-256
`1af1117a228f1b5bc7fa91a0dabc37848a99e7d25188e9be8043332ce721dfd3`.
Default source and notice inputs are `build/installer-inputs/clamav-1.5.4.tar.gz`
and `build/installer-inputs/notices/`. Generated inputs are excluded from Git.

The packaging Mac must already have the untouched pinned runtime available for
signature verification and usable signed definitions. Packaging does not install
that prerequisite. Definition freshness is checked against the daily database's
signed timestamp and the runtime policy's 72-hour limit.

Build the current native executable in a new local work directory. Set
`KUMO_RELEASE_APP` to the browser extracted from the exact prepared production
update ZIP, not a different re-signed copy. Its CodeDirectory hash must match the
browser later attached to the release. Use your existing identity and notary
profile; these examples create no credentials or published output.

```sh
mkdir -p dist
KUMO_INSTALLER_WORK=$(mktemp -d "$PWD/dist/installer-review.XXXXXX")
KUMO_RELEASE_APP='/absolute/path/to/extracted/Kumo.app'
xcrun swift build --package-path native/installer \
  --scratch-path "$KUMO_INSTALLER_WORK/native-build" -c release --arch arm64
KUMO_SETUP_BIN=$(xcrun swift build --package-path native/installer \
  --scratch-path "$KUMO_INSTALLER_WORK/native-build" -c release --arch arm64 --show-bin-path)
python3 scripts/build-installer.py \
  --app "$KUMO_RELEASE_APP" \
  --definitions "$HOME/Library/Application Support/KumoSecurity/ClamAV/database" \
  --executable "$KUMO_SETUP_BIN/KumoSetup" \
  --output "$KUMO_INSTALLER_WORK/Kumo Setup.app" \
  --sign-for-package \
  --identity 'EXISTING_DEVELOPER_ID_APPLICATION_SHA1'
```

The normal nested signer verifies the complete signed payload; its receipt
truthfully reports `notarized: false`, `nestedPackageOnly: true` and
`outerPackageNotarizationRequired: true`. That intermediate is not ready for
independent public distribution. Actual native-temp `/var` and `/private/var`
verification passed all 617 manifest files for the repaired 0.2 Setup; this does
not establish administrator installation.

The default vendor input is
`build/clamav-downloads/clamav-1.5.4.macos.universal.pkg`; `--vendor-package`,
`--runtime`, `--source-archive` and `--notices` accept explicit input locations.
The manifest binds regular payload files to SHA-256 hashes and records the
browser's version, build and CodeDirectory hash. Setup signing preserves nested
Kumo and Cisco signatures. Nested signing creates no developer ZIP; the public
installation asset is the standard package.

Build that package from the signed Setup payload:

```sh
python3 scripts/build-installer-pkg.py \
  --setup-app "$KUMO_INSTALLER_WORK/Kumo Setup.app" \
  --output "$KUMO_INSTALLER_WORK/Kumo.pkg" \
  --identity 'Developer ID Installer: Carson Press LLC (PV65ZWXCWX)' \
  --notary-profile 'EXISTING_NOTARYTOOL_PROFILE' \
  --notary-keychain "$HOME/Library/Keychains/login.keychain-db"
```

Omitting the package identity and notary options creates an **unsigned review
package** with public-distribution readiness explicitly false. It must not be
presented as a signed release. Build plans and diagnostics are preserved beside
the output in a private `.pkg-build` directory. No certificate, account or
Keychain credential is created by these commands.

Release validation calls `verify_public_package` independently of any adjacent
receipt. It checks the trusted Carson Press Installer signature, stapled ticket,
Gatekeeper, fixed installation rules and scripts, the sealed Setup/browser
identity, and exact Cisco component provenance. The embedded browser's version,
build and CodeDirectory hash must match the browser release archive.

## Installation boundary

Apple Installer installs Cisco's three components first. Kumo's package helper
never starts a nested Installer session. Its fixed script copies the entire
signed Setup app into a root-owned mode-0700 snapshot under `/private/var/tmp`,
verifies that copy, and executes only the signed dedicated package action.
There is no custom destination, executable, runtime, account or shell argument.

Before browser publication, the helper verifies the sealed payload, native
metadata, Cisco receipts and actual pinned runtime. It refuses app or engine
downgrades. The previous and staged browser update leases remain held through
atomic publication and console-user readiness. A normal readiness failure
restores the previous app or withdraws an incomplete first installation. If
restoration cannot be proved safe, the protected transaction is preserved for
repair. Cisco's separately installed components are not rolled back with Kumo.
Sources and notices are saved under
`/Library/Application Support/Kumo/Installer Sources/<build>/`.

The documented bundle script timeout is 3,600 seconds on macOS versions newer
than 15. Older systems retain Apple's default ten-minute limit. Abrupt process
or system termination can leave a protected transaction requiring a retry or
repair; crash recovery and target filesystem behavior require installation
acceptance testing.

User initialization runs with the captured console account's real and effective
UID, never as root. Its home comes from the account database and it uses the
private `Library/Application Support/KumoSecurity/ClamAV/` subtree. Bundled
definitions are signature-checked before activation; stale definitions require
a successful update. Initialization enables the exact
`app.kumo.clamav-definitions` user LaunchAgent, confirms it is loaded, checks the
sandboxed scanner's status and submits a harmless file through the real
file-descriptor scan protocol. A missing or failed scan cannot report Ready.
Existing browser profiles and explicit protection choices are preserved.

When bundled definitions must replace an existing directory, the previous
directory remains in the private transaction until automatic updates, scanner
status and the final harmless scan all succeed. A normal failure restores the
previous directory; a first installation withdraws its incomplete definitions.
If directory identity changes make rollback unsafe, the backup is preserved
and setup reports its private recovery location instead of overwriting another
directory. Abrupt termination recovery remains a separate acceptance check.

The source archive includes ClamAV's code, build files, internal libraries and
vendored Rust dependencies. License notices retain their original paths inside a
separate archive. This is not a verified complete source set for the external C
libraries statically linked by Cisco; their full build provenance has not been
reconstructed. Cisco runtime binaries and their code signatures are unchanged.

## Checks

```sh
python3 -m unittest scripts.test_installer_pkg scripts.test_installer_package -v
xcrun swift test --package-path native/installer \
  --scratch-path build/installer-native-tests
```

Tests use synthetic fixtures and mocked trust/process boundaries. Directory
transaction tests execute the shipping publish/commit/rollback code on owned
temporary directories, including first installation, late readiness failure
and replaced-path recovery. Actual helper subprocess tests reject direct open
and the retired administrator mode without reading payloads or showing an
administrator prompt. On macOS, a
clearly noninstallable fixture also exercises the actual Apple package build and
expansion tools. Neither command performs a system installation or executes an
Installer script. Native tests cover policy and controlled temporary files.

An assembled signed Setup supports read-only `--self-test`, `--package-policy`
and `--verify-payloads` checks. The private `--install-package-root` and
`--initialize-user` modes perform installation or initialization and must not be
used as build smoke tests. The former `--install-root` mode and no-argument
application route are retired and cannot install or authorize changes.

Full administrator installation, upgrade/rollback, abrupt termination recovery,
and performance on the owner's MacBook Air remain separate acceptance checks.
The older `KumoMalwareSetup` tool remains available for advanced repairs; see
[download antivirus setup](../../docs/download-antivirus.md).
