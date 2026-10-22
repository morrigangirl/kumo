# GitHub Release updates

Kumo downloads browser updates from
[`morrigangirl/kumo` Releases](https://github.com/morrigangirl/kumo/releases).
The stable feed is the `appcast.xml` asset of the latest published release:

```text
https://github.com/morrigangirl/kumo/releases/latest/download/appcast.xml
```

Each feed item points to the browser ZIP on its exact release tag. Kumo requires
Sparkle Ed25519 signatures for both the ZIP and the entire appcast, verifies
before extraction, and rejects an invalid feed even after a timeout. Production
updates also require Apple Developer ID signing and notarization. Downloading a
public update does not require a GitHub account or repository token.

The official Sparkle distribution is pinned in
[`config/sparkle-lock.json`](../config/sparkle-lock.json). The dedicated release
key is in the build Mac's login Keychain under `app.kumo.browser.release`; only
its public key is in [`config/release.json`](../config/release.json). The release
tools do not export private keys or accept them as command arguments.

## Published history

[Kumo 0.1.2, build 202610210003](https://github.com/morrigangirl/kumo/releases/tag/v0.1.2-202610210003)
was published on October 21, 2026. Its signed app, notarization, update/archive
signatures and five published assets passed the recorded verification. See
[0.1.2 production validation](security-audits/2026-10-21/0.1.2-production-release.md).
Published artifacts and tags remain immutable.

[Kumo 0.2.0, build 202610210004](https://github.com/morrigangirl/kumo/releases/tag/v0.2.0-202610210004)
is the current published release, from source
`8329043adc37008a53adcf1c7cbd11c702578a4b`. It provides the browser update ZIP and
complete notarized Apple installer, plus appcast, provenance manifest, notes and
checksums. The [production audit](security-audits/2026-10-22/0.2.0-production-release.md)
records exact publication, tag, six-asset and signed-feed verification. Clean-Mac
administrator installation remains unqualified.

The examples below document the release construction flow with the 0.2 tuple.
For future releases use a higher build, the new reviewed commit and fresh output
paths. Never recreate the published 0.2 tag or overwrite its assets.

Kumo 0.2 moves product controls into native browser Settings and removes the Kumo
product extension. PhishLang defaults on for new profiles and unset preferences;
explicit opt-outs are preserved. An enabled preference does not imply that the
model is ready. Desktop AI access remains separately disabled until the user
allows it. Ordinary third-party extensions remain supported.

Historically, 0.1.0 excluded PhishLang; 0.1.1 and 0.1.2 included its experimental
checkpoint with warnings off by default. On October 20, 2026, the owner accepted
the paper's CC BY 4.0 interpretation for the authors' repository/checkpoint and
authorized distribution with attribution and change notices. This decision is
bound to the exact checkpoint; it is distinct from upstream license evidence.
The matching decision, citation and license notices remain required in native
0.2 packages. See [phishing protection](phishing-protection.md).

## Prerequisites and release identity

Commit reviewed source and increase `build` in `config/release.json` for every
release, including a rebuild of the same marketing version. Marketing versions
have three decimal components and cannot decrease. Tags use
`v<version>-<build>`. The publisher checks all remote releases, including drafts,
and refuses reused/lower build counters or an ambiguous historical tag.

Update `docs/releases/<version>.md`, finish qualification, and create/push the tag
at the exact final reviewed commit. Never recreate or retarget a published tag.
For a future release, set `KUMO_VERSION` and `KUMO_BUILD` to that reviewed
configuration, then create its new tag once:

```sh
git tag -a "v${KUMO_VERSION}-${KUMO_BUILD}" -m "Kumo ${KUMO_VERSION}"
git push origin "v${KUMO_VERSION}-${KUMO_BUILD}"
```

Use an Apple Silicon build Mac with the [source-build prerequisites](source-build.md),
Xcode and its accepted license, Swift, the documented Python versions, GitHub CLI,
and sufficient storage for a full Chromium build. Model conversion uses pinned
Python 3.9 wheels on the build host; Python and model conversion tools are not
installed on users' Macs. The bundled, pinned Node runtime is a separate signed
payload; users do not need a system Node installation.

Three signing capabilities are distinct:

| Purpose | Required identity or key |
| --- | --- |
| Browser, helpers and Setup developer payload | Carson Press LLC Developer ID Application certificate and private key |
| Standard public Apple installer | Carson Press LLC Developer ID Installer certificate and private key |
| Update ZIP and appcast | Configured Sparkle Ed25519 Keychain key |

An existing `notarytool` Keychain profile must work in the signing session.
An approved browser-passkey provisioning profile is optional and does not itself
provide Apple Passwords filling. See [production signing](signing.md).

For the complete installer, prepare the exact original Cisco package from
`config/clamav-lock.json`, matching ClamAV source/license inputs, the pinned
unmodified runtime at `/usr/local/clamav`, and current signed definitions.
Packaging verifies those inputs; it does not install the runtime on the build
Mac. Define `KUMO_CLAMAV_DATABASE` as the prepared database directory containing
all three `.cvd` files and their matching detached signatures. Its signed daily
timestamp must satisfy the 72-hour policy when the installer is assembled.
See the [installer build and trust boundary](../native/installer/README.md).

## Prepare the browser update

Prepare pinned tools/data, complete the locked source build, and package its
finished app. Use the reviewed commit in an isolated source workspace. An
upstream preview app is not eligible for a release.

```sh
python3 scripts/prepare-release-vendor.py
python3 scripts/prepare-sparkle.py
python3 scripts/prepare-agent-runtime.py
python3 scripts/prepare-malware-feed.py
/usr/bin/python3 scripts/prepare-phishlang.py
scripts/build-source.sh build --work-dir build/release-source-0.2.0-202610210004
python3 scripts/package.py \
  --engine-app build/release-source-0.2.0-202610210004/recipe/build/src/out/Default/Chromium.app

python3 scripts/github-release.py doctor
python3 scripts/github-release.py prepare \
  --app dist/Kumo.app \
  --output dist/github-release-base/v0.2.0-202610210004 \
  --notes docs/releases/0.2.0.md \
  --identity 'EXISTING_DEVELOPER_ID_APPLICATION_SHA1' \
  --notary-profile 'EXISTING_NOTARYTOOL_PROFILE'
```

If `build/agent-runtime` already exists, use the preparer's `--verify` mode rather
than overwriting it. Add `--notary-keychain` when the profile requires an explicit
Keychain path. Add `--profile` only for an existing approved browser-passkey
profile.

`prepare` signs a separate copy. It requires a clean committed checkout,
completed source receipt, exact version/feed configuration, the configured
Ed25519 key, accepted notarization, stapling and Gatekeeper assessment. It
preserves the input app and creates no GitHub release.

This first stage creates **five base assets**. They are sufficient for inspecting
the signed browser update, but **0.2 and later cannot upload or publish without
the complete notarized installer**.

## Add the complete installer

Use the exact signed browser from the prepared ZIP as the Setup input. Its
CodeDirectory hash must match the app inside the public installer. Build the
current release Setup executable; an older binary without `--package-policy`
will be rejected.

```sh
mkdir -p dist/installer/v0.2.0-202610210004
ditto -x -k \
  dist/github-release-base/v0.2.0-202610210004/Kumo-0.2.0-202610210004-macos-arm64.zip \
  dist/installer/v0.2.0-202610210004/browser
xcrun swift build --package-path native/installer \
  --scratch-path build/installer-native -c release --arch arm64
KUMO_SETUP_BIN=$(xcrun swift build --package-path native/installer \
  --scratch-path build/installer-native -c release --arch arm64 --show-bin-path)
python3 scripts/build-installer.py \
  --app dist/installer/v0.2.0-202610210004/browser/Kumo.app \
  --definitions "$KUMO_CLAMAV_DATABASE" \
  --executable "$KUMO_SETUP_BIN/KumoSetup" \
  --output 'dist/installer/v0.2.0-202610210004/Kumo Setup.app' \
  --sign-for-package \
  --identity 'EXISTING_DEVELOPER_ID_APPLICATION_SHA1'
python3 scripts/build-installer-pkg.py \
  --setup-app 'dist/installer/v0.2.0-202610210004/Kumo Setup.app' \
  --output dist/installer/v0.2.0-202610210004/Kumo.pkg \
  --identity 'Developer ID Installer: Carson Press LLC (PV65ZWXCWX)' \
  --notary-profile 'EXISTING_NOTARYTOOL_PROFILE'
python3 scripts/github-release.py with-installer \
  --artifacts dist/github-release-base/v0.2.0-202610210004 \
  --installer dist/installer/v0.2.0-202610210004/Kumo.pkg \
  --output dist/github-releases/v0.2.0-202610210004
```

`Kumo Setup.app` is a signed nested build intermediate, not separately notarized
in this flow. `--sign-for-package` creates no standalone ZIP or Apple submission;
notarization, stapling and Gatekeeper checks apply to the outer distribution. The public fresh
installation flow is the standard `.pkg`; it installs ordered Cisco components,
then invokes Kumo's dedicated package helper without a nested Installer session.
Definitions, scheduled updates and a harmless scan are required for readiness.
Normal failure restores the previous browser; Cisco's separate components are
not rolled back. Actual installation/upgrade/recovery still needs target-Mac
acceptance testing. Signing/notarization does not replace those checks.

`with-installer` independently authenticates the actual package: trusted Carson
Press Installer signature, stapled ticket, Gatekeeper, fixed scripts/targets,
sealed Setup/browser and exact Cisco component provenance. It matches browser
version, build, team and CodeDirectory hash against the actual update ZIP. It
never trusts an adjacent installer receipt or installs the package.

It creates a new, exclusive **six-asset directory**, preserving the original base
directory. ZIP, appcast and release notes remain byte-identical. The added
installer record is bound into `release.json` and `SHA256SUMS` is regenerated.

| Final asset | Purpose |
| --- | --- |
| `Kumo-<version>-<build>-macos-arm64.zip` | Signed, stapled browser for the automatic updater; `ditto` preserves framework symlinks |
| `Kumo-<version>-<build>-macos-arm64.pkg` | Signed, notarized complete Apple installer for initial installation/repair |
| `appcast.xml` | Signed feed pointing to the exact ZIP, with its signature, size and platform requirements |
| `release.json` | Public source/app provenance and verified installer identity, size and digest |
| `release-notes.md` | Exact reviewed notes |
| `SHA256SUMS` | Digests of the other five assets |

The appcast continues to deliver the browser ZIP. The installer is a separate
release asset; its trust comes from Apple signing/notarization and independent
payload verification. An unsigned review package cannot enter this release flow.
All assets must be regular single-link files, and binary assets must fit GitHub's
2 GiB limit. Existing outputs are never overwritten. Timestamped Apple signatures
mean independent builds are not promised identical bytes.

## Upload and publish

The GitHub CLI must already be signed in with release permissions. Source must
remain the clean reviewed checkout with its exact pushed tag. Upload defaults
to a draft and, for native 0.2+, requires all six verified assets:

```sh
python3 scripts/github-release.py verify \
  --artifacts dist/github-releases/v0.2.0-202610210004
python3 scripts/github-release.py upload \
  --artifacts dist/github-releases/v0.2.0-202610210004
```

The tool checks monotonic releases, uploads without `--clobber`, downloads every
draft asset, and reruns verification. A partial draft resumes only when existing
assets match exactly. Notes must match `release-notes.md`; unexpected assets or
changed bytes stop publication. Review the qualified draft, then publish:

```sh
python3 scripts/github-release.py upload \
  --artifacts dist/github-releases/v0.2.0-202610210004 --publish
```

A command example does not establish publication. For each future release,
publish only after final qualification and notes review. Every stable release has its own
`appcast.xml`; GitHub's latest feed URL switches with that complete release.
Never replace old published bytes, put unsigned downloads in the feed, or use a
GitHub API response as an appcast. A correction needs a higher build.

## Dedicated GitHub Actions runner

The manual [release workflow](../.github/workflows/release.yml) is restricted to
this repository's protected `main` branch and a dedicated self-hosted Apple
Silicon runner labeled `kumo-release`. Its `github-release` environment should
require maintainer approval and permit only `main`. Do not expose this signing
runner to pull-request jobs. A checkout-v6-compatible Actions Runner is required.

The runner needs the source/model prerequisites above, both Developer ID
identities, the Sparkle key, accessible notary profile, a current ClamAV runtime
and signed database, exact original vendor package, matching source archive and
notices. The workflow does not install prerequisites, export certificates,
import private keys or bypass Keychain prompts.

| Environment variable | Value |
| --- | --- |
| `KUMO_DEVELOPER_ID_SHA1` | Installed Developer ID Application identity selector |
| `KUMO_INSTALLER_IDENTITY` | Installed Carson Press Developer ID Installer identity name |
| `KUMO_NOTARY_PROFILE` | Existing accessible notarytool Keychain profile name |
| `KUMO_NOTARY_KEYCHAIN` | Optional maintainer Keychain path; forwarded to browser, Setup and package notarization |
| `KUMO_CLAMAV_DATABASE` | Real directory containing current signed CVD databases and detached signatures |
| `KUMO_PASSKEY_PROFILE` | Optional approved Developer ID browser-passkey provisioning profile path |

The workflow prepares the exact checked-out source, builds native Kumo, signs
and notarizes the browser, prepares five base update assets, builds/signs/notarizes
the complete installer, attaches it as the sixth asset, and uploads a verified
draft. The **publish** input defaults false. The scoped GitHub token is available
only to upload. The updated six-asset workflow has not been dispatched as part
of local implementation.

Checkout uses `clean: false` to retain ignored source/download caches, then
refuses tracked or untracked source changes. Vendor preparation verifies existing
checkouts before moving to locked revisions; it does not reset local changes.
Keep earlier release source trees available for diagnosis.

References: [Sparkle publishing](https://sparkle-project.org/documentation/publishing/),
[Sparkle signature policy](https://sparkle-project.org/documentation/customization/),
[GitHub Release CLI](https://cli.github.com/manual/gh_release_create),
[GitHub release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
