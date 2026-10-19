# GitHub Release updates

Kumo's browser app updates come from
[`morrigangirl/kumo` Releases](https://github.com/morrigangirl/kumo/releases).
The stable appcast is the `appcast.xml` asset of the latest published release:

```text
https://github.com/morrigangirl/kumo/releases/latest/download/appcast.xml
```

Each feed item points to a ZIP on its exact release tag. The app requires
Sparkle Ed25519 signatures for both the ZIP and the entire appcast, verifies
before extraction, and does not let an invalid feed become acceptable after a
timeout. Apple Developer ID signing and notarization are also mandatory for a
production update. A GitHub account or repository token is not needed to
download these public updates.

The pinned official Sparkle distribution is recorded in
[`config/sparkle-lock.json`](../config/sparkle-lock.json). The dedicated release
signing key already exists in the build Mac's login Keychain under
`app.kumo.browser.release`. Only its public key is in
[`config/release.json`](../config/release.json). The release tools do not export
private keys or accept private keys as command arguments.

This update channel is implemented but has not been published. The Carson Press
LLC **Developer ID Application** identity is now installed on the build Mac,
and the notarization Keychain profile has been configured and authenticated.
Successful notarization and stapling are still required before the production
app can be published with updates enabled. Apple
Development signing remains a local development build. See [production
signing](signing.md) for those checks.

The first public binary excludes the experimental PhishLang checkpoint and its
native inference helper. Local dangerous-domain blocking and ClamAV download
scanning remain included. Package with `--without-phishlang`; the release
workflow uses this option. Model preparation and its Python 3.9 conversion
dependencies are not required for this release.

The optional development checkpoint remains marked
`localDevelopmentOnly: true`. Production preparation and verification reject that metadata before
signing or notarization if it is included. Its redistribution status must be
resolved before a future model-inclusive public binary. The paper's license
alone does not change this build metadata.

## Prepare a release

Commit the reviewed source and increase `build` in `config/release.json` for
every release, including a rebuild with the same marketing version. Builds are
positive integers; the initial `202610190001` also exceeds the old engine-based
bundle version. Marketing versions contain three decimal components and cannot
decrease. Release tags use `v<version>-<build>`, so the publishing tool can check
all existing GitHub releases, including drafts, for a reused or lower build.
An old release with an unknown tag shape stops publishing for explicit
reconciliation rather than silently assuming its version.

Update `docs/releases/<version>.md`, then tag the exact reviewed commit and push
that tag. For the current configured version:

```sh
git tag -a v0.1.0-202610190001 -m 'Kumo 0.1.0'
git push origin v0.1.0-202610190001
```

Prepare the pinned tools and data, finish the locked source build and package
its completed app. Use an isolated source workspace for the reviewed release
commit; the [source build instructions](source-build.md) describe build
requirements. Do not use the upstream preview for a release.

```sh
python3 scripts/prepare-sparkle.py
python3 scripts/prepare-release-vendor.py
python3 scripts/prepare-malware-feed.py
scripts/build-source.sh build --work-dir build/release-source-0.1.0-202610190001
python3 scripts/package.py \
  --engine-app build/release-source-0.1.0-202610190001/recipe/build/src/out/Default/Chromium.app \
  --without-phishlang

python3 scripts/github-release.py doctor
python3 scripts/github-release.py prepare \
  --app dist/Kumo.app \
  --output dist/github-releases/v0.1.0-202610190001 \
  --notes docs/releases/0.1.0.md \
  --identity 'THE_40_CHARACTER_DEVELOPER_ID_SHA1' \
  --notary-profile 'EXISTING_NOTARYTOOL_KEYCHAIN_PROFILE'
```

`prepare` invokes the existing release signer on a separate copy. It requires a
clean committed checkout, verified source receipt, exact app version and feed
configuration, the configured Keychain Ed25519 key, successful notarization,
stapling and Gatekeeper assessment. If approved browser-passkey provisioning is
available, also pass `--profile` with that existing Developer ID profile. The
input app is preserved. No GitHub release is created by this command.

The output contains exactly five assets:

- `Kumo-<version>-<build>-macos-arm64.zip`: the signed, stapled app, archived by
  `ditto` with framework symlinks preserved.
- `appcast.xml`: the signed feed with plain text release notes, exact archive
  URL, Ed25519 signature, byte length, minimum macOS version and Apple silicon
  requirement.
- `release.json`: public source commit, source receipt checksum, app identity,
  notarization status, archive checksum and signature.
- `release-notes.md`: the reviewed release text.
- `SHA256SUMS`: checksums for the other four assets.

An unpublished preparation draft may exist before these assets are ready.
Replace its preparation body with the exact final `release-notes.md` before
using `upload`; the publisher refuses different notes or unexpected assets.
Create and push the exact source tag only after the final release source and
model scope are settled. Never publish a preparation draft without its verified
browser archive and signed appcast.

The tool extracts the finished ZIP and rechecks its real app signature,
notarization and source receipt before publishing the local output directory.
It refuses to overwrite an existing directory. Archives must be under GitHub's
2 GiB per-asset limit. The recipe is repeatable; timestamped Apple signatures
and notarization mean independent builds are not promised identical bytes.

## Upload and publish

The GitHub CLI must already be signed in with permission to create releases.
Uploading defaults to a **draft**:

```sh
python3 scripts/github-release.py verify \
  --artifacts dist/github-releases/v0.1.0-202610190001

python3 scripts/github-release.py upload \
  --artifacts dist/github-releases/v0.1.0-202610190001
```

The tool requires the exact source tag, checks all release build counters,
uploads without `--clobber`, and downloads the completed draft to verify the
bytes and signatures. A partial upload can resume only when the existing
assets match exactly. Published releases are never edited or overwritten by
this tool. Review the draft, then make it public and latest:

```sh
python3 scripts/github-release.py upload \
  --artifacts dist/github-releases/v0.1.0-202610190001 \
  --publish
```

Publish every stable release with its own `appcast.xml`; GitHub's
`latest/download/appcast.xml` URL then switches with that complete release.
Never put unsigned downloads or a GitHub API response in the appcast URL.
Keep old published assets available for existing feeds. If a faulty build must
be replaced, ship a new, higher build instead of replacing its bytes.

## Optional GitHub Actions runner

The manual [release workflow](../.github/workflows/release.yml) runs only for
this repository's protected `main` branch, using a dedicated self-hosted Apple
silicon runner labeled `kumo-release`. Configure its `github-release`
environment to require a maintainer's approval and allow only `main`. Do not
attach this signing runner to pull request workflows. A current Actions Runner
supporting checkout v6 is required.

Install Xcode and accept its license; provide the source build's documented
Node and storage prerequisites, and Python 3.12+ for safe Sparkle archive
preparation. The public release omits PhishLang, so it needs no model conversion
wheels or separate Python 3.9 runtime. Install the selected team's Apple
Development and Developer ID identities, the dedicated Sparkle key, and the existing notarytool profile
in that runner's Keychain. The Keychain must permit these signing tools in the
runner session. This workflow deliberately does not export certificates,
import private-key secrets, create signing accounts or bypass Keychain prompts.

Set these environment variables in the GitHub `github-release` environment:

| Variable | Value |
| --- | --- |
| `KUMO_DEVELOPER_ID_SHA1` | Public SHA-1 identity selector for the installed Developer ID Application certificate |
| `KUMO_NOTARY_PROFILE` | Name of the installed notarytool Keychain profile |
| `KUMO_PASSKEY_PROFILE` | Optional local path of the approved Developer ID browser-passkey profile |

The workflow builds the exact checked out commit, packages it with
`--without-phishlang`, signs and notarizes it,
prepares and verifies the assets, then uploads a draft. Its **publish** input
defaults to false. The scoped GitHub token is used only for the upload step.
The workflow itself has not been dispatched during local implementation.

Checkout deliberately uses `clean: false` to preserve the dedicated runner's
ignored `vendor/`, `build/` and download caches. It still refuses tracked or
untracked source changes before building. `prepare-release-vendor.py` obtains
the two exact public upstream commits from `config/source-lock.json` and the
macOS recipe's pinned submodules. It verifies clean existing checkouts before
moving them to a new locked revision; it never resets or deletes local vendor
changes. Each release source tree is named with the exact source commit so
prepared trees from earlier releases remain available for diagnosis.

References: [Sparkle publishing](https://sparkle-project.org/documentation/publishing/),
[Sparkle signature policy](https://sparkle-project.org/documentation/customization/),
[GitHub Release CLI](https://cli.github.com/manual/gh_release_create),
[GitHub release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
