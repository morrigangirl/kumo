# Native GitHub Releases updates

Kumo uses the pinned Sparkle 2.10.0 framework prepared by
`scripts/prepare-sparkle.py`. `scripts/build-updater.sh` verifies that preparation
and builds `build/updater-native/KumoUpdater`. Packaging places the executable in
`Kumo.app/Contents/Helpers/KumoUpdater.app/Contents/MacOS/`, with the verified
framework in the companion's `Contents/Frameworks/` directory. No build-machine
path is needed after packaging.

The companion runs independently because the native browser launcher becomes
Chromium with `execv`. Sparkle's `hostBundle` and `applicationBundle` both target
the outer Kumo app; the companion itself remains alive through installation.
It provides three fixed commands:

- `--status`: bounded JSON diagnostics; no network requests or updater startup.
- `--check`: native, user-initiated update UI.
- `--background`: Sparkle's automatic check scheduler while Kumo is running.

The launcher starts the background companion before taking its browser lock and
only if the same installed companion is not already running. Launch Services
reopening the companion brings its manual update UI forward. A redundant
companion forwards a manual check to the existing process using a notification
whose name includes a hash of the canonical installed app path. A background
companion exits when there is no browser process and no active update cycle.
No persistent system service is installed.

## Release policy

The helper derives its target from its own exact nested bundle location. It
rejects a symlinked/copy-out helper, a mismatched bundle identifier, configuration
version, or build. The public release configuration is read from the sealed
`Contents/Resources/kumo-update-config.json` resource. Only
`https://github.com/morrigangirl/kumo/releases/latest/download/appcast.xml` is
accepted. Per-user Sparkle feed overrides do not replace this pinned feed.

Every network check requires `enabled: true`, a canonical 32-byte Ed25519 public
key, and valid strict Developer ID Application signatures from Carson Press LLC
(team `PV65ZWXCWX`) on both the outer Kumo bundle and updater companion. Apple
Development, ad-hoc, and unsigned builds remain disabled. Key provisioning alone
does not enable a development build. Production signing/notarization is handled
by the separate release workflow; the runtime does not read or export a private
signing key.

The outer Info.plist must require signed appcasts, verify archive signatures
before extraction, disable expiration of feed-signature failures, disable
profiling, and disallow automatic downloading/installing. Only native
application ZIPs at matching immutable release paths are accepted:

`https://github.com/morrigangirl/kumo/releases/download/v<VERSION>-<BUILD>/Kumo-<VERSION>-<BUILD>-macos-arm64.zip`

The build must also match the appcast's `sparkle:version`. Sparkle handles archive
signature verification, installed-code validation, downgrade protection,
Gatekeeper checks, authorization, and atomic app replacement. Release notes
linked to a separate network resource are not downloaded.

## Browser shutdown and installation

Sparkle normally waits for one browser process. Kumo requires the user to quit
all windows and profiles before consenting to download and install. The helper
never force-quits or sends signals to a browser.

Every normal launcher opens the sealed resource
`Contents/Resources/kumo-update-lock` read-only and holds a shared `flock` across
`execv`. The resource contains exactly `Kumo update coordination v1\n`. Before
forwarding any Install choice to Sparkle, the companion acquires a nonblocking
exclusive lock on that same inode and checks for remaining executable paths
under the same installed bundle. The lock works across user accounts using that
installation. Browser launches are blocked during staging and replacement.
A different installed Kumo copy does not share the lock.

The lock is held by the independently running companion until actual install
completion. A canceled/failed download releases it before extraction. After
extraction begins, errors, cancellations, and lost XPC connections retain the
lock because they do not prove the installer stopped. The exact Sparkle
authorization-canceled error is an exception only before a successful installer
handoff: it proves the installer was never submitted and safely releases the
lock. The normal progress UI disables Cancel during extraction, and the closed
browser target skips the ready-to-relaunch stage. Recovery otherwise only releases
it when the exact expected new build is present on disk and both its outer app
and companion pass strict Developer ID verification. Otherwise the native
recovery notice asks the user to keep the updater running and Kumo closed.
An ambiguous failed installer that never commits a replacement requires manual
repair; the helper cannot infer safe cancellation from an XPC disconnect. After successful replacement, the
companion releases the lock and starts the updated companion with a private
parent-process handoff. The child validates its exact live parent and production
signature, acknowledges readiness over its stdout pipe, and waits until the old
parent exits. It then starts the new update scheduler before opening the browser.
Both readiness and parent-exit waits are bounded at 30 seconds. This avoids
leaving the updated browser without an update monitor or using a stale framework.
The internal `--handoff <parent PID>` command accepts only the actual parent PID;
it cannot choose an arbitrary target app or bypass production validation. When the
browser was already closed, Sparkle may install immediately after extraction;
the initial Install consent authorizes this behavior. The ready-to-install UI's
Dismiss action is converted to cancellation so a staged installer cannot be
left pending without its lock.

Directly executing the internal Chromium binary bypasses launcher coordination
and is outside the supported browser launch path. The process inventory also
blocks existing internal helper processes it can identify. It does not inspect
profiles, credentials, page contents, or another installed browser's data.

## Focused verification

Run `xcrun swift test --package-path native/updater --scratch-path build/updater-policy-tests`.
The tests validate repository/feed/key/version policy, immutable release asset
paths, helper ancestry and bundle mismatch rejection, unsigned production-gate
rejection, resource symlink/hardlink/write-permission rejection, exact process
path boundaries, a real macOS process inventory, all 18 stage/choice/lease combinations, and
pre-download versus post-extraction cancellation/error state transitions. Compiled C and Swift
processes verify both directions of the installation lock, including a browser
shared descriptor surviving an actual `exec`.

A real Developer ID/notarized end-to-end replacement requires a production
release and is not simulated by loosening the release checks. No test publishes
a GitHub release or uses a personal browser profile.

References: [Sparkle setup](https://sparkle-project.org/documentation/),
[updating another bundle](https://sparkle-project.org/documentation/bundles/),
[security settings](https://sparkle-project.org/documentation/customization/),
[installer lifetime and process limitations](https://github.com/sparkle-project/Sparkle/blob/2.10.0/Documentation/Installation.md).
