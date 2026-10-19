# GitHub Releases updater validation

This report records the development integration snapshot. The later
[release preparation follow-up](release-preparation.md) covers model-scope
publication guards and the additional release preflight tests.

Kumo's app update channel is `morrigangirl/kumo` GitHub Releases. The stable feed is the latest release's `appcast.xml` asset; each archive uses its immutable version/build tag. The rebuilt development app is **0.1.0, build 202610190001**, with Chromium **155.0.8059.84** and pinned **Sparkle 2.10.0**. See [release preparation and publishing](../../github-releases.md).

The independent native companion survives the browser launcher's `execv` handoff. It requires signed feeds and archives, verifies before extraction, disallows feed-signature expiration and silent installation, and does not submit browser URLs or provider credentials. The release key was created in the login Keychain; only its public verification key is recorded in the project. No production private key was exported.

Installation requires explicit consent and closed browser profiles. A read-only sealed resource provides a shared browser lock across `execv` and an exclusive updater lock through replacement. Review corrected resumed-install dismissal, early release after installer errors, authorization cancellation before installer submission, ambiguity across retries, and restarting the checker after successful replacement. Exact prelaunch cancellation releases the lock; an ambiguous post-extraction failure retains it until completion or a verified expected replacement. If neither can be confirmed, manual repair may be needed. The helper does not force-quit browsers.

## Checks

| Check | Result |
| --- | --- |
| JavaScript regressions | 147 passed |
| Packaging, update policy and release activation | 62 passed |
| Compiled Swift launcher tests | 20 passed |
| Native updater tests | 19 methods passed, including 18 stage/choice/lease combinations |
| Compiled helper with OS network denied | Eight cases passed |
| Actual Objective-C callback registration | All 13 expected selectors present; driver overrides verified |
| Release policy and pinned vendor preparation | 27 passed, including real official-tool archive/feed signatures and tamper rejection |
| Final browser rerun | Agent control, Store isolation, update-status UI, startup privacy and TCP TLS passed |
| Actual Chromium lease | Held after startup and three more seconds; concurrent shared lock allowed; exclusive lock denied until graceful browser shutdown |
| Packaged signatures | Deep strict verification passed; app seal unchanged after browser QA |

The actual lease smoke used the exact compiled launcher prefix, the real packaged engine, a disposable profile and loopback-only QA debugging. It made no feed request, opened no personal profile and required no process signals for cleanup. About and Security checks exercised the real portable command-copy buttons and Kumo release link, with no automatic external request in this development build.

The original source receipt remains unchanged: input fingerprint `92acde368a82bc38610f1e310f97a769658d901aa53f0988db3a0b38b568814c`, receipt SHA-256 `614a7344c6f87f7ae037e04b85e7b040ab916f1fe87d87017ea3c37b30482f81`. Packaged engine/framework code and data still match the completed source output. The final outer CodeDirectory hash is `20d78e4a96abeec08c82e18c493b36dfaea31196`, signed by team `PV65ZWXCWX`.

## Production status

This remains an Apple Development app. Its updater reports `release-signing-not-configured` and keeps network checks disabled. The metadata-only doctor confirms the selected team's Developer ID Application identity is absent. Production preparation also requires notarization and a clean reviewed source commit. The release tool prepares a separate signed/stapled archive, checks its extracted app, uploads a draft and verifies downloaded assets before an explicit publish operation. The manual workflow has not been dispatched.

No GitHub release was uploaded or published, and no notarized archive replacement was performed. Those paths require the production prerequisites and end-to-end release QA. Sparkle's Ed25519 key authorizes future code and supports signing-identity rotation; the publishing pipeline separately enforces Carson Press Developer ID signing and notarization on every produced release. A development test does not prove those production paths.

The [machine-readable record](github-release-updates.json) contains exact package identities, checks and hashes of raw evidence. Raw build/test files remain outside Git, and published evidence paths are repository-relative. Earlier [malware](malware-protection.md) and [Desktop connectivity](desktop-connectivity.md) reports retain their original package identities and test scope.
