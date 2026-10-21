# Kumo for macOS

Kumo is a native Apple Silicon browser project based on Chromium, with Google browser identity, sync, telemetry integrations, and promotional services removed through ungoogled-chromium. It retains the native Chromium tab strip, omnibox, bookmarks, downloads, DevTools, extension APIs, site permissions, and web platform. Its Swift launcher starts Chromium directly; there is no Electron or webview browser shell.

The latest notarized production release is available for [Apple Silicon Macs](https://github.com/morrigangirl/kumo/releases/latest). Extract `Kumo.app` from the ZIP and move it to your Applications folder.

This repository contains Kumo's source, Chromium overlays, build recipes, tests and validation summaries. Upstream checkouts, downloaded model weights, threat-list snapshots and compiled applications are generated locally and excluded from Git. Evidence links under `build/`, `dist/` and `.cache/` refer to local development artifacts. Follow the [source-build instructions](docs/source-build.md), [malware-feed preparation](docs/malware-protection.md#reproduce-the-snapshot) and [GitHub release packaging](docs/github-releases.md) to reproduce the browser. Source version 0.1.1 includes the optional local PhishLang scanner; see [model preparation](docs/phishing-protection.md#build-and-checks).

The pending **0.1.2, build 202610210003** removes Kumo's built-in Apple Passwords integration: its settings, native fill sheet, pairing components and SDK probes. Password extensions continue through Chromium's usual extension support; compatibility with a particular Apple helper is not established. Chromium WebAuthn remains available. This replacement needs a fresh completed source build, validation and notarization before release; the unpublished build 202610210002 is superseded. Widevine DRM is not included, and the reported Crunchyroll playback issue remains unresolved.

The first published release, 0.1.0, used **Chromium 155.0.8059.84**. Source version 0.1.1 uses **156.0.8078.47**, following Chrome's October 20 security release. Its full source build and 19 candidate runtime checks passed. This engine upgrade is a local compatibility port using an immutable, unmerged ungoogled-chromium update. Completed-build receipts distinguish built applications from source targets; production distribution additionally requires Developer ID signing and Apple notarization. See [source build details](docs/source-build.md) and [0.1.1 candidate validation](docs/security-audits/2026-10-21/0.1.1-candidate.md).

The earlier upstream-binary preview used 155.0.8059.39, behind [Chrome's October 15 security release](https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_01886704284.html). The current local source build replaces those older engines. App updates use signed [Kumo GitHub Releases](docs/github-releases.md), with a separate native Sparkle companion. The signed update channel is live for Developer ID-signed, notarized production releases. Apple Development builds keep update checks disabled. The first public binary omitted the experimental PhishLang model and its native helper; domain blocking and ClamAV scanning were included. Version 0.1.1 integrates the model and sandboxed helper with warnings off by default; see [setup, model provenance and limitations](docs/phishing-protection.md).

## Run

```sh
open dist/Kumo.app
```

The public release has a Carson Press LLC Developer ID signature and a stapled Apple notarization ticket. Local development packaging verifies the completed source receipt, compiles the Swift launcher, adds local customization, and signs all native code with the selected team's development identity. It preserves the engine's hardened runtime, library validation and each helper's signing policy, then checks isolated sandboxed startup before replacing the existing app. Rebuilding requires Xcode with its license accepted, Python 3.12+, Node 22+, and a valid Apple Development identity for the configured team.

The default `npm run build` always builds that pinned upstream preview. It
refuses to replace an existing app containing a newer Chromium engine; use
`npm run source:package -- --jobs 4` to build the current source target. Missing
or invalid signed version metadata in an existing output also stops replacement.
For a separate preview QA copy, use
`npm run build -- --output dist/preview/Kumo.app`. Different output paths still
use the same normal Kumo profile when launched normally. Use a disposable
profile when testing an older engine.

The selected Apple team is **Carson Press LLC (`PV65ZWXCWX`)**, recorded in `config/apple-signing.json`. `npm run check:signing` inspects public certificate and provisioning metadata for that team without exporting keys. Its development certificate signs the local app. A valid Developer ID Application identity is now installed for production signing; an approved macOS browser-passkey profile for Kumo is still absent. Neither certificate alone grants that managed capability. See [production signing and notarization](docs/signing.md) for the separate release workflow.

The executable app is `dist/Kumo.app`. Kumo creates its own persistent profile at `~/Library/Application Support/Kumo`; it never imports Chrome's profile or credentials. Website cookies and storage can persist across restarts, including Google website sessions, subject to each website's expiry, MFA, and account policies. Browser Google account sign-in and Chrome Sync are disabled.

On the first launch, open a new tab if the initial tab still shows Chromium's placeholder. Choose **Keep it** when Chromium asks to confirm Kumo's start page.

Start-page search defaults to DuckDuckGo. Address-bar search initially uses the upstream **No Search** setting; choose your engine at **Settings → Search engine**, or use Kumo's **Settings → Search → Address-bar search settings** button. This preserves Chromium's protection against silent search-engine changes.

To package an engine you compiled from the pinned Chromium source recipe:

```sh
npm run source:package -- --jobs 4
```

That command prepares and compiles the actual Chromium source, then packages it. Each locked engine version uses its own `build/source-<version>` workspace; `--work-dir` can override it. Allow several hours and substantial disk space. See [prerequisites, locked inputs, and build commands](docs/source-build.md). Source compilation is distinct from the fast upstream-binary preview build.

The first published malware-enabled engine was built in `build/source-155.0.8059.84-malware-001`. Its normal Chromium target compiled the native download guard and delegate, linked the framework, verified libraries and signed the engine. That build also closes a DevTools completion bypass. Its evidence remains in `audit/devtools-completion-forwarding-002/`. The 156 engine was built separately in `build/source-156.0.8078.47-final002`; its completed receipt and candidate tests verify the retained native guard and both download-manager paths. Earlier trees and artifacts remain preserved. See [0.1.1 validation](docs/security-audits/2026-10-21/0.1.1-candidate.md) and the earlier [malware protection validation](docs/security-audits/2026-10-19/malware-protection.md).

## Features and current boundaries

| Requirement | Implementation and status |
| --- | --- |
| Native Mac browser | Chromium's real native browser UI, Swift bootstrap, isolated persistent profile, custom application icon. |
| Chrome extensions and themes | Chromium extension APIs retained. The “Install in Kumo” Store helper requests the signed CRX and leaves confirmation to Chromium. Native installation and a real uBlock Origin Lite upgrade from 2026.1012.1545 to 2026.1018.2229 passed, including packed installation, its module worker, APIs and six enabled rulesets. Native Update preserved Kumo's helper with it both enabled and disabled; manifest/package requests omitted cookies and authentication. Google's Just Black theme also passed source-browser installation, native Appearance and its Store-detail link. Automatic extension-update scheduling remains unverified. Legacy NPAPI/Flash/Java plugins are unsupported. |
| Custom themes | Six start-page palettes, accent color, local wallpaper, custom greeting, preferences import/export, and export of a Chromium toolbar/tab theme manifest. Native Chromium appearance settings and installed Chrome themes remain available. |
| Any search engine | Five presets and custom HTTP/HTTPS search templates with `{searchTerms}` on the start page, including local search servers. Chromium's native settings independently control address-bar search engines. |
| Password extensions | Chromium's ordinary extension and Native Messaging support remains. Kumo's built-in Apple Passwords menu, sheet, settings and pairing work are removed from the pending source version. Each password extension retains its own authentication and browser-support requirements; Apple-helper compatibility is unverified. See [password-extension boundaries](docs/apple-passwords.md). |
| Passkeys and security keys | Chromium WebAuthn remains. Kumo's separate Apple capability probe is removed. Optional managed browser-passkey entitlement/provisioning support remains in release-signing tools; no approved Kumo profile or successful Apple passkey request is claimed. |
| Codex / Claude Desktop control | Portable Desktop setup, local stdio MCP tools and Native Messaging bridge, opt-in origin-bound tab grants, session revocation, password-field exclusion. Official clients keep their own personal/work account sign-in. No provider token extraction or separate provider API billing is used. |
| Local phishing warnings | Kumo 0.1.1 integrates the optional PhishLang MobileBERT model with native Swift/Core ML CPU inference, bounded privacy-filtered page inputs and a browser-owned warning page. Warnings start off; enable them in Privacy & security. The first public release, 0.1.0, omitted the model. Synthetic integration does not establish production accuracy or an 8 GB hardware qualification. |
| Known-malware domains | Local HaGeZi TIF Mini rules block listed domains and subdomains for matching page/resource requests. Enabled by default, with list age, controls and periodic HTTPS feed refresh. No browsing URL lookup or file upload. This layer does not scan downloaded files; see [scope and updates](docs/malware-protection.md). |
| Download antivirus | The source engine holds ordinary downloads for a sandboxed native ClamAV scan before completion or automatic opening. Setup uses the official Cisco installation and verified local definitions, with scheduled updates. Missing, stale, infected, encrypted, limited or failed scans block completion. Saved pages/MHTML use a separate path; see [setup and limits](docs/download-antivirus.md). |
| App updates | Signed appcasts and archives on `morrigangirl/kumo` GitHub Releases, checked by a separate native Sparkle companion. Installation requires user approval and closed browser profiles. A separate increasing Kumo build counter prevents version rollback. The notarized production release has updates enabled; development builds keep network checks disabled. |
| Chrome security controls | Native certificate/settings UI, sandbox, site isolation and permission model are retained. **Full Chrome security parity is not delivered**: this ungoogled base lacks Google Safe Browsing and Google component updates. Kumo's signed GitHub release update channel is active. The source recipe preserves OS download quarantine and Store-origin isolation; the upstream preview has upstream's different defaults. |
| Web 1/2/3 | Chromium's ordinary web platform, including modern web apps, WebAssembly, WebGL/WebGPU and WebAuthn. Compatible wallet extensions may serve Web3 sites. No wallet, blockchain protocol handler, or IPFS gateway is bundled. |
| TLS / post-quantum | Chromium/BoringSSL's supported modern TLS and hybrid post-quantum key agreement are inherited. No legacy insecure TLS is enabled. Server support and the actual handshake determine negotiated protection; PQ key agreement does not make the entire certificate ecosystem quantum-safe. |

## Password extensions

Use Chromium's normal extension installation and management for password tools. The pending source version removes Kumo's Apple Passwords fill command, native sheet, settings page, helper session and pairing UI. This change does not include a profile migration or cookie deletion; Google website sessions remain subject to the existing profile and each website's policies.

Extension support does not establish that Apple's browser helper accepts Kumo. The owner's custom extension has not been qualified against the replacement build. See [current boundaries and historical SDK findings](docs/apple-passwords.md).

## Agent setup

Open **Agents** from Kumo's new tab. Copy the Codex or Claude setup command and run it to register Kumo with your chosen official client. Existing account authentication stays in that client. Workspaces may restrict MCP or browser access. Setup configures Codex Desktop or Claude Desktop directly and installs a private bridge independent of the checkout or app folder. Moving Kumo.app does not change the clients' MCP command; the launcher resolves Node when it starts. See the [Desktop setup instructions](docs/agents.md#desktop-setup).

Choose the tabs to grant, accept website access, and enable control. The browser starts with control off; changing a tab's origin removes its grant. Revocation invalidates pending results. New tabs require a separate opt-in. Both connected clients share the granted tab set; vendor identity is not authenticated by the local bridge.

See [agent protocol, account setup and access boundaries](docs/agents.md).

## Verification

The [0.1.1 candidate validation](docs/security-audits/2026-10-21/0.1.1-candidate.md) records the actual Chromium 156 build, embedded receipt, model attribution, isolated migration and 19 browser/security runtime checks. Candidate validation is separate from final production signing and notarization, which are recorded in each release's assets.

The earlier [0.1.0 production validation](docs/security-audits/2026-10-20/production-release.md) records Apple acceptance, stapling, Gatekeeper, exact artifact/runtime identity, public download/feed verification and the local production installation.

The latest [GitHub Releases updater validation](docs/security-audits/2026-10-19/github-release-updates.md) records the earlier model-inclusive development package, signed-feed tests, real Chromium installation-lock checks and production prerequisites at that validation snapshot.

```sh
npm test
python3 scripts/source.py self-test
```

The following commands retain their historical default `dist/Kumo.app` selectors; some require older seed fixtures. They do not all honor an app-path environment override. Use the exact versioned candidate and separately reviewed selectors described in the [0.1.1 validation](docs/security-audits/2026-10-21/0.1.1-candidate.md) when qualifying that release. Examples for the historical default package:

```sh
npm install --prefix .cache/qa --no-save --package-lock=false --ignore-scripts playwright-core@1.64.1
# For this build's retained .39 fixture: run first, alone, after packaging .84.
node scripts/smoke-profile-upgrade.mjs verify
node scripts/smoke-browser.mjs
node scripts/smoke-agents.mjs
# Optional model-inclusive development builds only: synthetic PhishLang warnings.
node scripts/smoke-phishing.mjs
# Local domain blocking and actual native antivirus completion/cancellation.
node scripts/smoke-malware.mjs
node scripts/smoke-download-malware.mjs
node scripts/smoke-search.mjs
# Live public Quad9 probe in an isolated profile; native setting and restart check.
node scripts/smoke-dns.mjs
# Confirm security cards report the actual packaged engine and source target.
node scripts/smoke-security.mjs
# Ordinary headed startup/new tab, with Default NetLog and a local positive control.
node scripts/smoke-privacy.mjs
# Source build only: native download quarantine and the Extensions sidebar link.
node scripts/smoke-download.mjs
node scripts/smoke-native-store-link.mjs
# Source build only: ordinary Store scripting blocked, trusted helper SPA flow.
node scripts/smoke-store-script-guard.mjs
# Interactive source-only Store checks: target each printed disposable QA app.
node scripts/smoke-extension.mjs --update-check
node scripts/smoke-extension.mjs --fixture theme
# Optional live TLS/PQ and certificate-error checks:
node scripts/check-network.mjs --tcp
```

Tests use disposable profiles, fake local pages, and official Store extension/theme fixtures. Interactive source-only checks generate separately signed QA apps whose launchers force those disposable profiles; target the printed QA app when using GUI/CUA. They do not sign into Google, Codex, Claude, or Apple Passwords, select personal credentials, modify a real Chrome profile, or send provider inference requests. The Store harness requires GUI/CUA clicks for the native confirmation; it is not fully automated. Provider login, real password selection, protected media, automatic extension-update scheduling, and release security remain unverified.

The source .84 browser passed start-page/theme/search persistence, native settings, original-download quarantine, security-version cards, and real Native Messaging agent-control checks. Its .39→.84 profile upgrade preserved synthetic HTTPOnly cookies and local storage. Live TCP and QUIC checks negotiated TLS 1.3, AES_128_GCM, and X25519MLKEM768; the invalid-certificate fixture was rejected. A bounded 15-second ordinary startup trace observed only the loopback positive control. These describe the tested fixtures and connections, rather than every server or an exhaustive privacy/security audit. Evidence and exact package identities are recorded in [source-build details](docs/source-build.md).

An earlier JavaScript suite passed all 147 tests, including 36 phishing regressions and 23 bridge tests. The [Desktop connectivity validation](docs/security-audits/2026-10-19/desktop-connectivity.md) records portable installation and real client configuration checks. The [malware protection validation](docs/security-audits/2026-10-19/malware-protection.md) records domain blocking, twelve actual antivirus download cases and the final source receipt. The earlier [PhishLang port validation](docs/security-audits/2026-10-19/phishlang-port.md) records its signed app, native tests, real warnings and repeated security checks. The source app also passed the eight-case native Store scripting guard and a complete agent grant/revoke/control check. The Store harness verifies exact SPA document acknowledgement and CRX URL construction behind a rejecting dispatch barrier; actual installation is checked separately through native GUI consent. An earlier signed .84 package passed a real native uBlock Origin Lite upgrade to 2026.1018.2229, with 18,829 packaged rules across six enabled rulesets. Its finalized trace records the approved 9,145,194-byte package download during the first native Update; the installed version, packed location and public-key-derived ID matched. This establishes the observed manual upgrade, while automatic scheduling and hostile-update rejection remain unverified. See [extension update evidence](docs/extension-update-qa.md).

Native search QA added a custom HTTP engine through Settings and made it the default. The choice survived a browser restart, and the native omnibox controller generated correct query URLs that reached a local fixture. Native custom-engine templates use `%s`; Kumo's start-page templates use `{searchTerms}`.

Native Secure DNS QA selected Quad9's custom HTTPS resolver through Settings. Chromium's real DNS probe succeeded, and strict secure mode and the resolver template persisted across a restart. This checks DNS configuration and resolution; it does not establish URL or download reputation protection. See [security controls and optional protection](docs/security.md).

## Attribution

Kumo's code is licensed under [MIT](LICENSE). Chromium and third-party components retain their own licenses; view `chrome://credits` in the browser and the upstream source notices. The ungoogled patch set and macOS recipe retain their upstream licensing. See [third-party notices](THIRD_PARTY_NOTICES.md).
