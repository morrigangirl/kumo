# Download antivirus

Kumo's source-built Chromium engine holds ordinary downloads before completion, final rename or automatic opening, including CRX downloads handled by that download manager. A signed native helper scans a private snapshot with the separately installed official Cisco ClamAV engine. Only a successful verdict bound to the download's exact GUID, size and SHA-256 releases it. The bundled upstream-binary preview does not contain this native gate.

## Setup and status

[Kumo 0.2.0, build 202610210004](https://github.com/morrigangirl/kumo/releases/tag/v0.2.0-202610210004) includes the complete notarized Apple installer. Its signing, Apple and independent payload/publication checks are recorded in the [production audit](security-audits/2026-10-22/0.2.0-production-release.md). Actual administrator installation, upgrade/recovery on another Mac and 8 GB hardware remain unqualified. The previous 0.1.2 browser ZIP required separate antivirus setup; its [production record](security-audits/2026-10-21/0.1.2-production-release.md) remains historical evidence.

Use the [**standard Kumo `.pkg` installer**](https://github.com/morrigangirl/kumo/releases/download/v0.2.0-202610210004/Kumo-0.2.0-202610210004-macos-arm64.pkg) for first installation or missing-dependency repair on an Apple Silicon Mac running macOS 13 or later. Open the package in Apple's Installer and approve its administrator prompt. The package includes Kumo with PhishLang and its bundled agent runtime, the original Cisco antivirus components, signed definitions and the current user's scheduled definition updates. Its installer checks a harmless scan before reporting setup ready. The internal `Kumo Setup.app` is not a standalone installer; opening it directly or using its retired administrator route does not install Kumo. No Terminal, Homebrew or separately installed Node is required for the standard package.

The **browser ZIP and signed Sparkle app updates contain only the app and its bundled resources**, including PhishLang and Node. They do not install or repair `/usr/local/clamav/`, the user's virus definitions or their update schedule. A browser-only update preserves those existing dependencies. If they are missing, ordinary downloads remain blocked until protection is ready; use the complete `.pkg` for the full installation/repair path.

In the native 0.2 browser, open **Settings → Kumo → Download protection** (`chrome://settings/kumo`) to inspect the scanner status. **Refresh status** rereads the helper status. **Install or repair protection** starts the verified antivirus setup flow; **Update definitions** refreshes the current user's databases. If the repair action opens Apple's Installer for the verified Cisco component, complete that installation, then return to Kumo and choose **Update definitions**. These controls do not require copied commands.

Messages such as `engine-not-installed`, `engine-verification-failed`, `definitions-missing`, `definitions-stale` or `definitions-verification-failed` mean that scanning is unavailable; they are not successful protection results. The page also reports website-domain protection and PhishLang separately. For new/unset 0.2 preferences, PhishLang starts enabled; an existing explicit off choice is preserved. Model warnings and antivirus scanning are different layers.

For browser updates, use **Settings → Kumo → Updates → Check for updates**. Its **Release history** link opens [Kumo GitHub Releases](https://github.com/morrigangirl/kumo/releases), which includes the separate complete installer. Checking for an app update does not install antivirus dependencies. Installer construction, payload verification and remaining acceptance limits are documented in [native/installer/README.md](../native/installer/README.md).

### Definition updates and readiness

Kumo uses the pinned, authenticated ClamAV 1.5.4 tools at `/usr/local/clamav/`, preserving Cisco's binaries and signatures. Definitions are private to the current user in `~/Library/Application Support/KumoSecurity/ClamAV/`. Successful initialization configures the user LaunchAgent `app.kumo.clamav-definitions` to run verified FreshClam at login and every eight hours. It runs independently of Kumo without a resident scanning daemon. Status reports whether that exact schedule is configured and whether current definitions are usable; configuration does not guarantee the last scheduled update succeeded.

Missing helpers, invalid vendor files, definitions older than 72 hours, scanner errors, malware, encrypted archives, exceeded limits and timeouts block completion. They never become a successful scan. A download interrupted by this gate requires a fresh download and scan. Actual administrator installation, upgrade/rollback and whole-browser performance on an 8 GB Mac remain separate target-Mac acceptance work; this setup documentation does not claim those checks passed.

## Local processing and limits

The sandboxed scanner has no network entitlement. The separate updater fetches official definition databases over HTTPS and verifies their CVD signatures. Files and browsing addresses are not uploaded. The scanner validates Cisco's signing identity and hashes of its fixed runtime files before execution.

There is one active scan and space for eight queued downloads. Downloads over 1 GiB are blocked by the gate. ClamAV limits expanded archive work to 1 GiB, 10,000 entries, recursion depth 20 and 120 seconds. The browser imposes a total 180-second deadline, including queue time. Cancellation and timeout terminate the owned helper process group, including ClamAV. Snapshot copies and repeat hashing add disk I/O and latency.

DevTools download behavior overrides forward completion to the original Chrome delegate, so choosing an automated download directory does not skip the native gate. The packaged browser uses Chrome profiles in both headed and unified headless mode. The separate upstream `headless_shell` target is not shipped.

The native gate and helper each bind a private, unlinked read-only snapshot to the original file, and recheck original identity, size and bytes before completion. Temporary browser download data is still accessible to other processes running as the same macOS user. This feature governs Kumo's completion and opening decisions; it cannot isolate all activity by that user.

Background extension/component update fetches use separate machinery; signed CRX verification remains Chromium's responsibility. Saved pages/MHTML use Chromium's separate SavePackage path and are outside this ordinary-download gate. Browser caches, service-worker storage, arbitrary writes by other applications and files already on disk are also outside it. `no-known-malware` means no malware was found under these limits; it is not a guarantee of safety.

Production helper checks on this development Mac found approximately 1.23 GiB peak ClamAV RSS and about 5–6 seconds for small fixtures, including process start and database load. Those observations came from a 24 GB M4 Pro. Total browser/scanner performance on an actual 8 GB Mac remains unqualified.

## Build and verification

Prepare the domain feed separately, build the native helper with `scripts/build-malware.sh`, then use the pinned Chromium source recipe. The source orchestrator applies `scripts/malware_overlay.py` and requires the exact guard in `native/chromium/kumo_download_guard.mm` before compiling and issuing a new completed-build receipt. Packaging checks that receipt and signs the scanner separately with App Sandbox, hardened runtime and library validation.

The scanner protocol, official package pins and native tests are documented in [native/malware/README.md](../native/malware/README.md). Browser integration checks use only disposable profiles, local benign fixtures and the standard inert EICAR antivirus test string. No live malicious site or executable malware is required.
