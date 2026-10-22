# Download antivirus

Kumo's source-built Chromium engine holds ordinary downloads before completion, final rename or automatic opening, including CRX downloads handled by that download manager. A signed native helper scans a private snapshot with the separately installed official Cisco ClamAV engine. Only a successful verdict bound to the download's exact GUID, size and SHA-256 releases it. The bundled upstream-binary preview does not contain this native gate.

## Setup and status

Use **Kumo Setup.app** for a complete installation on an Apple Silicon Mac running macOS 13 or later. Extract the Setup ZIP, open **Kumo Setup**, click **Install**, and approve macOS's single administrator prompt. Setup closes Kumo normally, installs the browser and original Cisco antivirus package, prepares the current account's signed virus definitions, and enables automatic updates. It checks the installed scanner with a harmless file before offering **Open Kumo**. No Terminal command, Homebrew, or separate Apple Installer session is needed.

The installer includes the existing production browser with its PhishLang model and helper. Local phishing warnings remain optional and off by default; website access is requested when they are enabled. Installer construction and its trust checks are documented in [native/installer/README.md](../native/installer/README.md). The new setup flow does not by itself establish a completed administrator installation or hardware qualification on a MacBook Air.

To inspect scanner status, open the **gear on Kumo's new-tab page → Privacy & security → Download antivirus**. This card belongs to Kumo's start page; Chromium's regular Settings page does not contain it.

### Repair and advanced setup

The bundled command-line setup remains available for repairs and browser-only ZIP installations. This command locates the installed app through macOS:

```sh
open -n -b app.kumo.browser --args --kumo-scanner-setup
```

The repair tool downloads the exact pinned ClamAV 1.5.4 universal package, verifies its hash and Cisco Installer signature, and opens Apple's Installer when needed. Complete that installation, then run the repair command again to initialize definitions. Kumo uses untouched vendor tools at `/usr/local/clamav/`. The complete Kumo Setup app carries the original vendor package; the browser app uses the separately installed runtime. Neither flow modifies Cisco's binaries or signatures. Users need no Python, Homebrew or Xcode.

Definitions are private to the current user in `~/Library/Application Support/KumoSecurity/ClamAV/`. Successful initialization configures the user LaunchAgent `app.kumo.clamav-definitions` to run verified FreshClam at login and every eight hours. It runs independently of Kumo without a resident scanning daemon. Status reports whether that exact schedule is configured and whether current definitions are usable; configuration does not guarantee the last scheduled update succeeded.

Update definitions explicitly with:

```sh
open -n -b app.kumo.browser --args --kumo-scanner-update
```

The status card distinguishes ready, setup required and unavailable definitions. Missing helpers, invalid vendor files, definitions older than 72 hours, scanner errors, malware, encrypted archives, exceeded limits and timeouts block completion. They never become a successful scan. A download interrupted by this gate requires a fresh download and scan.

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
