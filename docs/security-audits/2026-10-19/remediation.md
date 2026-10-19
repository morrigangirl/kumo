# Agent-control fixes and security rerun — October 19, 2026

Both Medium findings from the [original security sweep](report.md) are fixed in the rebuilt, signed [Kumo.app](../../../dist/Kumo.app). The bounded regression and security checks passed. Existing production release gaps remain open.

The original report and CVE matrix are preserved as the pre-fix snapshot. Its report SHA-256 remains `80321eca4ea69b65a4da7063593401230469928179e12c512318cb7dccc044fd`. Current machine-readable results are in [remediation.json](remediation.json).

## Changes

- **KUMO-AUDIT-EXT-001 — fixed and verified:** the UI captures each displayed origin before requesting website permission. The worker requires explicit canonical tab/origin pairs, rejects stale or pending navigation, and rechecks tabs and website permissions inside the serialized grant commit. It publishes only the captured origins. A failing selection leaves access disabled, refreshes the choices and requires another confirmation. Revocation invalidates asynchronous commits before publication.
- **KUMO-AUDIT-EXT-002 — fixed and verified:** a shared sensitive-field predicate matches `one-time-code` as a case-insensitive autocomplete token, including section prefixes and ASCII whitespace. Payment/password autocomplete exclusions also ignore case. Snapshot control metadata, clicks and typing use the same exclusion. Recognition still depends on page markup; this does not identify every possible sensitive field.

Production changes are limited to [background.js](../../../extension/background.js) and [newtab.js](../../../extension/newtab.js). Regression coverage is in [extension-agent.test.mjs](../../../tests/extension-agent.test.mjs) and the actual-browser [smoke-agents.mjs](../../../scripts/smoke-agents.mjs). Production extension permissions are unchanged.

## Regression and packaged-browser results

| Check | Result |
| --- | --- |
| Full JavaScript suite | **66 passed**, zero failures; 15 added regression tests |
| Agent/Store targeted suite | **43 passed**: 35 extension-agent tests and eight Store-helper tests |
| Isolated old/new modules | Old ordinary-control test passed while three security invariants failed; fixed modules passed all four checks |
| Actual UI and Native Messaging | Stale displayed origin A could not grant already-permitted destination B; access stayed disabled with no grants; refreshed explicit B grant and snapshot succeeded |
| Actual sensitive fields | Nine real DOM fixtures; **18 click/type actions rejected**, synthetic values unchanged, zero click events and no sensitive control metadata/form values in snapshots |
| Normal control and revocation | Normal click/text entry, explicit revoke and cross-origin redirect revocation passed |
| Native/overlay/receipt/package checks | **57 passed**, zero failures, one expected pristine-overlay skip because source was already patched |
| Store scripting restrictions | Eight origin/control cases passed, no skips; ordinary-extension positive control and helper SPA/document confirmation passed |
| Security cards | Correct packaged/source versions; no automatic release request |
| Startup privacy | Headed 15-second observation with normal launcher flags, no network suppression; Default NetLog positive control passed; only loopback HTTP(S) host observed |
| Live TLS | TCP TLS 1.3 and default QUIC used `AES_128_GCM` and `X25519MLKEM768`; invalid-certificate fixture rejected in both runs |
| Signing and cleanup | Deep/strict Apple-team verification passed before and after runtime tests; disposable profiles, extension copies, sockets, tokens and owned processes removed |

The agent test loaded a copy of the packaged extension with loopback-only fixture permissions, normal Chromium sandbox, mock Keychain and basic synthetic password storage. No personal profiles, saved credentials, provider accounts or provider tasks were used. The Store test locally fulfilled inert page fixtures and stopped CRX navigation before dispatch; it did not repeat native Store installation or upgrade testing.

## Rebuilt artifact

The explicit package command reused the verified existing locally compiled engine; no Chromium C++ rebuild was needed for these JavaScript changes:

```sh
python3 scripts/package.py \
  --engine-app build/source-155.0.8059.84/recipe/build/src/out/Default/Chromium.app \
  --output dist/Kumo.app
```

- Chromium **155.0.8059.84**, commit `5869fe313571d75152b77813cf0a4ee26a4e6df0`.
- Unchanged native input fingerprint `6a5dd6ca1a044b5de1d52b033188548c9a477bca196f25dca53642ce2ef875cc` and embedded source receipt `1f2af548aa9a52f3325471b2627ab950784874ba0815db06884b08980d22afb3`.
- Apple Development team **PV65ZWXCWX**; app CodeDirectory hash `0aab5e233283af5f9a69f4e3dd99faf866b0c959`.
- Hardened runtime and library validation retained (`0x12a00`). Packaged modified JavaScript matches the reviewed source byte for byte.

## Advisory and source recheck

The original exact 30-day window remains **September 19, 2026 at 10:07:52 AM through October 19 at 10:07:52 AM, America/New_York**. All **449** retained Google CNA records were independently reparsed and hash checked: **340** potentially Mac/shared and **109** explicitly other platforms. Every Google English prior-to statement agreed with its exclusive fixed-version bound, and all bounds remain at or below `.84`. This is vendor advisory coverage; most older fixes were not individually traced across major versions or tested with exploits.

A fresh [official Chrome release feed](https://chromereleases.googleblog.com/feeds/posts/default?alt=json&max-results=150&published-min=2026-09-19T00%3A00%3A00-04%3A00&published-max=2026-10-20T00%3A00%3A00-04%3A00) retrieved at **15:07:47 UTC** returned the same bytes and 24 desktop announcements, with no additional desktop CVEs. The latest stable announcement remained [October 15's `.84` release](https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_01886704284.html). The 449 authority records were rechecked from preserved responses rather than all fetched again.

Source comparison reconfirmed 73 exact latest Chromium files, seven retained new patch hunks in modified production files, and ten exact V8 production/version files. Native input hashes, actual source-engine artifacts, receipts, compiled mitigations and the reviewed CT call chain remain unchanged. No full Chromium/V8 regression run, fuzz campaign or sandbox-escape experiment was performed.

## Remaining release work

Automatic browser updates, authenticated security-data delivery and URL/download reputation protection remain absent. Without refreshed data, the bundled CT list becomes untimely **November 29, 2026 at 8:35:40 AM New York time**; the pinned source then treats that CT result as requirements met and skips relevant SCT-based constraints. The list is currently timely and ordinary certificate validation remains enabled. This future behavior was rechecked in source, without changing the runtime clock.

Developer ID signing/notarization, real Apple credential selection/passkey validation and production distribution checks also remain outside this repair. Passing this bounded sweep does not establish full Chrome security parity or a production-ready browser.

Raw logs, independent reviews, hashes and cleanup records are retained in [the remediation evidence directory](../../../.cache/qa/agent-security-fixes-2026-10-19/). Key records are `rebuilt-artifact-verification.json`, `post-runtime-verification.json`, `tests/before-after-evidence.json`, `runtime/agents-browser-001.json`, `runtime/security-runtime-checks.json` and `source-rerun/summary.json`.
