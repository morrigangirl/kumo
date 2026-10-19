# PhishLang native port validation — October 19, 2026

The rebuilt [Kumo.app](../../../dist/Kumo.app) includes experimental local phishing
warnings. Enable **Settings → Privacy & security → Enable local warnings**, then
allow website access. It starts off. The [feature guide](../../phishing-protection.md)
explains data exclusions, limits, build instructions and model provenance.

The pinned PhishLang MobileBERT weights run through CPU-only Core ML in a dedicated
signed Swift helper, `Contents/Helpers/KumoPhishing.app`. The helper has App Sandbox
enabled and no network entitlement; inference needs no provider account or server.
Build-time Python/PyTorch/Transformers are excluded from the application.

## Verification

| Check | Result |
| --- | --- |
| JavaScript | **102 passed**, zero failures/skips; 21 worker and 15 extractor tests added |
| Native Swift | **13 methods passed**, including 16 upstream tokenizer fixtures, bounded framing, schema, missing resources and inference math |
| Package validation | **28 passed**; pinned assets, model interface, digest, tampering, size/symlink guards and dedicated helper layout |
| Conversion | **10 synthetic FP32 Core ML/PyTorch comparisons passed**; maximum class-score difference 0.00000234 |
| Final signed helper | **18 checks passed**; sequential framed inference/status, caller authorization, frame/input limits, malformed input, metadata, signatures and exact sandbox entitlement |
| Actual browser | **Six scenario groups passed**, with six real Core ML classifications and two status requests |
| Existing agent controls | UI grant/revoke, ordinary actions, stale-origin rejection, cross-origin revocation and all 18 sensitive actions across nine fixtures passed |
| Store restrictions | All eight origin/control cases and SPA/document confirmation passed; no real CRX download/install repeated |
| Security cards | Engine/source comparison correct; no automatic release request |
| Startup privacy | Normal headed startup and 15 quiet seconds, no added network suppression; only loopback HTTP(S) host observed |
| Live TCP TLS | TLS 1.3, `AES_128_GCM`, `X25519MLKEM768`; invalid-certificate fixture rejected |

Actual browser checks used disposable profiles, mock Keychain, synthetic loopback
pages and normal Chromium sandboxing. The copied QA extension pregranted website
access to exercise settings and real Native Messaging; the production extension
still requests optional website permission from the person's click. No personal
profile, credential vault or provider account was accessed.

The browser checks exercised default-off state, real settings, high-score warnings,
Return to a new tab, Continue for the returned document, renewed warning after
reload, disabling scanners/helper and clean re-enabling. A benign article returned
no signal. Synthetic private field sentinels were absent from every native payload;
warning UI displayed only the origin. Agent control remained disabled with no tab
grants. Visual review confirmed readable warning text and both navigation controls.
The helper had no Internet sockets at the observation point. Browser NetLog held
only fixture loopback HTTP URLs. These bounded observations do not constitute a
complete network-syscall audit. Owned browser/helper processes exited and the
temporary profile was removed.

Independent review found warning-ticket and disabling races during implementation;
serialized storage mutation and epoch/document/revision revalidation fixed them,
with regression tests. A pathological tokenizer input was reduced from about
14 seconds to about 63 ms through a bounded linear special-token pass.

The first package attempt correctly failed its signed inference probe before
replacing the previous app: macOS required the sandboxed secondary executable to
have its own signed bundle identity. The dedicated nested helper app fixed that
launch failure while retaining the sandbox. The second package passed inference,
startup and signature checks before atomic publication. No production source
changed after that build; documentation was updated afterward.

## Current artifact and model

- Chromium **155.0.8059.84**, commit `5869fe313571d75152b77813cf0a4ee26a4e6df0`; reused the verified locally compiled engine without a new C++ build.
- Native input fingerprint `6a5dd6ca1a044b5de1d52b033188548c9a477bca196f25dca53642ce2ef875cc`; embedded source receipt `1f2af548aa9a52f3325471b2627ab950784874ba0815db06884b08980d22afb3`.
- Apple Development team **PV65ZWXCWX**; outer CodeDirectory hash `5de26d296e64ee034b6c0e24d91af74525fc46d0`.
- Helper CodeDirectory hash `28609ccc185cecc55038a803c8d0aa7ee2dde193`; executable SHA-256 `0c289357299ee408a06334dbaf790a25bad77f837a8981a49ab2593334388446`.
- Hardened runtime and library validation retained (`0x12a00`); helper entitlement is exactly `com.apple.security.app-sandbox = true`.
- PhishLang commit `6b7283854ef8a6edc73f945c1ce7e51b2e1dc4fd`; compiled model **98,273,259 bytes**, directory digest `4bbcaf00ab81fdf8845b7ad149bf7b3dddd55c0d45a8e65342af1d3d52da106a`.

Three fresh bundled-helper processes on an **M4 Pro with 24 GB RAM** measured
**111 MB peak helper RSS**, **12–63 ms tokenization/inference**, and **43–93 ms**
including startup/model load. Filesystem caches were not purged. These figures
exclude Chromium, macOS and other tabs. Real **8 GB hardware remains unqualified**.

## Limits and remaining work

Integration passed; detection accuracy has not been established. An ordinary
synthetic login structure scored almost 1.0, demonstrating false-positive risk.
The 0.9 threshold is an engineering choice. The filtered parser and bounded windows
differ from the full research system. Fresh legitimate/phishing evaluation with
separate domains and times is required before enabling warnings by default.

Classification occurs after page load; scripts may already have executed. It is
not a comprehensive credential-submission barrier. Long pages, frames and shadow
content have limited coverage. Failed/limited analysis never reports a safe verdict.

The paper is CC BY 4.0; the reviewed repository/fine-tuned weight metadata did not
specify a separate artifact license. The model records that unresolved scope and
local-development status; attribution and the base MobileBERT Apache-2.0 license
are bundled. Public/commercial redistribution clearance remains separate.

This remains an Apple Development build. Developer ID/notarization, automatic
engine/security-data/model updates, reputation feeds and real Apple credential
qualification remain open. The [earlier CVE sweep](report.md) and
[agent remediation](remediation.md) are unchanged historical records. This port
did not repeat a full upstream CVE fetch or exploit/fuzz campaign.

[Machine-readable record](phishlang-port.json) and
[raw evidence](../../../.cache/qa/phishlang-port-2026-10-19/) retain package logs,
test results, independent reviews, runtime cleanup and the actual warning screenshot.
