# Local phishing warnings

Kumo 0.1.1 includes a native macOS port of the pinned PhishLang
MobileBERT classifier. Enable it in **Kumo Settings → Privacy & security → Enable
local warnings**, then allow website access. It starts off. Turning it off stops
the native host, unregisters scanning and retires existing page scanners.

This feature analyzes pages after they load. A high model score opens Kumo's own
extension warning page, showing the site's origin with **Leave this site**
and **Continue anyway**. Continue authorizes only the returned document; a reload
is analyzed again. Leave opens a blank page. A missing or failed model produces unavailable/partial status,
never a safe verdict. Low scores are recorded as **no signal**, not proof of safety.

## What runs on the Mac

The app bundles one FP32 Core ML model and vocabulary inside a dedicated signed
`Contents/Helpers/KumoPhishing.app` bundle. Its native Swift helper uses CPU-only
inference and Chrome Native Messaging over inherited standard input/output. It
has App Sandbox enabled, hardened runtime and library validation, with no network
entitlement. Python, PyTorch and Transformers are build-time conversion tools;
they are not installed or run when a person browses. No AI account, API key or
online inference service is required.

The scanner and native host are independent of agent control. Allowing website
access for phishing analysis does not grant a tab to Codex or Claude. The existing
origin-bound agent confirmation and revocation rules still apply.

## Data and work limits

The isolated top-frame scanner reads a bounded representation of headings,
paragraphs, links and form structure. It does not read filled field values,
checked state, editable content, script bodies, event handlers, cookies, browser
storage, clipboard or Apple Passwords. Link credentials, query strings, fragments
and non-allowlisted path components are removed. The current document URL stays
within the browser for result binding and an expiring warning/continuation ticket;
it is not sent to the model. A warning displays only the origin.

Visible page text can itself contain personal information. Analysis remains local;
the helper does not log page text, results or visited URLs. QA traces contain only
owned synthetic fixtures. These exclusions reduce inputs but do not identify every
possible secret embedded in page text.

- At most 24 KiB extracted text, 20,000 traversal nodes and 256 features per scan.
- At most eight scan attempts per document, at least two seconds apart. Transient
  busy/transport failures retry within that budget.
- At most four pending native requests and one native model process per browser
  extension instance. Inputs use 128-token windows, at most eight windows including
  a tail window when necessary. Long/omitted content is marked limited.
- Document IDs, exact URLs and live DOM revisions are checked before warnings.
  Navigation, page replacement, DOM mutation, permission removal and disabling
  invalidate pending work. Warning tickets are serialized, tab-bound and expiring.
- Private/incognito tabs and Chrome Store pages are excluded. Cross-origin frames,
  closed shadow roots and content beyond the limits are not fully analyzed.

This is an asynchronous page detector. Scripts may already have run before a
verdict arrives; it does not comprehensively intercept credential submission or
custom JavaScript exfiltration. There is no before-navigation threat-list check,
download reputation feed or automatic model update channel.

## Model provenance and behavior

The source is [UTA-SPRLab/phishlang](https://github.com/UTA-SPRLab/phishlang), commit
`6b7283854ef8a6edc73f945c1ce7e51b2e1dc4fd`. Authors: Sayak Saha Roy and Shirin
Nilizadeh. The importer downloads five immutable data files and verifies their Git
blob IDs, sizes and SHA-256 hashes. It does not execute upstream Python, installers
or pickle files. Conversion dependencies are binary wheels pinned by version and
SHA-256 in [the model lock](../config/phishlang-model-lock.json). All model loading
during conversion is offline and uses Safetensors.

Ten synthetic FP32 Core ML/PyTorch comparisons passed, with maximum class-score
probability difference about 0.00000234. The Swift tokenizer matches sixteen
upstream tokenizer fixtures. Compiled model size is about 98.3 MB. These checks
establish conversion/tokenizer parity, not detection accuracy or calibration.

The browser uses the maximum class-1 score across bounded windows and warns at
0.9. That is an engineering threshold, not a calibrated 90% likelihood that a site
is malicious. Synthetic tests include an ordinary login structure that this model
flags strongly. Expect false positives. The privacy-filtered parser, bounded
windows and native runtime differ from the authors' complete research system;
their published accuracy does not establish this port's performance. Warnings
remain experimental and off by default pending fresh, domain/time-separated
legitimate/phishing evaluation.

The authors' [publication](https://arxiv.org/abs/2408.05667) is CC BY 4.0. On
October 20, 2026, the project owner accepted the interpretation that the authors'
published PhishLang repository and checkpoint are covered by that license and
authorized their inclusion in Kumo's public browser update. The distribution
decision is recorded in [the distribution policy](../config/phishlang-distribution.json)
separately from the unchanged upstream/conversion evidence;
no additional confirmation from the authors was obtained. Production packaging
checks that the decision covers the exact pinned checkpoint. The base Google
MobileBERT model declares Apache-2.0. [Attribution and changes](../native/phishing/NOTICE.md),
license links and the MobileBERT license text are bundled with the model.

## Build and checks

On the current Apple Silicon build host with Xcode installed:

```sh
/usr/bin/python3 scripts/prepare-phishlang.py
bash scripts/build-phishing.sh
npm test
python3 scripts/test_phishing_package.py
python3 scripts/package.py \
  --engine-app build/source-155.0.8059.84/recipe/build/src/out/Default/Chromium.app \
  --output dist/Kumo.app
node scripts/smoke-phishing.mjs
```

The conversion wheel lock targets the build host's Python 3.9. It is not a browser
runtime requirement. Packaging validates model hashes and interface, signs the
dedicated helper with its sandbox entitlement, signs/verifies the parent app, then
performs real framed inference before atomically replacing the previous app. A
failed probe leaves the previous application intact.

An 8 GB Apple Silicon Mac is the intended minimum target, not yet a qualified
hardware minimum. Three final bundled-helper benchmarks on an M4 Pro with 24 GB
RAM observed about 111 MB peak helper RSS, 12–63 ms tokenization/inference and
43–93 ms total process startup/model load/inference. Each used a fresh process;
filesystem caches were not purged. Memory excludes Chromium, macOS and other tabs.
The complete browser must still be measured on real 8 GB hardware under a busy-tab
workload.

The [port validation](security-audits/2026-10-19/phishlang-port.md) records 102
passing JavaScript tests, 13 native test methods, 28 package tests, 18 final signed
helper checks and six actual-browser scenario groups. Real warning navigation,
Continue/reload behavior, disabling/re-enabling, synthetic secret exclusion and
agent isolation passed. These are integration checks, not detection accuracy tests.
