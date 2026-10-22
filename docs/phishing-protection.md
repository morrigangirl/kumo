# Local phishing warnings

This page describes the **native 0.2.0 implementation**, whose full browser build
and release qualification are still in progress. Kumo 0.1.1 and 0.1.2 used the
earlier extension integration and started with warnings off. Historical results
below apply to those recorded builds, not automatically to the new native port.

In 0.2, local PhishLang warnings default **on** for new profiles and previously
unset preferences. Existing explicit opt-outs are preserved. Control them in
**Settings → Kumo** (`chrome://settings/kumo`). The browser owns the preference,
collection, helper connection and warning page; there is no Kumo extension and
no extension website-access prompt.

An enabled preference and working protection are separate states. Kumo reports
migration pending, starting, ready, unavailable or off. Page collection waits for
successful settings migration and actual model readiness. A missing or failed
model stays unavailable and never produces a safe-site verdict. Turning warnings
off cancels pending work, stops the helper and disconnects the document sampler.

## What happens on a page

The native browser observes eligible top-level HTTP(S) documents after loading.
It runs a bounded sampler in a dedicated isolated JavaScript world, then sends
only the filtered text representation to its fixed local helper. Restored tabs
can be sampled once protection becomes ready. Internal pages, error documents,
private/incognito pages, Chrome Store pages and URLs containing credentials are
excluded.

A high score opens the browser-owned `chrome://kumo-phishing-warning/` page.
It displays the site's origin with **Leave this site** and **Continue anyway**.
The browser binds an expiring ticket to that exact tab and destination; the page
cannot supply another URL. Continuing authorizes only the returned committed
document. Reloading checks again. Leaving goes to a blank page. The warning
buttons require a real user action; ordinary web pages and agents do not gain a
system-action bridge through this UI.

The native dangerous-domain service is a separate layer. Its network admission
hooks check known blocked hosts and redirect destinations using a bundled list
and a validated fixed-source update. That check does not depend on the PhishLang
model. An unavailable list is reported separately; startup waits are bounded and
do not turn an unavailable list into a safe-site verdict. Coverage across the
new native network hooks still needs final browser qualification.

## What runs on the Mac

The app bundles one FP32 Core ML model and vocabulary inside the dedicated
`Contents/Helpers/KumoPhishing.app` bundle. The browser verifies its signed helper
and launches that fixed executable with `--browser-stdio`, using private inherited
pipes and bounded length-prefixed JSON messages. No extension origin, executable
path, model path or shell command comes from a web page.

The Swift helper uses CPU-only inference, App Sandbox, hardened runtime and
library validation, with no network entitlement. Python, PyTorch, Transformers
and Core ML conversion tools run only on the build host. No AI account, API key
or online inference service is needed for browsing.

Phishing analysis is independent of Codex/Claude access. Enabling protection
neither enables agent control nor grants tabs to an agent. Native agent grants
and their origin/revocation rules remain separate. The model channel exposes
only status and classification; it cannot install software or change desktop
client settings.

## Data and work limits

The sampler represents headings, paragraphs, sanitized links and form structure.
It excludes filled field values, checked state, editable content, script bodies,
event handlers, cookies, browser storage, clipboard and password stores. Form
text and input names/placeholders are not copied. Link credentials, query
strings, fragments and non-allowlisted path components are removed. Common
email/token/secret/number patterns in visible text are redacted.

The full current page URL remains inside the browser for document/revision
binding and the warning ticket; it is not sent to the model. The warning shows
only its origin. Visible page text can still contain personal information that
these rules do not identify. Analysis remains local; the helper does not log
page text, results or visited URLs. QA uses owned synthetic fixtures.

- At most 24 KiB of UTF-8 output and 256 candidate elements per sample. Discovery
  visits at most 12,000 nodes; text extraction has a separate 8,000-node budget.
- At most eight admitted classifications per document, separated by at least
  two seconds. Unchanged document revisions/payloads avoid repeated inference.
  A saturated queue does not consume a document's admission budget.
- At most four pending classifications and one sequential helper/model process
  per original browser profile. Inputs use 128-token windows, at most eight
  windows including a tail window. Omitted content is marked limited.
- Native document identity, exact URL, generation and live DOM revision are
  checked before a warning. Navigation, page replacement, relevant mutation and
  disabling invalidate stale results. Warning tickets expire after ten minutes.
- Subframes, shadow roots, hidden/editable content and content beyond the bounds
  are not fully analyzed. These limits are not a complete secret detector.

This is an asynchronous page classifier: scripts may run before a result arrives.
It does not comprehensively intercept credential submission or custom JavaScript
exfiltration. Low scores mean **no signal**, not proof of safety. ClamAV download
scanning is a separate layer; there is no cloud download-reputation service.
Model changes ship with signed browser updates rather than an independent
background model-download channel.

## Model provenance and behavior

The source is [UTA-SPRLab/phishlang](https://github.com/UTA-SPRLab/phishlang), commit
`6b7283854ef8a6edc73f945c1ce7e51b2e1dc4fd`. Authors: Sayak Saha Roy and Shirin
Nilizadeh. The importer downloads five immutable data files and verifies their
Git blob IDs, sizes and SHA-256 hashes. It does not execute upstream Python,
installers or pickle files. Conversion wheels are pinned by version and hash in
[the model lock](../config/phishlang-model-lock.json). Model loading during
conversion is offline and uses Safetensors.

The original conversion checks passed ten synthetic FP32 Core ML/PyTorch
comparisons, with maximum class-score probability difference about 0.00000234.
The Swift tokenizer matched sixteen upstream fixtures. Compiled model size is
about 98.3 MB. These establish conversion/tokenizer parity, not detection accuracy
or calibration; changing browser integration requires its own runtime checks.

The browser uses the maximum class-1 score across bounded windows and warns at
0.9. This is an engineering threshold, not a calibrated 90% probability that a
site is malicious. Synthetic tests include an ordinary login structure that
scores strongly. Expect false positives and missed threats. The privacy-filtered
parser, bounded windows and native runtime differ from the authors' complete
research system; their published accuracy does not establish this port's
performance. Enabling warnings by default is a product decision; fresh,
domain/time-separated legitimate/phishing evaluation remains outstanding.

The authors' [publication](https://arxiv.org/abs/2408.05667) is CC BY 4.0. On
October 20, 2026, the project owner accepted the interpretation that the authors'
published repository and checkpoint are covered by that license and authorized
public distribution with attribution and change notices. The accepted decision
is recorded in [the distribution policy](../config/phishlang-distribution.json)
separately from unchanged upstream/conversion evidence; no additional author
confirmation was obtained. Production packaging checks the exact checkpoint
against that decision. The base Google MobileBERT model declares Apache-2.0.
[Attribution and changes](../native/phishing/NOTICE.md), license links and the
MobileBERT license text are bundled with the model.

## Build and qualification

On the configured Apple Silicon build host with Xcode installed:

```sh
/usr/bin/python3 scripts/prepare-phishlang.py
bash scripts/build-phishing.sh
python3 -m unittest scripts.test_native_protection scripts.test_phishing_package -v
xcrun swift test --package-path native/phishing
```

Model conversion uses the pinned Python 3.9 environment; it is not a runtime
requirement. Build the complete reviewed native Chromium source and pass its
finished app to `scripts/package.py`, as described in
[source builds](source-build.md) and [release preparation](github-releases.md).
Packaging validates model hashes/interface, signs the helper with its sandbox
entitlement, verifies the parent app and performs real framed inference over the
native browser channel before atomically publishing an app. A failed probe
preserves the previous output. Do not use an old source tree or extension smoke
harness to claim native 0.2 browser qualification.

Focused native-port work has passed compiled C++ policy fixtures, actual sampler
privacy/bounds/revision cases, Swift channel tests and syntax checks against the
pinned Chromium headers. The full 0.2 engine build, link, packaged helper probes
and actual-browser migration/warning/cancellation flows remain separate gates.
No 0.2 browser release is established by these source-level results.

For historical context, the [0.1 port validation](security-audits/2026-10-19/phishlang-port.md)
records 102 JavaScript tests, 13 native methods, 28 package tests, 18 signed-helper
checks and six browser scenario groups. Warning navigation, Continue/reload,
toggling, secret exclusion and agent isolation passed on that integration.
They are not native 0.2 acceptance results or detection-accuracy tests.

An 8 GB Apple Silicon Mac remains the intended minimum target. Three historical
bundled-helper benchmarks on an M4 Pro with 24 GB RAM observed about 111 MB peak
helper RSS, 12–63 ms tokenization/inference and 43–93 ms total startup/model-load/
inference time. Each used a fresh process; filesystem caches were not purged.
These numbers exclude Chromium, macOS and other tabs. Whole-browser performance
and default-on protection under a busy-tab workload still require measurement
on real 8 GB hardware.
