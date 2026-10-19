# Kumo local phishing host

This is a native Swift/Core ML inference host for the separately converted PhishLang
MobileBERT classifier. It contains no network client, page fetcher, Python runtime,
browser-control tool, or credential reader. The extension supplies bounded,
preprocessed page text; the host never receives filled form values by design.

The integrated development helper is a dedicated app at `Kumo.app/Contents/Helpers/KumoPhishing.app`.
Its executable is `Contents/MacOS/KumoPhishingHost`; resources are fixed at that
helper's `Contents/Resources/PhishLang/{PhishLang.mlmodelc,vocab.txt,model-info.json}`. Chrome
Native Messaging must pass exactly the allowed Kumo extension origin as its sole
argument. An origin mismatch exits before loading resources or reading requests.

The helper app has its own signed Info.plist (`app.kumo.phishing`) and is signed
with App Sandbox enabled and no network entitlement, plus hardened runtime and
library validation. Signing only a secondary executable in the outer browser
bundle omits its signed bundle identifier: macOS then aborts in sandbox bootstrap
before `main`. The dedicated app retains sandbox isolation while permitting access
to its own bundled model. The packaged helper's actual framed startup/classification
check must pass before a rebuilt Kumo replaces the previous app.

Requests are 32-bit little-endian length-prefixed JSON, at most 256 KiB:

```json
{"id":"status-1","type":"status"}
{"id":"page-1","type":"classify","text":"bounded preprocessed synthetic page text"}
```

IDs are nonempty strings of at most 128 UTF-8 bytes; text is at most 32,768 Swift
characters and is also constrained by the frame limit. Extra keys, malformed
requests, unknown actions and incomplete/oversized frames are rejected. No request
can select a model or filesystem path. The host writes only framed JSON to stdout
and does not log request contents. The frontend owns cancellation and stale-tab
checks. Host requests run sequentially and share one CPU-only Core ML instance.

The uncased BasicTokenizer/WordPiece vocabulary feeds 128-token windows (126 page
tokens plus CLS/SEP, stride 64), capped at eight. Larger inputs use seven initial
windows and one tail window and return `truncated`/`coverageLimited: true`. Each
response reports the maximum class-1 softmax probability over its windows. At the
provisional 0.9 threshold it returns `suspicious`; other scores return `no-signal`,
which is not a safety assurance. Empty/short text still receives one window.
Missing/corrupt models and inference failures return explicit unavailability/error,
never a benign verdict. This threshold is not yet calibrated on current phishing.

Build with `scripts/build-phishing.sh`. Run synthetic tests with:

```sh
xcrun swift test --package-path native/phishing --scratch-path build/phishing-native-tests
```

For offline parity and memory diagnostics, the command-line-only diagnostic mode
accepts a single **synthetic** JSON request on stdin and writes unframed JSON:

```sh
printf '%s' '{"id":"synthetic","type":"classify","text":"Example sign in page"}' |
  build/phishing-native/KumoPhishingHost --benchmark --resources build/phishlang-model
```

`--self-test` accepts the same arguments/input. Diagnostic model paths cannot be
passed through Native Messaging. `peakResidentBytes` is the host's Darwin high-water
RSS, not total Kumo/system memory; an actual 8 GB Mac remains necessary to qualify
an 8 GB minimum. Unit tests use synthetic inputs and do not access user profiles.

Model source pin: UTA-SPRLab/phishlang `6b7283854ef8a6edc73f945c1ce7e51b2e1dc4fd`.
The paper is CC BY 4.0; explicit redistribution rights for separately hosted code
and trained weights remain unresolved. Model packaging is local-development-only
until those artifact rights are established. This Swift implementation is original
bridge/tokenizer code; upstream model attribution and conversion metadata travel
with the model resources. MobileBERT's base model is Apache 2.0.


## Separate Kumo extension

The optional [standalone add-on](../../addons/phishlang/README.md) packages the
same bounded scanner and native classifier independently of Kumo.app. Its
extension ID is `ejmohaggcahgfhmgkdiicnmmlpnhgfmi`; its native host name is
`com.kumo.phishlang`. The companion is `Kumo PhishLang.app` (`app.kumo.phishlang`).
A sealed Info.plist selects this fixed standalone origin. An absent selection
retains the integrated Kumo origin; malformed or unrecognized selections fail
closed before reading Native Messaging input.

`KumoPhishLangSetup` is a separate, signed Swift installation tool. It checks the
companion’s strict Developer ID signature, team, secure timestamp and exact
sandbox entitlement, then installs the companion and its sealed extension copy
to stable user-owned paths. No administrator password, Python runtime, daemon or
login item is required. Custom test paths require all three target overrides;
linked, unowned and unexpected filesystem contents are rejected. Installation
and removal preserve unrelated browser data and native hosts.

Build with `scripts/package-phishlang-extension.py`. Run native regression tests
through the same Swift package; its setup tests use temporary fixtures and an
injected signature verifier. The browser smoke test separately exercises the
actual Developer ID verifier and real sandboxed inference on the packaged bytes.
