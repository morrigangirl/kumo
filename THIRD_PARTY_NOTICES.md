# Third-party source and runtime

Kumo's MIT license covers only this project's original code. It does not relicense Chromium, ungoogled-chromium, their patches, or bundled third-party components.

- Chromium source: <https://chromium.googlesource.com/chromium/src>. Chromium's primary license and all third-party notices remain in the source archive. The running browser exposes bundled credits at `chrome://credits`.
- ungoogled-chromium: <https://github.com/ungoogled-software/ungoogled-chromium>, pinned by `config/source-lock.json`. The repository's BSD license and individual patch attributions apply.
- ungoogled-chromium macOS recipe and initial runtime: <https://github.com/ungoogled-software/ungoogled-chromium-macos>, pinned to `155.0.8059.39-1.1`. Its licensing and patch attribution remain upstream. Its original code signatures are verified before preview packaging; the modified Kumo app receives a local development signature and is not an upstream-notarized Kumo distribution.
- The optional browser QA tool is Playwright Core, under Apache-2.0, fetched into the ignored `.cache/qa` directory. It is not included in the browser application.
- The agent bridge uses the installed Node.js runtime through an absolute path. Node.js is not bundled. Its own license applies.
- Apple SDK frameworks are system dependencies and are not redistributed in this repository.
- The experimental local phishing feature includes a pinned PhishLang MobileBERT checkpoint converted to Core ML. Authors: Sayak Saha Roy and Shirin Nilizadeh. Its [publication](https://arxiv.org/abs/2408.05667) is CC BY 4.0; the reviewed repository does not specify the license for its separate code or fine-tuned weights. This development build records that unresolved scope rather than assigning a license to those artifacts. The underlying [Google MobileBERT](https://huggingface.co/google/mobilebert-uncased) model declares Apache-2.0. See [model attribution and port changes](native/phishing/NOTICE.md) and the bundled model notice. Kumo's MIT license does not relicense the model. Conversion dependencies are not included in the runtime application.

Chrome, Chromium, Apple, Codex, Claude, and other product names belong to their respective owners. This project has no asserted affiliation or certification from those vendors.
