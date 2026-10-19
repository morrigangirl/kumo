# Model-free release candidate

Kumo 0.1.0, build 202610190001, is prepared without the experimental PhishLang
checkpoint, vocabulary, native inference helper or its Native Messaging
template. Domain blocking and the ClamAV download gate remain included. The
explicit packaging option is `--without-phishlang`; default development builds
can still include the model.

The completed Chromium 155.0.8059.84 engine is reused with its verified source
receipt. Its source input digest remains
`92acde368a82bc38610f1e310f97a769658d901aa53f0988db3a0b38b568814c`.
The new package/runtime changes do not alter the engine's source inputs.

Validation passed:

- 153 JavaScript tests, 72 package tests and 27 release tests.
- 25 compiled launcher tests, including five new native-host retirement cases.
- Two real browser starts confirmed model-free status, disabled controls,
  removal of an old enabled preference and persisted content script, and
  rejection of classifier enablement without a Native Messaging call.
- All 211 static domain rules matched in Chromium. Actual main-frame,
  redirect and subresource blocking, disable/re-enable, persistence through
  three browser starts and website-sender authorization checks passed.
- The candidate passed isolated engine/scanner startup and deep strict code
  signature checks. The Developer ID preflight has no blockers.

The model-free browser smoke's initial harness expected an `ok: false` error
field; the existing message API returns `{error: string}`. After correcting that
assertion, the full smoke passed without changing the candidate app. Both logs
are retained locally.

Independent review found no actionable security blocker in omission, runtime
availability gating, old-state retirement or safe native-host manifest unlink.
Tests use disposable profiles, copied extension resources, inert loopback
fixtures and mock Keychain storage. They do not access personal accounts or
real passwords, and do not establish antivirus detection coverage.

A valid Carson Press LLC Developer ID Application identity and an authenticated
notarization Keychain profile are now installed. This record describes the
development-signed candidate before production notarization, archive
verification and publication. It does not claim live updates are active.

The [machine-readable record](model-free-release.json) binds this snapshot to
its source files, app identity and local evidence.
