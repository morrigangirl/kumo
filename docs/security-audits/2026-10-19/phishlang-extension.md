# Separate PhishLang extension — 2026-10-19

Kumo PhishLang is a separately packaged Manifest V3 extension and native Swift/Core
ML companion. It has extension ID `ejmohaggcahgfhmgkdiicnmmlpnhgfmi`, native host
`com.kumo.phishlang`, an optional website-access grant, and starts off. It runs
alongside Kumo’s model-free built-in extension. Its runtime needs neither Python
nor a cloud AI account. The local add-on ZIP includes the model.

## Result

- 170 JavaScript tests, 27 native tests (no skips), and 9 package tests passed.
- Independent artifact review passed 320 checks across all 40 distributed files.
- Both native binaries have strict Carson Press LLC Developer ID signatures,
  secure timestamps, hardened runtime and library validation. The classifier’s
  only entitlement is App Sandbox; it has no network access entitlement.
- Every extracted ZIP file matched its package receipt; both native signatures
  survived extraction. The archive is a local signed build, not yet notarized.

## Actual browser and installation checks

The actual signed Swift installer installed the helper, stable extension and
origin-restricted native registration into owned temporary directories. Real Kumo
loaded the separate extension and its built-in extension simultaneously. Local
Native Messaging/Core ML produced a benign article result and synthetic phishing
warnings. Agent grants stayed off; Kumo’s own model remained omitted.

The real content script excluded filled password/OTP/email values, editable text,
script bodies, hidden sentinels and private link/document query information from
native payloads. Warnings displayed only the origin. Leave replaced the warning
with `about:blank`; Continue allowed one returned document and a reload warned
again. Turning protection off removed its scripts and stopped inference;
re-enabling scanned an already open synthetic page. Actual uninstall and process
cleanup completed. No external page request or personal account access occurred.

The initial Leave target `chrome://newtab/` reached an error page when the separate
Kumo new-tab extension was present. The final add-on uses `about:blank`, including
its expired-warning fallback; its label and regression assertions match this
behavior. The integrated development controller’s default remains unchanged.

## Installer and packaging safeguards

Tests cover symlink/hardlink rejection, unrelated installation preservation,
complete custom-target requirements, exclusive file publication, rollback, foreign
host arrival during staging, and source mutation after app staging. The stable
extension is copied only from the signature-verified staged companion. Model,
vocabulary and conversion metadata are rechecked after copying and before signing.
Private keys, conversion runtimes and developer-machine paths are absent from the
deliverable. The original model attribution and provenance notices are preserved.

## Limits and evidence

These synthetic tests establish integration and isolation, not phishing accuracy
or calibration. The whole browser/add-on has not been qualified on an 8 GB Mac.
Website permission prompts were pregranted only in the disposable copied QA
manifest; direct gesture, denial and grant-removal behavior have separate tests.
No default browser profile or installation was modified; no public add-on binary
was uploaded. A Chrome Web Store submission and notarization are separate from
this local package.

The adjacent JSON records archive identity, exact source/evidence hashes and all
seven browser scenario groups. Detailed local evidence is under
`.cache/qa/phishlang-addon-2026-10-19/`, including the independent artifact review,
real browser results and archive extraction verification. Installation and removal
instructions are in [the add-on README](../../../addons/phishlang/README.md).
