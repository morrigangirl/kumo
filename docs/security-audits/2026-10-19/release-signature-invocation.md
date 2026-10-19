# Production signature verification invocation

The first production signing attempt stopped before Apple submission. The
signer passed a textual certificate requirement as the value after `codesign
-R`; Apple's CLI interpreted that value as a filename and rejected it as an
invalid requirement specification.

The corrected invocation prefixes the inline requirement with `=`. It retains
strict verification for all architectures, Apple's generic anchor, the
Developer ID Application certificate OID and the configured team. Signature
timestamp, authority, flags and exact entitlements are still checked separately.
No trust condition was relaxed.

Three new regressions cover the actual argument boundary and inline syntax,
dynamic team binding, and rejection of inconsistent signature metadata. The
argument regression fails against the old implementation. All **34 release
tests** (27 publisher, four vendor and three signature invocation tests) and
**72 package tests** pass.

A read-only invocation of the installed `codesign` also accepted the corrected
inline syntax and Apple/team requirement against the existing development
candidate. That syntax probe does not claim Developer ID signing or
notarization of the candidate. Its raw result remains local at
`.cache/qa/production-release-2026-10-19/codesign-requirement-syntax.json`.

The fix changes release tooling only. It requires no Chromium or app rebuild.
Successful production signing, notarization and archive verification remain
required before publication.
