# Kumo 0.1.0 production release — 2026-10-20

[The notarized release](https://github.com/morrigangirl/kumo/releases/tag/v0.1.0-202610190001)
was published as GitHub Latest on October 20, 2026. Build `202610190001` uses source
commit `9349018fb584f54ff29be7d33f4edb9e7deb8b4c` and Chromium `155.0.8059.84`.
The production app is installed at the build Mac’s existing `dist/Kumo.app`.

## Apple and artifact verification

Apple accepted submission `d3ee0a6a-95a8-4586-aee2-c107e884ab5b`. Its submission
was made October 19; acceptance was confirmed October 20. The ticket was stapled
and validated, and Gatekeeper explicitly accepted the app as **Notarized Developer
ID**. All 25 native code items passed strict all-architecture Developer ID, Carson
Press LLC team and secure timestamp checks. The complete deep strict seal passed.

Every file and framework alias from the exact signed app previously tested was
compared against the extracted distribution archive. All 625 previous entries
matched; the only addition was `Contents/CodeResources`, Apple’s stapled ticket.
No browser/helper code, configuration or resource seal changed after those runtime
checks. The raw source engine’s 11 and framework’s 39 code/data sections, completed
source receipt, 16 extension sources and eight agent runtime files matched.

The app omits the experimental model/helper, retains domain blocking and ClamAV
integration, and has its production GitHub updater enabled. The earlier runtime
checks include model retirement/UI, domain blocking, twelve actual antivirus
completion/cancellation cases and native updater status. See the October 19 release
preparation evidence for those checks and the adjacent JSON for the exact binding.

## Publication and update feed

The publishing tool verified the clean source commit and local/remote tag, exact
five-asset draft, signatures, archive and notarization. It uploaded and downloaded
the complete draft, verified identical bytes, then published it as Latest.

An anonymous HEAD request to the exact ZIP URL returned HTTP 200 and the expected
169,940,338-byte length. An anonymous fetch of the stable appcast returned the
exact 2,031 prepared bytes; the official Sparkle tool verified its signature.
Neither request used cookies or account authorization. The stable feed is:

`https://github.com/morrigangirl/kumo/releases/latest/download/appcast.xml`

Archive SHA-256:
`9688a7e82c560f7d872877ae0d1d338101dafd91291d1f2d68aceb0aa84a8bbc`.

## Local installation

The existing registered application was closed. A staged copy matched every one
of the 626 extracted file/alias entries and passed signature, ticket and Gatekeeper
checks. Exclusive locks were held on both old and new app coordination resources;
process closure was checked again before atomic replacement. The previous
application was preserved under `dist/backups/`. The installed copy’s complete
manifest and strict seal matched, and Launch Services resolved Kumo’s bundle ID to
`dist/Kumo.app` after registration refresh. No default-browser choice was changed.

The installed updater’s read-only status returned `available: true`, `reason:
ready`, the exact release version/build, pinned GitHub feed and Sparkle 2.10.0.
No personal browser profile was opened or modified during verification/install.

## Practical limits

This first production release has no subsequent production version against which
to exercise a full Sparkle replacement. The update policy, compiled locking and
choice tests, signed feed/archive verification and actual production readiness
checks passed; a later production-to-production replacement remains a separate
check. The optional managed Apple browser-passkey profile is still absent.
Notarization does not guarantee freedom from vulnerabilities or complete Chrome
feature/security parity.

The adjacent JSON records release metadata, source/runtime binding, backup path
and SHA-256 hashes of detailed local evidence in
`.cache/qa/production-release-2026-10-20/`. Historical audit snapshots remain intact.
