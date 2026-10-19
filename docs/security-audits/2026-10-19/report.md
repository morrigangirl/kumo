# Kumo security sweep — October 19, 2026

The sweep found **two reproducible Medium issues in Kumo's agent controls** and confirmed security-update gaps that block a production release. It found **no publicly listed Chrome CVE in the selected window whose Google fix-version bound exceeds Kumo's Chromium 155.0.8059.84 baseline**. That is advisory coverage, not a claim that every upstream fix or exploit was independently verified.

The reviewed agent files match the copies inside the current signed `dist/Kumo.app`. No product source, application, browser profile or security setting was changed during this audit. The two findings remain present.

## Scope and baseline

- Window: **September 19, 2026, 10:07:52 AM through October 19, 2026, 10:07:52 AM, America/New_York**; exactly 30 days. Later announcements are outside this snapshot.
- Target: native Apple Silicon macOS Kumo, locally compiled Chromium **155.0.8059.84**, commit `5869fe313571d75152b77813cf0a4ee26a4e6df0`.
- Source fingerprint: `6a5dd6ca1a044b5de1d52b033188548c9a477bca196f25dca53642ce2ef875cc`; embedded receipt: `1f2af548aa9a52f3325471b2627ab950784874ba0815db06884b08980d22afb3`.
- Reviewed Google release announcements, linked public Chromium/V8 changes, all referenced desktop CVE authority records, source preparation/build settings, native Passwords code, extension permissions, Store/updater changes and the local agent bridge.
- No real account/vault access, exploit execution, browser launch, engine rebuild or live hostile-site testing. This is a bounded source/advisory review rather than a full Chromium audit or penetration test.

## Confirmed custom-code findings

### KUMO-AUDIT-EXT-001 — Medium: agent grant does not bind the displayed origin

The grant dialog records the displayed origin and requests that site's extension permission, but sends only tab IDs to the worker. The worker reads each tab's current URL and grants its current origin. If the tab navigates while the dialog is open and the destination retains a host permission from earlier use, the grant can authorize a different origin from the one the person confirmed.

Evidence: [newtab.js:116](../../../extension/newtab.js#L116), [newtab.js:132](../../../extension/newtab.js#L132), [background.js:245](../../../extension/background.js#L245).

The unchanged production UI and worker handlers reproduced a displayed/requested `https://example.com` becoming an actual grant for `https://other.example`. The connected client could then list that destination. A destination without retained host permission was rejected by the negative control. Default-off agent access and required prior host permission limit exposure; the flaw still violates the origin-specific confirmation boundary.

**Fix:** send the expected origin with each selected tab ID; validate current and pending navigation against that expected origin when committing the grant. Reject and refresh the dialog on mismatch. Retain host-permission checks and test navigation before/during configuration, including previously authorized destinations.

### KUMO-AUDIT-EXT-002 — Medium: tokenized OTP markup bypasses action exclusion

The sensitive-field check matches `autocomplete="one-time-code"` exactly. A valid token list such as `autocomplete="section-login one-time-code"` does not match, so the injected agent function permits type/click actions on that verification-code field.

Evidence: [background.js:164](../../../extension/background.js#L164), with action paths at [background.js:178](../../../extension/background.js#L178) and [background.js:188](../../../extension/background.js#L188). Pinned Blink's autocomplete parser accepts the section prefix.

The actual worker and injected function accepted synthetic type/click actions using a deterministic DOM shim. The exact unprefixed OTP form was rejected. This establishes an action-policy bypass; it does **not** demonstrate reading an existing OTP/password, crossing an origin boundary or escaping Chromium's sandbox.

**Fix:** use normalized, case-insensitive autocomplete token matching consistently, with tests for section prefixes, casing and whitespace. Preserve exclusion of passwords, payment fields, hidden/file fields and noneditable controls.

Both findings were independently reproduced and reviewed. Neither is assigned a CVE or claimed to be an instance of a Chrome CVE. As an interim mitigation, leave agent control off until these are repaired and the updated package is validated.

## Existing release-blocking security gaps

| Area | Confirmed behavior | Required work |
| --- | --- | --- |
| Engine updates | `enable_updater=false`; no Kumo engine updater/release feed exists. Extension updates do not update Chromium itself. | Establish prompt Chromium security rebases and authenticated, signed browser update delivery, including failure/downgrade handling. |
| Security-data updates | The prepared global component checker returns before doing update work. CRLSet and PKI Metadata remain registered, but registration does not deliver new data. | Provide a maintained, authenticated channel for revocation/root constraints, CT log lists and relevant key pins; review privacy behavior before restoring endpoints. |
| URL/download reputation | Safe Browsing database, remote and download-protection paths are disabled/removed. DNS blocking is not URL or file reputation. | Integrate maintained, appropriately licensed non-Google protection matching the intended product security claims. |

Evidence includes [config/chromium.gn:25](../../../config/chromium.gn#L25), prepared `components/update_client/update_checker.cc:105–109`, component registrations and generated build flags. These are existing design/release gaps, not newly assigned CVEs.

**CT deadline:** the bundled CT log data is dated September 20. The actual policy considers it timely for 70 days. Without refreshed data, it becomes untimely on **November 29, 2026 at 8:35:40 AM New York time**. `ChromeCTPolicyEnforcer::CheckCompliance` then returns `CT_POLICY_BUILD_NOT_TIMELY`, and `RequireCTDelegate::CheckCTRequirements` treats that result as requirements met. SCT-based root constraints are also gated on timely data. This is a source-backed future fail-open condition; the bundled list is currently timely and ordinary TLS certificate validation remains enabled. No future-clock runtime experiment was performed. A rebuilt engine with refreshed data or a validated data-update path can change this deadline.

Development signing, absent approved Apple passkey provisioning and unexecuted clean-machine notarized release QA remain distribution/feature gaps. They are not evidence of a Chrome CVE.

## Chrome CVE and changelog coverage

The saved official feed contains 61 posts in the window, including 24 desktop announcements. Six Stable desktop security announcements list **445 distinct newly published CVEs**. Extended Stable also reannounces **four older CVEs**, bringing the desktop inventory to **449**. Each has a successfully retrieved, hash-recorded Google CNA record.

| Stable announcement | Published fixed-version family | Listed CVEs |
| --- | --- | ---: |
| September 22 | 154.0.8037.57/.58 | 108 |
| September 29 | 154.0.8037.92/.93 | 32 |
| October 1 | 154.0.8037.97/.98 | 11 |
| October 6 | 155.0.8059.39/.40 | 247 |
| October 13 | 155.0.8059.79/.80 | 37 |
| October 15 | 155.0.8059.84/.85 | 10 |

Google's CNA text identifies **340 Mac/shared records** and **109 explicitly Android, iOS or Windows records**. The Mac/shared set comprises 15 Critical, 125 High, 130 Medium and 70 Low records. These are upstream advisory severities, not counts of currently open Kumo vulnerabilities. Shared means the CNA description does not name a single platform; it is conservatively retained for Mac review.

Every Google "prior to" statement agrees with its exclusive `lessThan` fix bound, and all those bounds are at or below `.84`. The matrix labels this **upstream-version-covered**. The CNA `version` field repeats the bound; the audit does not mistakenly treat that repeated value as an inclusive vulnerable starting version. See the 449-row [CVE matrix](cve-matrix.csv), [summary](summary.json), [release inventory](release-inventory.json) and [expanded shorthand versions](release-versions-expanded.json).

No inventoried CVE matched the downloaded CISA Known Exploited Vulnerabilities catalog, and the captured desktop announcements contained no exploitation-in-the-wild notice. Absence from those sources is not proof that exploitation has not occurred.

### Source preservation checks

- Official tag lookups match Kumo's exact `.84` commit. The official `.85` commit is its direct child and changes only `chrome/VERSION` from patch 84 to 85. That numbering difference does not identify a missing security-code change.
- The `.79 → .84` comparison contains 93 entries: 73 local files exactly match final upstream Git blob hashes; six differ; two are gitlink directories; twelve are absent platform/test paths. All four differing production files were reviewed against exact upstream contents, and all seven new fix hunks remain intact. The other two differing entries are tests/fuzzing. The absent entries are Android/iOS or Blink tests, not Mac production C++.
- The latest V8 roll contains ten production/version files, all matching final upstream blob hashes. Six regression files were pruned from the lite archive. No V8 exploit/regression execution is claimed.
- September and October fixes on older major branches were assessed using Google CNA bounds. Release branches diverge, so numeric version comparisons are **not** represented as proof of cross-major commit ancestry or independent per-CVE patch validation.
- Beta, Dev and Early Stable notices/changelog links were inventoried. Their entire commit histories were not audited, and no assurance is given for unpublished/restricted security bugs or future releases.

The inspected build retains V8 sandboxing, pointer compression, bounds checks, stack protection, fortification, libc++ hardening, Chromium process sandboxing and certificate-validation paths. No concrete exploitable flaw was identified in the reviewed native Passwords adapter or restored Store/updater boundaries. These observations do not establish full Chrome security parity or absence of other defects.

## Validation and evidence

- Full existing JavaScript suite: **51/51 passed** after allowing its required local Unix sockets. The initial sandboxed run failed socket creation with `EPERM`; that environment failure is preserved and is not counted as a product regression or pass.
- Existing Store/updater overlay checks: **27 passed, one expected pristine-tree skip** against an already-applied source tree.
- Native command regressions: **3/3 passed**; AppKit panel syntax/warnings check passed.
- New reproductions: **3/3 reproduced the two issues and negative control**, independently repeated. A passing reproducer means the flaw exists; these are not fixes.
- Missing new runtime coverage includes certificate-error, embedded-frame and BFCache/process-crash negative native Passwords cases, hostile update rejection, real credentials and exploit/fuzz testing of the Chromium tree.

Raw advisories, CNA records, fetch hashes, source comparisons, actual code diffs, test logs and peer-review results are retained in `.cache/qa/security-sweep-2026-10-19/`. Important records are `upstream/cve-matrix.json`, `native/upstream-peer-review.json`, `native/extension-peer-review.json`, `extensions/findings.json`, `root-independent-repros.log`, `source/source-review.md`, `source/ct-staleness-call-chain.json` and `packaged-js-comparison.json`.

Recommended order: repair the two agent boundaries and revalidate the packaged app; implement browser and security-data update delivery; close reputation-protection and production-release validation gaps. Preserve this dated snapshot and rerun advisory collection against the exact next source lock.

Primary references:

- [Google Chrome release feed for the audit window](https://chromereleases.googleblog.com/feeds/posts/default?alt=json&max-results=150&published-min=2026-09-19T00%3A00%3A00-04%3A00&published-max=2026-10-20T00%3A00%3A00-04%3A00) — locally filtered to the exact audit cutoff.
- [Google's October desktop release archive](https://chromereleases.googleblog.com/2026/10/) and [September archive](https://chromereleases.googleblog.com/2026/09/).
- [CVE authority API example: CVE-2026-110922](https://cveawg.mitre.org/api/cve/CVE-2026-110922) — every record's exact API URL and hash are in the matrix.
- [Official Chromium .85 commit](https://github.com/chromium/chromium/commit/0e66b94549a8bd85f03fbdf189b752d6e7b63c32), [Chromium .79→.84 comparison](https://github.com/chromium/chromium/compare/155.0.8059.79...155.0.8059.84), and [V8 comparison](https://github.com/v8/v8/compare/d89479ac5446a374c55a35be19b5a23437558d99...712e1808de2d7416f1276d0deb1ee4ac978132b8).
- [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).


Export note (2026-10-19): machine-specific checkout paths were converted to repository-relative references. Findings and evidence hashes are unchanged. The original report is retained privately under `.cache/qa/desktop-connectivity-2026-10-19/original-audit-exports/report.md`; its SHA-256 is `80321eca4ea69b65a4da7063593401230469928179e12c512318cb7dccc044fd`. Historical references to the original report hash identify those original bytes.
