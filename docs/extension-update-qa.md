# Native extension-update QA

The third locally built source package passed two real native Update completions and anonymous manifest-transport checks with the bundled helper enabled and then manually disabled. Run 20 preserved command-line location `8`, exact bundle paths and helper states, but did not download a CRX or upgrade old uBlock Origin Lite `2026.1012.1545`. The fourth package completed with the reviewed XML namespace correction. Run 21 on that fourth package passed a genuine manual native upgrade from `2026.1012.1545` to `2026.1018.2229`, with separate saved transport and installed-state correlation. Automatic scheduling remains unverified.

The modified downloader and its updater caller compiled through normal Ninja against Chromium 155.0.8059.84/SDK 27.0, and four source packages completed. The fourth source fingerprint is `6a5dd6ca1a044b5de1d52b033188548c9a477bca196f25dca53642ce2ef875cc`; its normal C++/framework build and signing/packaging completed with embedded receipt `1f2af548aa9a52f3325471b2627ab950784874ba0815db06884b08980d22afb3` at `2026-10-19T13:31:44Z`. Root's strict deep signature check passed (`22-current-artifact-verification.json`). This is a local development browser, not a notarized production release.

## Offline and loopback checks

```sh
node --test tests/extension-update-netlog.test.mjs
node scripts/smoke-update-netlog.mjs
node scripts/smoke-extension.mjs --prepare-only --update-check
```

The parser tests use synthetic NetLog events. The loopback check uses the packaged browser, a disposable profile and a local HTTP server. It sends deliberately synthetic Cookie and Authorization headers only to that server as positive controls, then sends a request with credentials omitted. Default NetLog retains the header names while redacting sensitive values, so missing headers can be distinguished from redacted values. The check also validates response MIME capture and conversion from NetLog timestamps to the wall clock used to scope a manual Update click. It removes Playwright's `--disable-background-networking` default. This is NetLog-schema evidence, not Store/update evidence.

Prepare-only copies and re-signs a generated QA app, verifies it and deletes it without launching Chromium or contacting Store. It may use the preview for setup evidence. It uses the configured Apple Development identity through `codesign`; private keys are never exported. The original app, engine and all retained nested Mach-O code must match the configured Team ID. Each main executable retains its original verified signing-policy flags, excluding ad-hoc/linker bookkeeping, and its corresponding source entitlements. Chromium, the generated launcher and the outer app use the unique QA identifier; their flags, entitlements and Team IDs are checked. Copied nested signatures must remain unchanged. There is no ad-hoc signing fallback or sandbox, certificate or library-validation bypass. This local development signing does not establish Developer ID distribution or notarization.

Prepare-only passed against the preview on 2026-10-18: Team ID `PV65ZWXCWX`, original main policies `0x12a00`, matching source entitlements, 15 unchanged nested Mach-O signatures and a unique QA identifier. The copied superseded Swift launcher was removed because its original signature binds the original Info.plist; the actual Chromium executable was retained and re-signed. The temporary app was removed, and the original app still passed deep strict signature verification. Chromium was never launched, so this establishes setup integrity rather than native Store update behavior.

## Native runtime check

```sh
node scripts/smoke-extension.mjs --app /absolute/path/to/Kumo.app --update-check
```

Functional mode requires `sourceCompiledLocally: true`. The harness prints a generated app path, unique bundle identifier and disposable profile. Use CUA on **that generated app**, rather than the ordinary Kumo app. In its official uBlock Origin Lite Store listing, click **Install in Kumo** and accept Chromium's native **Add extension** confirmation after reviewing it. Do not sign in or import a profile. The fixture is Store ID `ddkjiahejlhfcafbddmgiahcphecmpfh`, linked by the [official uBO Lite project](https://github.com/uBlockOrigin/uBOL-home#ubo-lite).

Send these commands to the harness's stdin in order:

1. `status` checks the installed packed MV3 extension, matching public key/Store ID, module worker, local APIs and nonempty packaged DNR rulesets.
2. `check installed` records the operator's observation of native installation consent and requires those checks to pass.
3. Keep Kumo enabled and send `check updates`. It closes the Store tab, clears only the owned profile's cookies, adds an explicitly synthetic Secure/SameSite=None `.google.com` cookie applicable to `clients2.google.com`, then clicks the actual native **Update** button. Completion must occur within 60 seconds. Native helper metadata and saved preferences must retain the exact state, bundle path and numeric command-line location `8`.
4. Use CUA to turn **only Kumo** off with its native Extensions switch. Keep uBlock Origin Lite enabled, then send `check updates` again. No programmatic helper toggles are permitted. The same state/location/path checks apply to this disabled case.
5. `finish` requires exactly those two successful checks, verifies the installed fixture again, requests owned native shutdown and observes actual child exit before reading the finalized Default NetLog. Each click has a separate, nonoverlapping half-open request-start window; a later success cannot rescue an empty or failed earlier window. All CDP shutdown stages have bounded deadlines. A failed update attempt disqualifies the run; `close` or EOF aborts and cleans up.

The native browser launches without Playwright's background-network suppression flag. CDP attaches only after the native packed installation, so it does not replace Chromium's CRX download/consent flow. The debugging port is ephemeral, loopback-only and confined to this disposable QA app.

## What a successful result establishes

The finalized NetLog must show a successful GET to the exact HTTPS Store update endpoint after the manual click, advertising the installed fixture's ID/version and internal packed location with CRX3 support. Request-header evidence must be present, and the response must declare `text/xml` or `application/xml`; HTTP 200 HTML or a missing MIME type is insufficient. This checks declared XML MIME, not XML-body parsing. Cookie/Authorization headers, account retry parameters, update URL data and activity/roll-call/enablement/disable-reason pings are rejected, including nested `x=` parameters. Redirects, authentication retries and failed HTTP responses fail the check. Only header names and aggregate evidence are reported; the temporary NetLog is deleted.

If an update CRX download occurs, its transport must use the exact permitted `https://clients2.googleusercontent.com/crx/blobs/` origin/path, without credentials or redirects. If no download occurs, anonymous download transport is explicitly **not exercised**. An unchanged installed version or successful manifest response does not establish automatic scheduling, update installation, or publisher-proof validation of an update CRX. Those output claims remain false in the generic transport harness; the separate run 21 audit below establishes observed native upgrade behavior without inflating those flags.

On 2026-10-18, a bounded search for an older official fixture queried four browser versions for each of Refined GitHub, Vimium, Stylus and Dark Reader through Google's anonymous update endpoint. Each extension returned one current version or `noupdate`; none provided two versions. No CRX was downloaded or signature validation claimed in that search. The 16 XML responses and hashes are retained locally in `.cache/qa/cws-version-probes-20261018`. Earlier uBO Lite version probes also returned one current version or no update. A repacked manifest or unsigned historical ZIP is not a substitute for a genuine older Store package.

## Completed runtime evidence

Run 20 (`.cache/qa/source-155.0.8059.84-runtime/20-final-native-updates.json`) passed both native toolbar completions, exact helper state/location/path retention and separate anonymous HTTP 200/XML request windows. The owned browser exited normally, the complete NetLog was archived with SHA256 `c4d0266f2d7dd2d882dd2ab435c215431ffdf1f681111abd94b3db1cd09246b5`, and its runtime was removed. Both checks retained extension version `2026.1012.1545`; no CRX download occurred. This is a transport/state-retention pass, not an upgrade pass.

The earlier bounded fixture searches found only current versions or `noupdate`. A later original Google install redirect yielded a genuine older uBlock Origin Lite CRX; an anonymous official manifest replay subsequently offered a newer package. Both original artifacts are retained and verified without repacking or re-signing:

| Fixture | Version | SHA256 |
| --- | --- | --- |
| Old | `2026.1012.1545` | `de67c08f8f7a337bc82c2cc86423eea0243e02be3fd3bd9e289c20c82eadb24a` |
| New | `2026.1018.2229` | `559d10ef7dcb96bc4e812de6b3ff0c2e6c7abca578324d8d7afd7d8cf78a6dd7` |

The audits `build/source-155.0.8059.84/audit/old-crx-fixture` and `new-crx-fixture` bind both CRX3 signed IDs to `ddkjiahejlhfcafbddmgiahcphecmpfh` and the same developer SPKI, and verify all signatures including Chromium's pinned production Store publisher proof. Both manifests are MV3 and declare the canonical update URL. This offline evidence provides real test inputs; browser installation/update behavior is established separately by run 21.

The replay XML uses `http://www.google.com/update2/response`, while domain substitution changed the prior parser's expected namespace to a reserved `qjz9zk` identifier. That parser rejects the saved replay before examining its offered update. The earlier native body was not captured, so its exact parse failure remains inferred. The reviewed amendment restores only the XML protocol namespace constant and comment; it performs no request to that URI and changes no Store endpoint, credential/redirect policy, publisher verification or helper behavior. Ten-file replay and actual root-guard/helper regressions passed; normal C++/framework build, signing and fourth-package validation subsequently completed in `audit/store-manifest-namespace-001/actual-normal-package-completion.json`. The fourth package subsequently passed the genuine manual native upgrade in run 21.

Run 21 independently passed `PASS_NATIVE_UPGRADE_OBSERVED_WITH_TRANSPORT_AND_FIXTURE_CORRELATION`. Its actual native-consented old packed installation was captured before the first Update; the same profile then exposed packed version `2026.1018.2229`, the same public-key-derived ID/SPKI and persisted active new-package path. The matching old-version manifest source `1:711` completed before the exact authenticated-fixture CDN request `1:730`; that request completed with HTTP 200, no credentials/redirects/errors and 9,145,194 filtered body-read bytes within the first native window. The second check advertised the new version. Both helper states retained location `8`, exact path and disable reasons. Normal native/harness exit and owned app/profile removal were verified.

The saved proof is under `build/source-155.0.8059.84/audit/store-manifest-namespace-001/final-upgrade-audit`: `run21-pre-installed-state.json`, `run21-post-installed-state.json`, `run21-upgrade-analysis.json` and the independent `run21-independent-release-review.json`. The finalized NetLog SHA256 is `5c65d6e2d285fb9a2f910a7ca7b73972458b1a7da79959b69485998dd20e2b66`; its archive metadata and complete harness JSONL are retained under `.cache/qa/source-155.0.8059.84-runtime/21-*`. Fourth-package provenance is embedded receipt `1f2af548aa9a52f3325471b2627ab950784874ba0815db06884b08980d22afb3`, fingerprint `6a5dd6ca1a044b5de1d52b033188548c9a477bca196f25dca53642ce2ef875cc`, with strict signature verification in run 22.

Default NetLog body counts are size correlation, not an independent hash of the native downloaded bytes. The audit does not trace native publisher-verifier execution or independently capture/parse the native XML body. Retained old/new artifacts have separate valid developer and production Store proofs. An optional fixed-scope comparison matched all 374 installed script/style/HTML/text/WASM members to the authenticated new archive and matched original manifest fields semantically; JSON/images, native metadata and generated extras were outside byte comparison. This does not establish whole-tree or wire-body identity. Manual Update success also does not establish automatic scheduling, hostile-package rejection, real accounts or exhaustive security parity.

To repeat an actual upgrade check, install the retained original old signed CRX through normal native consent in the generated disposable app, verify its old packed version/key, then use the real Update button and capture the new packed state before cleanup. Installing the current Store listing alone may yield the latest version and cannot demonstrate an old-to-new transition. Never repack, re-sign, edit the manifest or load unpacked to manufacture the transition.

## Theme and native Store links

```sh
node scripts/smoke-extension.mjs --fixture theme --prepare-only
node scripts/smoke-extension.mjs --fixture theme
node scripts/smoke-native-store-link.mjs
```

Theme mode uses Google's official Just Black fixture, Store ID `aghfnjkcakhmadgdomlmlhhaocbkloab`, through the same unique signed QA app and forced disposable profile. CUA must target the printed generated app path. After observing native **Add theme** consent, run `status`, `check installed`, and `finish`. The checks require an actual packed theme, matching public key/Store ID, no extension permissions or executable content, and the installed theme's real native Appearance state/name. The visible `#openTheme` control is a `cr-link-row`, not an anchor: its actual user-click navigation must request `https://chromewebstore.google.com/detail/<ID>`. A temporary route aborts that test navigation before fetching the page. Installation still deliberately uses the user-selected Store listing and Chromium's native consent flow. No installed metadata is synthesized. Theme mode rejects `--update-check`; the default uBO Lite flow is unchanged.

The separate source-only headless check inspects native Extensions sidebar `#discover-more-text a`, requiring the rendered `https://chromewebstore.google.com/category/extensions` href and `_blank` target. Its real user click must request that same destination, also intercepted and aborted before fetching a Store page. It uses a fresh profile and closes its owned browser. Both functional checks refuse the upstream preview. The first source package passed the native sidebar link check; the second passed official Just Black installation and its Appearance detail click after explicit user consent (`16-source-theme.json`). Default-theme Customize Chrome GUI validation remains separate. Both fixture prepare-only modes passed on the preview with the original team/policies/entitlements and 15 unchanged nested signatures; that establishes signing/setup integrity without launching Chromium or validating the restored native links.

## Store-page script restrictions

The source overlay restores the real modern and legacy Store domain restrictions for ordinary extensions. The only new exception is Kumo's fixed command-line helper identity on the exact canonical HTTPS modern Store origin at port 443, without URL credentials. That exception skips only the Store denial; normal host, user and enterprise-policy checks still apply. Existing privileged component behavior is preserved. Global Store service classifiers remain disabled.

```sh
python3 -m unittest discover -s scripts -p 'test_store_script_guard.py' -v
node scripts/smoke-store-script-guard.mjs
```

The compiled offline fixtures exercise the actual access-function bodies with parsed-component and permission shims; they do not test Chromium's URL parser or renderer. The runtime guard passed on the locally built Chromium 155.0.8059.84 app on 2026-10-18, using a fresh sandboxed profile and mock keychain. The ordinary random-identity MV3 probe had mandatory matching host permissions: both declared and background programmatic injection worked on the unrelated HTTPS control and were denied on the modern Store, legacy Store and arbitrary legacy path, modern subdomain, HTTP, URL credentials and nondefault HTTPS port. None of those cases was skipped. Only the canonical HTTPS helper appeared. Both extensions' saved locations were command-line (`8`), and their saved paths matched the actual loaded helper/probe paths. Chromium intentionally does not cache command-line manifests in preferences; live manifest identity and permissions are checked in the extension worker.

The helper's category → detail A → detail B → category sequence passed with button counts `0, 1, 1, 0`. Each trusted DOM click exercised the actual production background validation and document-bound acknowledgement. Before any fixture click, the harness replaces only this owned helper worker's `chrome.tabs.create` with an identity-verified recording function that always rejects before dispatch. It checks the exact current extension ID, engine version and fixed CRX3 query at that boundary, then requires the expected rejection to return through the real helper. The original API is never called or used as a fallback. This boundary avoids depending on page routing to intercept Chromium's native CRX handling. All nine website fixture responses were locally fulfilled inert HTML; no CRX navigation was dispatched. This guard verifies the requested background URL, not native navigation, download, installation, server TLS or unrelated browser background networking. Native installation and update transport remain separate checks.

The passing guard output and cleanup proof are retained in `.cache/qa/source-155.0.8059.84-runtime/10-store-script-guard-predispatch-final.log` and `10-store-script-guard-cleanup.json`. The owned browser closed and every owned temporary directory was removed. Earlier context-route harness failures remain preserved in the audit directory and runtime logs; they are not counted as transport or installation evidence.
