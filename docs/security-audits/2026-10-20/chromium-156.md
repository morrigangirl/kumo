# Chromium 156 release preparation

Status: the compatibility port completed its original full source build and candidate runtime qualification on October 21. Replacement build `202610210001` completed its reviewed incremental build, raw receipt verification and all 19 new candidate runtime groups. Production signing, notarization and published assets are separate release records.

The final prepublication check found Chrome's [October 20 desktop stable update](https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_02018666648.html), published after the earlier check. It announces 156.0.8078.47/.48 and 353 security fixes across platforms. That total is not a count of independently confirmed Kumo/macOS vulnerabilities. Google's [CNA record for CVE-2026-113279](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/113xxx/CVE-2026-113279.json) describes critical Accessibility memory corruption before 156.0.8078.47, potentially allowing execution inside the sandbox. It does not describe a sandbox escape or restrict the issue to another platform.

Kumo held the signed, unsubmitted 155-based 0.1.1 candidate and began a separate 156 source workspace. The notarization profile was available during that earlier preparation. The latest default-Keychain lookup for `Kumo Notary` now exits 69 because the profile is missing; restoration is required before submitting the replacement build. Existing 0.1.0 release assets and the earlier candidate remain preserved.

## Pinned inputs

- Chromium 156.0.8078.47, commit `1d17a2e2ee147bb7d6ae2ab6abdb3a2510c17775`; official archive SHA256 `28432028890ef70e1f2e9db880c500907ad1b04f5ae6b655a3f394b9f2eaa705`. The `.48` revision changes only `chrome/VERSION`.
- Common ungoogled-chromium [PR #4003](https://github.com/ungoogled-software/ungoogled-chromium/pull/4003), exact head `0673f8701c94e5688c33ef8ce5e36602d311d246`. It is unmerged, with no approved maintainer review at audit time. Its upstream code, configuration and source-validation checks passed.
- macOS recipe tag `155.0.8059.84-1.1`, commit `28552f14731fe8f60422e19bbc2361468d420b25`. Using that platform recipe with 156 is a local compatibility port. The lock records this explicitly; it does not imply an upstream macOS 156 release.
- The common revision includes canvas-noise bounds correction `e917fa4ff7606ee1b9d05768118081248b3861ee`.

## Static patch review

Independent review matched all 70 PR file blob hashes to the pinned checkout; 42 changed files contain only patch hunk-offset refreshes. No concrete new runtime security weakening was found. TLS/DoH and Linux sandbox hunks refresh context, the EV patch follows a metadata-file rename, and the WebAssembly update retains bounds checking. The canvas change constrains noise writes to destination pixmap bounds. Common GN flags and domain regexes are unchanged from the previous pinned common core.

Safe Browsing remains disabled by the existing ungoogled configuration. Removal of advertising-attestation inputs concerns Google's Privacy Sandbox feature, not the Chromium process sandbox. PR build notes describe an optional fallback for older GN that would reduce build-time dependency/header checks; that fallback has not been applied to Kumo. This static review does not establish successful compilation, runtime security or full Chrome parity.

## macOS recipe assessment

The first full-source probe verified the official archive and applied all 109 selected common patches. It stopped at the first macOS patch because bindgen revision storage changed upstream; that partial workspace is preserved. A small scratch audit then identified outdated Crubit and GN patches elsewhere in the old macOS series.

The selected route uses the matching official Chromium Clang/Rust/Crubit and native TypeScript packages and retains only eight platform/build-tool patches. Upstream parser implementations and their default feature states are preserved: WebBundle uses its Rust paths, while the generic CBOR reader/writer still have upstream-default-off Rust feature switches. It omits the old C++ CBOR/WebBundle fallback, V8 sanitizer-detection rewrite, compiler consistency bypass, external Rust/bindgen workarounds, PVT deletion, GN dependency-check suppression and Homebrew TypeScript substitution. The embedded 156 GN source supports `public_inputs` and `check_includes_strict`. Private Verification Tokens remain upstream-default-off; keeping their code also preserves token deletion and service guards.

A concrete new font safety change routes unknown avar major versions of at least 2 through Fontations. The legacy fallback patch had incompatible context around this code; retaining upstream Rust avoids reverting the new condition. This finding is distinct from the advisory's Fontconfig issue and is not assigned that CVE here.

All 15 Kumo overlay/enterprise preimages were checked against immutable copies from the actual full-common probe, transformed with the exact pinned domain function. All original macOS patch target sets are disjoint from those files. The new extension user-block and capture checks survive Kumo's insertion byte for byte. Upstream common patches already remove production Google profile creation; Kumo cancels only a remaining test-only caller. Synthetic adjacent-code tests are not evidence that Google profile creation is enabled.

## Preparation checks

The initial prepared source input digest was `4138ed592f06a185c3e944b1b45bd49453f6359ea122b46e85fa5e9e35820994`. Independent static review matched that recipe policy, official resource pins and source preimages. Its nine retained patches applied with zero fuzz to owned copies of their real source targets; 13 selected security files remained byte-identical to the post-common baseline.

Actual platform preparation passed: every installed Clang, Rust/Crubit, objdump and Node file/link was compared with its verified archive, including exact directory contents, modes, revision stamps and native arm64 tools. The official formatter also matched its publisher hash. Eighteen recipe/resource regressions, four vendor tests and the final 13 source-orchestration tests passed. Separate copy-only source/extension/enterprise checks passed 38 tests without skips; 17 malware regressions and actual malware overlay validation passed. These checks are preparation evidence, not a completed browser build or runtime qualification.

The normal initial preparation then completed all 13 stages, and independent review matched the actual extension, native Passwords, download and enterprise outputs to the reviewed inputs. All three actual-source native context-menu tests passed. GN bootstrap and target generation passed (36,031 targets from 4,973 files). Ninja stopped before browser compilation because the official native TypeScript package was missing. An independent graph inventory found exactly 109 missing, unproduced inputs: the native compiler and 108 declaration files, all under `third_party/typescript/mac-arm64`; no other missing input group was found among 199,886 transitive inputs. The failed workspace and evidence are preserved; no completed receipt or 156 app was produced.

The dependency correction pins Chromium's exact native TypeScript 7.0.2 CIPD package: immutable instance `63sEajfB6_MIU0PehstKopK1_P_yfUm21-o-zedkrz0C`, ZIP SHA256 `eb7b046a37c1ebf3085343de86cb4aa292b5fcfff27d49b6d7ea3ecde764af3d`. It also removes the older Homebrew TypeScript patch, retaining Chromium's original compiler wrappers and `use_typescript_go=true` default. This changes the prepared-source fingerprint to `055d5b05d56eaf76f72f8a51f6823d1ceef5a7704b2153cbf0807a90969f7cc3` and requires a fresh normal preparation in `build/source-156.0.8078.47-final002`; the earlier workspace is not migrated or relabeled.

Correction validation passed 26 recipe/resource tests, four vendor tests, 13 source-orchestration tests, the source self-test and the local toolchain doctor. The strict installer checked every one of the 118 ZIP payload files and all 109 graph inputs; the actual arm64 compiler reported `Version 7.0.2`. Independent review verified the public CIPD resolution, immutable object/hash identity, payload and original source/default preimages. All eight retained patches passed on owned source copies, preserving 18 selected security and TypeScript preimages. The retained isolated-declarations patch adds type annotations erased at runtime; both its original and patched source passed the official compiler's declaration flags, so its necessity is not claimed.

## Completed source and runtime checks

Fresh preparation in `build/source-156.0.8078.47-final002` completed all 13 stages. Independent review of that actual tree verified the eight selected platform patches, official tools and native TypeScript package, Kumo's extension/native/download/enterprise overlays and preserved security preimages. All three actual-source context-menu tests passed. The normal four-worker build then completed all 57,485 Ninja actions, including native Passwords and both download-manager paths, framework linking, library verification, upstream signing and engine packaging.

The completed source receipt records `2026-10-21T05:57:08Z`, input digest `055d5b05d56eaf76f72f8a51f6823d1ceef5a7704b2153cbf0807a90969f7cc3` and path-free embedded receipt digest `005d5708f39502c4b541b42927ecec1e1d65d63f5634944708b20de9676f1e87`. Independent candidate review rehashed the raw artifacts and receipt and matched all 56 mapped engine/framework sections after packaging, allowing the expected signature changes.

The development-signed Kumo 0.1.1 / `202610200002` candidate passed its identity/model/attribution checks and all 19 isolated runtime checks. These cover browser settings/persistence, exact 155→156 synthetic profile migration, agent controls, actual Core ML inference and privacy fixtures, domain blocking, both antivirus download paths, extension/app-seal handling, Store scripting protection, TLS, bounded ordinary-startup privacy, native search/DNS and updater-lock behavior. The current compiler/linker additionally passed the focused 13-command mixed-language unwind fixture and fresh Mach-O metadata proof. These are bounded integration and compatibility checks, not an exhaustive security audit or model-accuracy qualification. See [candidate results and limits](../2026-10-21/0.1.1-candidate.md).

A fresh official release check on October 21 at 04:53–04:54 UTC found no newer macOS stable implementation release: `.48` is a direct child of `.47` changing only `chrome/VERSION`. The announcement's six Critical entries include an explicitly Android-only Skia issue; they must not be described as six confirmed macOS Critical vulnerabilities. All six Chrome CNA records still give the pre-`.47` affected boundary.

## Replacement download-guard build

The preserved Developer ID-signed `202610200002` stage later blocked benign CDP downloads after ctime-only changes during scanning. Its normal native cases passed, and no unsafe completion was observed. The metadata writer was not established. The held stage is not the replacement release.

An independent APFS clone in `build/source-156.0.8078.47-final003` reused the completed source and compiled outputs. Two reviewed one-file amendments retain strict original-file checks, allow at most one fresh full scan after otherwise identical metadata changes, and unconditionally bind both snapshots to the first SHA-256. The first amendment's build was interrupted before any completed receipt to close the original-byte binding gap; its state, guard and log are preserved.

The final normal four-worker build recompiled the guard, relinked the framework, verified libraries, ran upstream signing/DMG packaging and final pinned-tool/source checks. Its actual receipt records `2026-10-21T07:18:57Z`, source inputs `e6725469a395d3ad7d4c4638d02b377397c65bf2f396fb4f2f72ffff9313db99` and embedded digest `0de4bed0904ae4f529097ba3e92c141dea25f301a3e6f9448d6765f9ea129a44`. This was an incremental build, not another full 57,485-action compilation. Independent review matched the raw artifact hashes and all 56 packaged engine/framework section descriptors and file-backed bytes. The original `final002` state, receipt, guard and whole Mach-O bytes remain unchanged.

The extracted retry policy passed 13 functional scenarios plus its strict-comparator check; all 47 existing native/source/receipt checks also passed. All 19 new candidate runtime groups completed at `2026-10-21T07:27:29Z` with zero exit codes, including the full six-case matrix on both native and CDP download paths. Signed-stage fault injection and production qualification remain pending. The prior 19-group candidate result is preserved as historical evidence.

## Production boundary

Candidate validation does not attest a production signature or notarization. Production distribution requires final Developer ID signing, exact-archive Apple acceptance, stapling, Gatekeeper verification and signed GitHub release assets. The final app must retain the PhishLang citation, license link and modification notices before its model is uploaded or distributed. Release assets record the final production identity separately.

Local evidence is preserved under `.cache/qa/chromium-156-security-2026-10-20/`, `.cache/qa/chromium-156-security-2026-10-21/`, `.cache/qa/chromium-156-release-2026-10-20/`, `.cache/qa/chromium-156-release-2026-10-21/` and `.cache/qa/phishlang-release-2026-10-20/`. These generated directories are excluded from Git.
