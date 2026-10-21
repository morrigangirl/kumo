# Chromium 156 release preparation

Status: compatibility port in progress; no 156 binary has been published.

The final prepublication check found Chrome's [October 20 desktop stable update](https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_02018666648.html), published after the earlier check. It announces 156.0.8078.47/.48 and 353 security fixes across platforms. That total is not a count of independently confirmed Kumo/macOS vulnerabilities. Google's [CNA record for CVE-2026-113279](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/113xxx/CVE-2026-113279.json) describes critical Accessibility memory corruption before 156.0.8078.47, potentially allowing execution inside the sandbox. It does not describe a sandbox escape or restrict the issue to another platform.

Kumo held the signed, unsubmitted 155-based 0.1.1 candidate and began a separate 156 source workspace. The working default-Keychain notarization profile is available; no credential-restoration step is outstanding. Existing 0.1.0 release assets and the earlier candidate remain preserved.

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

The selected route uses the matching official Chromium Clang/Rust/Crubit packages and retains only nine platform/build-tool patches. Upstream parser implementations and their default feature states are preserved: WebBundle uses its Rust paths, while the generic CBOR reader/writer still have upstream-default-off Rust feature switches. It omits the old C++ CBOR/WebBundle fallback, V8 sanitizer-detection rewrite, compiler consistency bypass, external Rust/bindgen workarounds, PVT deletion and GN dependency-check suppression. The embedded 156 GN source supports `public_inputs` and `check_includes_strict`. Private Verification Tokens remain upstream-default-off; keeping their code also preserves token deletion and service guards.

A concrete new font safety change routes unknown avar major versions of at least 2 through Fontations. The legacy fallback patch had incompatible context around this code; retaining upstream Rust avoids reverting the new condition. This finding is distinct from the advisory's Fontconfig issue and is not assigned that CVE here.

All 15 Kumo overlay/enterprise preimages were checked against immutable copies from the actual full-common probe, transformed with the exact pinned domain function. All original macOS patch target sets are disjoint from those files. The new extension user-block and capture checks survive Kumo's insertion byte for byte. Upstream common patches already remove production Google profile creation; Kumo cancels only a remaining test-only caller. Synthetic adjacent-code tests are not evidence that Google profile creation is enabled.

## Preparation checks

The frozen source input digest is `4138ed592f06a185c3e944b1b45bd49453f6359ea122b46e85fa5e9e35820994`. Independent static review matched the exact recipe policy, official resource pins and source preimages. All nine retained patches applied with zero fuzz to owned copies of their real source targets; 13 selected security files remained byte-identical to the post-common baseline.

Actual platform preparation passed: every installed Clang, Rust/Crubit, objdump and Node file/link was compared with its verified archive, including exact directory contents, modes, revision stamps and native arm64 tools. The official formatter also matched its publisher hash. Eighteen recipe/resource regressions, four vendor tests and the final 13 source-orchestration tests passed. Separate copy-only source/extension/enterprise checks passed 38 tests without skips; 17 malware regressions and actual malware overlay validation passed. These checks are preparation evidence, not a completed browser build or runtime qualification.

## Remaining release gates

Full common/macOS patch application, exact Kumo overlay preimages, normal source compilation, completed-build receipt validation, browser/security/upgrade runtime checks, final Developer ID signing, Apple notarization and stapling, and signed GitHub release packaging remain required. The final app must retain the PhishLang citation, license link and modification notices before its model is uploaded or distributed.

Local evidence is preserved under `.cache/qa/chromium-156-security-2026-10-20/` and `.cache/qa/phishlang-release-2026-10-20/`. These generated directories are excluded from Git.
