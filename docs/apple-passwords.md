# Password extensions and Apple capability boundaries

## Current source and release status

[Kumo **0.1.2, build 202610210003**](https://github.com/morrigangirl/kumo/releases/tag/v0.1.2-202610210003) was published on October 21, 2026. It removes the built-in Apple Passwords integration: the native fill command and sheet, settings/help panel, unwired session-pairing components, and standalone SDK probes. Its fresh completed source build, signed runtime checks, Developer ID signing, Apple notarization and public update verification passed. See [production release validation](security-audits/2026-10-21/0.1.2-production-release.md). The unpublished 202610210002 candidate remains superseded.

Chromium's ordinary extension APIs and Native Messaging remain available for password tools. No custom extension or installed browser profile is changed by this removal. Password extensions retain their own native-helper, account-selection and authentication requirements. Installing one does not establish that Apple's helper accepts Kumo, and the owner's custom plugin has not been qualified against the replacement build.

Chromium WebAuthn, passkeys and security-key support remain separate from the removed password-fill integration. The release-signing tools retain optional support for an Apple-approved managed browser-passkey entitlement and provisioning profile. Carson Press LLC's Developer ID certificate alone does not grant that capability; no approved Kumo profile or successful live Apple passkey request is claimed. See [optional passkey signing](signing.md#optional-approved-browser-passkey-capability).

## Historical implementation and validation

The following records describe removed experiments and earlier builds, rather than features or instructions for Kumo 0.1.2.

The former AppKit sheet displayed a canonical HTTPS destination and a real semantic username or secure-password field. The person could invoke macOS AutoFill → Passwords, choose an account and explicitly press Fill. Its browser adapter bound the result to the original renderer field, document and origin and cancelled on navigation, tab hiding or closure. It did not provide Safari-style inline website account suggestions.

Earlier compile-only SDK checks and **93 synthetic panel assertions** passed on macOS 27.0.1 with the macOS 27.0 SDK and Swift 6.4, following earlier SDK 26.5 checks. The native field menus exposed enabled system AutoFill actions. The probes did not select or retrieve personal credentials.

The signed Chromium 155 source browser passed four synthetic scenarios: exact Unicode filling of the original field despite decoy focus, Cancel, navigation and real tab hiding. Cancellation left the website fields empty. An earlier typing mismatch and tab-visibility harness failure were corrected before the accepted rerun; they were not counted as passes. Historical evidence remains in `.cache/qa/source-155.0.8059.84-runtime/15-native-passwords-final.{log,json}`. These tests did not establish real Apple credential selection or automatic domain matching. Historical release/audit documents retain their original package identities and scope.

A standalone session-pairing entry-window experiment passed **47 geometry and 75 AppKit checks** on October 21, 2026. It avoided synthetic helper-window bounds, cleared entry when safe placement was unavailable, and required six ASCII digits plus explicit confirmation. It was never connected to a working Apple helper session or compiled into the released browser. Live pairing-window placement remained unverified. That component and its test commands are now removed.

## Historical Apple-helper admission result

The installed Apple helper's launch constraints did not list Kumo's `app.kumo.browser` identity with Carson Press LLC team `PV65ZWXCWX`; Kumo also lacked the managed entitlement accepted by an alternative constraint. Browser-list inclusion was requested in [Apple issue #1849](https://github.com/apple/password-manager-resources/issues/1849). Filing the issue does not enable an existing installed helper.

A capability-only probe from the unchanged Developer ID-signed production browser received no response before the helper exited. Apple's diagnostic reported `SIGKILL (Code Signature Invalid)` without identifying the specific failed constraint. This is consistent with the static restrictions but does not prove which constraint failed. No pairing challenge or credential query was sent. The owned profile/extension were removed; the result is recorded in `.cache/qa/pairing-helper-admission-2026-10-21-003/result.json`.

This historical result remains a compatibility boundary for Apple-dependent extensions. Removing Kumo's built-in implementation neither fixes the helper's admission rules nor demonstrates that the custom plugin works.

## Historical public-SDK findings

These findings are scoped to the inspected SDKs and experiments, which have been removed from the product source. They are not a promise about every later Apple SDK.

| API area | Observed boundary |
| --- | --- |
| AppKit semantic username/password fields | Exposed system-mediated AutoFill UI; no verified arbitrary-site account-list API. |
| Associated website passwords | Shared-web-credential requests require the app's associated domains, website cooperation and consent. |
| Security/Keychain and LocalAuthentication | Authentication can authorize permitted operations; it does not add access-group membership or replace the browser helper's paired protocol. Legacy file-keychain unlocking is not access to the complete Apple Passwords vault. |
| Browser public-key credential APIs | Browser passkey consent/metadata are distinct from saved website password retrieval and require the applicable managed entitlement. |
| Credential-provider identity store | Entries belong to the credential-provider extension, rather than an Apple Passwords-wide account index. |
| Credential data management | The inspected macOS 27 Swift interface marked password saving unavailable on macOS; reporting APIs did not retrieve saved passwords. |
| BrowserEngineKit/WebKit/Safari APIs | UIKit text-input APIs and WebKit/Safari-specific surfaces did not establish an arbitrary Chromium/AppKit password-vault interface. |

No experiment exported a password database, impersonated a supported browser, modified Apple helpers or suppressed authentication. The completed tests and blocked helper probe must not be described as successful seamless password integration.

## Primary references used in the historical audit

- [Apple: App access to saved passwords](https://support.apple.com/guide/security/app-access-to-saved-passwords-sec8762eb992/web).
- [Apple: AutoFill Everywhere, WWDC20](https://developer.apple.com/videos/play/wwdc2020/10115/).
- [Apple: On Mac keychain APIs and implementations, TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).
- [Apple: Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps).
- [Apple: Authenticating people by using passkeys in browser apps](https://developer.apple.com/documentation/authenticationservices/authenticating-people-by-using-passkeys-in-browser-apps).
- [Apple: Browser public-key credential entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.web-browser.public-key-credential).
