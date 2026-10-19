# Chrome promotion suppression specification

Status: Proposed feature. No implementation is included in this specification.

## Purpose

Let people use Google websites in Kumo without repeatedly dismissing prompts to install, switch to, or open Google Chrome. Once enabled, suppression happens automatically on supported sites, across navigation and browser restarts.

The motivating experience is repeated Chrome recommendations in Safari. Kumo uses Chromium, but suppression must depend on the prompt actually present rather than assuming Google treats Kumo as Chrome.

## Setting and user experience

Add one global toggle to **Kumo Settings → Privacy & Security**.

| Element | Specification |
| --- | --- |
| Label | **Hide Chrome promotion prompts** |
| Description | Hide Google prompts asking you to install or switch to Chrome on supported sites. |
| Initial value | Off for new and existing profiles. Enabling requests the supported Google site permissions once, if needed. |
| Scope | This Kumo profile, across normal windows and tabs. Private browsing is outside the first release. |
| Persistence | Stored locally; included in preference export and import. No account or sync required. |

Turning it on starts suppression in already open supported pages and on future visits, without reloading tabs. Focus stays where it is unless it must leave a suppressed prompt. When permissions are denied or setup fails, leave it off and show an inline explanation with a retry action. Do not show another prompt on every Google visit.

Turning it off stops suppression in existing tabs, restores still-present UI hidden by Kumo when its script context is reachable, and prevents future injection. Do not automatically reload pages, recreate prompts the website has removed, or show a replacement banner announcing every blocked promotion. An interrupted extension context may require a manual reload, as described under Runtime lifecycle.

The toggle must be keyboard accessible, expose its checked state and description to assistive technology, and announce save or permission errors in the existing settings status area.

## Supported sites and prompts

The first release targets these exact HTTPS hosts. A site's adapter may act only on reviewed promotional surfaces within that site.

| Google service | Hosts |
| --- | --- |
| Search and Maps | `google.com`, `www.google.com`, `maps.google.com` |
| Gmail | `mail.google.com` |
| Drive | `drive.google.com` |
| Docs, Sheets, and Slides | `docs.google.com` |
| Calendar | `calendar.google.com` |
| Photos | `photos.google.com` |
| Meet | `meet.google.com` |
| YouTube | `youtube.com`, `www.youtube.com` |

Eligible surfaces are Google-owned banners, floating cards, popovers, and modal overlays whose purpose is to recommend Chrome. Examples of intended messages include “Use Chrome,” “Try Chrome,” and “Switch to Chrome”; these illustrate intent and are not selectors.

Support initial page load, delayed insertion, replacement of a dismissed promotion, and navigation within a web app. Repeated visits must not require another dismissal. A page without an eligible promotion must behave normally.

Country-specific Google domains require explicit additions and fixtures; the first release must not claim coverage for every Google domain. Do not use `*.google.com`, substring host matching, or permission to access all websites for this feature. Google Accounts, consent hosts, the Chrome Web Store, and intentionally visited Chrome download or help pages are outside its suppression scope.

## Matching and suppression requirements

Each bundled rule must identify an exact host and applicable route, a dedicated promotional container, and positive evidence that the container promotes Chrome. Prefer stable structural identifiers and known Chrome promotion destinations. Localized copy may support a match but must not be its only evidence. Parse link destinations as URLs; a word or URL occurring in user content is insufficient.

Never hide a whole dialog merely because its text contains “Chrome.” In particular, preserve:

- Google sign-in, account recovery, verification, passkey, and permission dialogs.
- Cookie consent, privacy choices, security notices, and genuine browser compatibility or unsupported-feature warnings, even if they recommend Chrome.
- Search results, email, documents, comments, videos, advertisements, and other ordinary content mentioning Chrome.
- Browser-native UI, downloads, extension installation prompts, and user-initiated Chrome links.

Rules must distinguish the service's own promotion UI from editable or user-authored content. Unknown variants remain visible. A rule that cannot make that distinction must not ship.

Hide only the dedicated promotion and its verified associated UI. Keep the original nodes and record the DOM properties Kumo changes so suppression can be reversed. Remove a backdrop, scroll lock, inert state, or focus trap only when the adapter can establish that it belongs to that promotion. Preserve unrelated dialogs and page changes made since suppression. A modal variant must remain visible until its adapter can demonstrate usable scrolling, pointer input, and keyboard navigation after suppression.

If focus is already within a suppressed prompt, return it to the preceding valid page control or an appropriate page landmark. Do not steal focus when it is elsewhere. Hidden promotions must leave the accessibility tree and tab order, and must not leave empty layout space or an invisible click barrier.

Do not click “No thanks,” accept or decline consent, submit forms, navigate, modify cookies or site storage, spoof browser identity, block Google resources, or disable site scripts. This is local presentation filtering; it is not a popup blocker or an ad blocker.

## Integration with Kumo

Use Kumo's bundled Manifest V3 extension for the first implementation. Native Chromium patches are unnecessary for the proposed approach, so it can serve both the upstream-binary preview and source build.

| File or area | Planned change |
| --- | --- |
| `extension/shared.js` | Add `hideChromePromotions: false` to `DEFAULTS` and preserve it in `validateSettings`. Only literal `true` enables it; absent or invalid values normalize to false. |
| `extension/newtab.html` | Add the toggle and description to `panel-privacy`. |
| `extension/newtab.js` | Render and save the value; request host permissions directly from the enabling gesture; show setup errors and reconcile imported preferences. |
| `extension/background.js` | Reconcile preference, permission, and content-script state; register or unregister only this feature's scripts; activate and deactivate existing documents. |
| New `extension/chrome-promotions.js` and bundled rule data | Apply reviewed rules, observe relevant DOM changes, and provide idempotent activation and reversible cleanup. |
| `tests/preferences.test.mjs` and new promotion tests | Cover preference compatibility, detection, lifecycle, and false positives. |
| New `scripts/smoke-chrome-promotions.mjs` | Verify behavior in a disposable real-browser profile using sanitized fixtures. |

Keep the existing optional host permissions model. Request only the exact HTTPS host patterns in the supported-site table. Explicitly exclude private tabs and incognito content-script contexts even if the extension is allowed there. Enabling this setting must not configure agent access, connect the native agent bridge, or grant an agent any tabs. New message handlers must validate the extension sender and trusted settings page; page content cannot change the setting or gain agent privileges.

Turning the feature off must retain existing host grants: permissions belong to the whole extension and may also support agents. Unregister this feature's scripts and clean up its DOM changes instead of calling `permissions.remove`. The current `background.js` revokes agent grants on any host-permission removal; preserve that separate behavior for explicit browser permission revocation.

## Runtime lifecycle

Use dynamically registered content scripts in the isolated extension world, with `runAt: "document_start"`, `persistAcrossSessions: true`, and top-frame matching for the first release. Dynamic registration and early injection are supported by the [content scripts API](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts). Embedded promotions are supported only when the top document contains an independently verified promotional wrapper; cross-origin frame inspection is deferred.

Register listeners synchronously in the service worker, consistent with the current MV3 architecture. Reconcile state on startup, extension update, local preference changes, and permission changes. Check the current setting and exact document origin before any DOM mutation, even when a persisted registration has injected the script. Prevent duplicate observers and serialize reconciliation so a late enable result cannot override a newer disable request.

For existing documents, inject the same idempotent bootstrap after permission succeeds. Use one initial inspection followed by batched `MutationObserver` work scoped to added or changed candidate containers. Avoid polling, rescanning the entire page on every mutation, and observer loops caused by Kumo's own changes. Handle restored pages and web-app navigation without accumulating listeners.

Disabling must also notify running scripts to disconnect observers and restore owned changes: unregistering a script does not undo an existing injection, as the [scripting API documentation](https://developer.chrome.com/docs/extensions/reference/api/scripting#examples) explains. Clean up on permission loss and document teardown while the context remains reachable.

Extension crashes, reloads, disablement, or uninstall can prevent a final cleanup handler from running. Stop further suppression on observable context invalidation and restore owned changes where execution remains possible. Every adapter must leave the page usable even if its existing mutations remain until navigation or a manual reload. Document manual reload as the recovery for incomplete restoration; do not promise rollback after an unreachable context is destroyed.

If any required site permission is revoked, stop the feature, restore affected documents where possible, set the preference to off, and show “Google site access is required to hide Chrome promotions.” Permission is requested again only after an explicit enable action; the [permissions API](https://developer.chrome.com/docs/extensions/reference/api/permissions#implement_optional_permissions) requires a user gesture for requests.

Older preference files default to off. Importing `true` may activate the feature only when all required permissions already exist; otherwise normalize it to off and explain that the person must enable it to grant site access. Import must not silently obtain permissions. Resetting preferences disables suppression.

## Rule maintenance and privacy

Keep detection rules and code bundled with Kumo. Each rule needs a stable ID, supported host and route, sanitized fixture, locale coverage, and date last checked. Add selectors only after reproducing the actual promotional variant; do not invent Google DOM identifiers. English is required initially; claim other locales only where structural matching and fixtures verify them.

All matching runs locally. Do not send page text, URLs, account information, screenshots, or suppression events to a service. Do not retain browsing history or prompt contents. Release updates carry rule changes; no remote script, rule feed, or machine-learning classifier is required.

If a Google redesign breaks a rule, leave the unknown UI visible. A false positive affecting normal content blocks release of that rule. Disable or narrow the affected rule while preserving tested coverage elsewhere.

## Acceptance criteria

| Scenario | Required result |
| --- | --- |
| Fresh or upgraded profile | Toggle is off; missing legacy preference values remain valid. |
| Enable with permission granted | One global setting takes effect in existing supported tabs and future documents without reload or agent access. |
| Permission denied or setup fails | Toggle returns to off, partial registration is rolled back, and a clear inline retry path appears. |
| Known prompt at load, inserted late, or reinserted | Prompt is suppressed automatically; page remains usable. |
| Web-app navigation, reload, and browser restart | Enabled behavior persists without duplicate observers or repeated consent requests. |
| Turn off in another tab | Existing scripts stop and restore Kumo-owned changes within one second in foreground test pages; later prompts remain visible. |
| Negative fixtures | Sign-in, consent, security, compatibility warnings, and user content remain visible and functional, including mixed dialogs mentioning Chrome. |
| Modal promotion | No orphan backdrop, scroll lock, inert page, keyboard trap, unexpected focus jump, or hidden focus target remains. |
| Unknown variant on a supported site | Leave it visible without changing its DOM. |
| Unsupported host or lookalike domain | Do not inject this feature or change its DOM. |
| Preference import, export, and reset | Value round-trips; missing permission never enables it; reset stops active scripts. |
| External permission revocation or rapid toggle changes | Final preference and registration agree; reachable scripts stop suppression and clean up. |
| Extension context interrupted during suppression | Existing changes leave the page usable; observable invalidation stops further work; manual reload restores the website's presentation. |
| Feature disabled while agents are enabled | Agent grants, connection state, and shared host permissions are unaffected. |

Use deterministic positive and negative fixtures for each rule, including Chrome mentions in email and documents, simultaneous legitimate and promotional dialogs, localized variants, and delayed or replaced nodes. Browser tests must exercise actual extension permissions, persisted registration, service-worker restart, cleanup, focus, and scrolling. Test-only fixture access must never broaden the production host list.

For performance, target under 10 ms at the 95th percentile for each detection batch on a documented reference Mac with a large fixture page, no feature-attributable main-thread task over 50 ms, and no recurring work on an unchanged page. Verify known structural fixtures do not visibly flash their promotion before suppression; measure and document any unavoidable flash for variants requiring runtime evidence rather than hiding the page while waiting.

## Delivery

First capture and sanitize real Google promotion variants, recording service, locale, signed-in state, and viewport without account data. Then implement preference and permission lifecycle, add independently tested site adapters, and run the acceptance matrix in both packaged build variants. A target host without a validated adapter must be removed from the shipped support and permission lists until it is covered.

Release notes must list the supported services and locales. Completion requires every shipped rule to pass its positive fixtures and all negative fixtures, plus live checks of captured variants where reproducible. Google experiments can change prompt delivery; absence of a prompt in a live visit is not proof that suppression worked.
