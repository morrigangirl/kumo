# RELAY and Mission Memory

RELAY uses the native Chromium vertical tab strip, a native Views entry in the tab rail, and a browser-owned side panel. Mission Memory and the start page are compiled WebUI resources. No Kumo extension is installed or required.

## Appearance

Kumo Settings offers an accent picker and violet, ice blue, teal, rose and amber presets. Saving appearance applies the accent to the browser palette and native rail. Illumination can be off, a static glow, or a slow five-second pulse; intensity is adjustable. In RELAY, the narrow perimeter and rail accent pulse. Native tab layout transitions take 160 ms and use Chromium's existing tab accessibility, dragging and keyboard behavior. The motion preference and the system Reduce Motion setting suppress animation.

The **Activate RELAY frame** action enables the vertical rail and dark browser palette. Existing explicit vertical-tab preferences are preserved until this action is used. The default for new profiles is vertical tabs. Other installed themes remain selectable through Chromium's Appearance settings.

## Local memory

Open **RELAY / Mission Memory** in the tab rail, or `chrome://kumo-missions/`. Create a named mission, enter notes and a next step, and save. **Checkpoint open tabs** lets the person select up to 50 ordinary web tabs; **Leave this here** replaces that mission's saved source list. Editing notes alone retains its saved sources. Up to 100 missions are stored in the regular browser profile as a local, nonsyncing preference.

Capture is explicit. Private and guest profiles are excluded. Checkpoints contain browser-owned titles and HTTP(S) addresses with query strings and fragments removed. They do not capture DOM text, cookies, passwords, fields, or authentication state. Source links can require signing in again and URLs that rely on a query string may need to be revisited manually. Notes are user-entered text; do not paste secrets into missions that will be shared.

**Resume saved tabs** opens their addresses in the saved order as background tabs. It does not close existing tabs, restore forms, grant agent tab access, or run an agent. Window geometry, scroll positions, and tab groups are not yet checkpointed. These are explicit source-and-notes checkpoints, not automatic session recordings.

## Opt-in MCP

Mission sharing is independent of the existing live-tab grants. In Mission Memory, expand **Share with an AI client**, select missions, then choose **Share selected missions**. Read access lasts for the current browser session and ends on revocation or bridge disconnect. It is off on startup. No setting import, MCP command or ordinary web page can enable sharing.

After upgrading an already configured installation, use **Settings → Kumo → Connect Codex Desktop** or **Connect Claude Desktop** once to refresh the managed MCP runtime, then restart that client to reload its tool list. This uses the existing native setup buttons and does not require copied commands.

All clients configured for that profile use the same authenticated local bridge permission. The UI states this explicitly; it does not claim to identify individual clients. A cloud-connected client can transmit retrieved content to its provider. Revocation prevents future reads, not copies already received.

Available MCP tools:

- `missions_list`: names, IDs, timestamps and source counts of shared missions.
- `missions_search`: search shared names, notes and next steps; returns matching metadata.
- `missions_read`: one shared saved mission with notes, next step, sources and timestamp.

There are no write or delete tools. Both the browser and local broker validate requests and permissions. Pending reads are rechecked; partially revoked list/search results are filtered again. Native memory is never a live-tab control grant. Recent successful reads are visible in the session activity list, which does not store note contents. Titles, URLs and notes are marked as untrusted data for clients.

## Validation

The regression suites exercise private-by-default behavior, separation from tab control, invalid parameters, unshared search results, token-bearing URL rejection, atomic saves, Unicode notes, deletion, and revocation while a read is pending. The native overlay pins every upstream hook to a whole-file SHA256, including the rail, side-panel action, animation and default layout changes.

### Development candidate verified 2026-10-27

Kumo **0.3.0 / 202610270001**, macOS ARM64, Chromium **156.0.8078.47**. The candidate is `dist/relay-0.3.0/Kumo.app`. It has an Apple Development signature (team PV65ZWXCWX); it is not notarized, published, or installed over `/Applications/Kumo.app`.

- 38 JavaScript tests, 38 native tests, and 49 Python checks passed. The 21 overlay checks were rerun after the final native changes. The smoke-harness self-test and `git diff --check` passed.
- The final headed browser run passed all 12 grouped checks, including repeated RELAY activation, writing the existing vertical-tab default explicitly, activation from horizontal tabs, actual appearance controls, mission checkpoint/resume, private-by-default MCP reads, revocation, and mission persistence after shutdown.
- Native UI review confirmed the dark accent palette, expanded and compact rail, side-panel editing and Settings navigation, new-tab/close controls with motion enabled, and the browser menu. Animation duration and Reduce Motion are covered by the source implementation; no frame-rate or video-timing measurement was made.
- No browser JavaScript errors were recorded. The signature was unchanged by the test. The owned browser and agent helper exited, the agent socket disappeared, and the disposable profile was removed.

Local evidence: `.cache/qa/relay-20261027/runtime-04/results.json`, `native-frame-review.json` and `relay-native-frame.png` in that directory; `build-final-4.log` and `package-final.log` in its parent. Earlier diagnostic runs are retained and are not qualification evidence.

Source input digest: `4e215392e88ccb9be834d21af826f2f17241bd4701e5778e263d6039d54116a1`. Final app CDHash: `963a97c1c8973f4dd52f41d7ccfec6daecfff531`. The normal source build produced the verified receipt; eight recorded, preimage-checked overlay amendments are retained under the local QA directory.

### Native window treatment (0.3.1)

RELAY now paints the macOS frame, toolbar and vertical rail as native Views surfaces. The address field uses a compact six-pixel corner radius and an accent outline while retaining the original text field, security indicators, autocomplete and focus handling. The frame adds terminal-style corner brackets and illumination along all four window edges. Native traffic lights, drag regions and resize behavior remain in Chromium's frame implementation.

The four narrow edge textures sit in a non-interactive compositor layer. Slow pulse changes layer opacity on a five-second cycle, without repainting page content. The profile's saved accent, illumination, intensity and motion preferences are observed live. Motion is suppressed for inactive/hidden windows and when macOS Reduce Motion disables rich animation; fullscreen hides the decorative perimeter. Private and guest windows do not receive the RELAY perimeter or Mission Memory rail button.

The new native implementation lives in `native/browser/relay/kumo_relay_frame.{h,cc}`. Chromium changes remain pinned, whole-file-checked hooks in `scripts/browser_integration_overlay.py`.

### 0.3.1 qualification and local installation, 2026-10-27

Kumo **0.3.1 / 202610270002** was built, packaged and installed at `/Applications/Kumo.app`, replacing 0.3.0. It is Apple Development signed (team PV65ZWXCWX), not notarized or published. Source input digest: `56f4e1e042bea32d794c8acc8d0b1c4533066f7d0b061d06b97b8c2913bf76cd`. Candidate and installed CDHash: `74e1c8d6b71e4a284093493ec7e4a33a7d1207e3`.

- 38 native tests, 36 overlay/package guard checks, the smoke harness self-test, and all 12 headed runtime check groups passed. Activation now restores RELAY from Paper as well as enabling the vertical rail and palette.
- Native UI review exercised the app menu, Settings, tab opening/closing, rail expansion/collapse, Mission Memory side panel, fullscreen entry and exit through the View menu, and native window zoom. Four-edge screenshot comparisons measured visible pulse changes; disabling motion produced identical edge pixels.
- The final smoke run reported no browser JavaScript errors, unchanged signatures, stopped browser/helper processes and removal of the disposable profile. The first manual gate timed out during review; its screenshots remain evidence, while `frame-runtime-02/results.json` is the completed qualification run.
- The installed app launched successfully with the existing Aoibh profile. Its saved Paper theme was changed to RELAY through **Activate RELAY frame**, retaining violet `#a78bfa`, slow pulse, intensity 100 and motion enabled. A second four-edge comparison verified the installed pulse. Other profile data and security settings were preserved.

Build and test evidence is under `.cache/qa/relay-20261027/`; installation, signature and installed screenshot evidence is under `.cache/install-0.3.1/`. The previous application is retained at `~/Library/Application Support/KumoInstallBackups/20261027-113934/Kumo-0.3.0.app` for rollback.
