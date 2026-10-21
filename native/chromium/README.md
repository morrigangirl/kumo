# Native macOS credential sheet

`kumo_password_panel.h/.mm` uses public AppKit only. It creates a visible native username or secure password field where the person can choose the system AutoFill → Passwords action, select the website or app entry and saved account in Apple's chooser, then explicitly click Fill. The field is the fill target; account selection stays in Apple's chooser. The sheet does not keep a username history or provide a separate saved-account list. It has no extension or extension pairing protocol. macOS retains control over credential selection and authentication.

```cpp
kumo::ShowKumoPasswordPanel(parent_window, canonical_origin, is_password,
    [](bool accepted, std::u16string value) {
      // Revalidate the original frame, document token, origin, and exact field.
      // Only accepted=true may fill that one field in the current document.
    });
```

The caller must run on the main thread, own a visible `NSWindow`, and invoke this from a browser-owned user action. Pass the browser's canonical ASCII HTTP(S) origin. Another attached sheet or an invalid origin causes cancellation. `CancelKumoPasswordPanel(parent_window)` cancels only this credential sheet; call it on navigation, tab closure, and revocation. Parent window closure also cancels it. Completion is delivered once, after clearing the field and its editor. AppKit string buffers are released; secure memory zeroing is not promised.

Compile without Chromium dependencies:

```sh
xcrun clang++ -std=c++20 -fobjc-arc -Wall -Wextra -Werror -fsyntax-only native/chromium/kumo_password_panel.mm
```

This passed on 2026-10-18 using the installed public macOS SDK. The semantic controls were separately tested through `native/apple-passwords`' empty-field probe: enabled system AutoFill → Passwords actions were visible in both username and secure password context menus on macOS 27.0.1. No personal credential was selected, unlocked, read, or filled. The native sheet itself has not been exercised against a Chromium page. Its source must be linked into the Chromium build and connected to an exact-field adapter with origin/document revalidation. Automatic domain matching is not established by the manual system-picker result. See [the SDK audit](../../docs/apple-passwords.md).
