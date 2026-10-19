#ifndef KUMO_NATIVE_CHROMIUM_KUMO_PASSWORD_PANEL_H_
#define KUMO_NATIVE_CHROMIUM_KUMO_PASSWORD_PANEL_H_

#include <functional>
#include <string>

#ifdef __OBJC__
@class NSWindow;
#else
class NSWindow;
#endif

namespace kumo {

using PasswordPanelCallback = std::function<void(bool accepted, std::u16string value)>;

// Main thread only. Call after an explicit browser-owned user action. trusted_origin
// must be the canonical, ASCII-serialized HTTP(S) origin from the browser process,
// never a renderer-provided label. The sheet does not inspect a webpage or vault.
// Its native semantic field offers macOS's user-mediated AutoFill where available.
// Callback runs exactly once on dismissal. Cancel returns false and an empty value.
// A successful selection is returned only when the person clicks Fill.
//
// The caller must revalidate frame identity, document token, origin, and field
// renderer ID before consuming the value. Cancel the sheet on navigation, tab
// closure, or revocation. Never send its value to agents, logs, clipboard, or disk.
void ShowKumoPasswordPanel(NSWindow* parent,
                           const std::string& trusted_origin,
                           bool is_password,
                           PasswordPanelCallback callback);

// Main thread only. Cancels only a Kumo credential sheet attached to this window.
// Other applications' or browser features' sheets are not affected.
void CancelKumoPasswordPanel(NSWindow* parent);

}  // namespace kumo

#endif  // KUMO_NATIVE_CHROMIUM_KUMO_PASSWORD_PANEL_H_
