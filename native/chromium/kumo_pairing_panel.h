#ifndef KUMO_NATIVE_CHROMIUM_KUMO_PAIRING_PANEL_H_
#define KUMO_NATIVE_CHROMIUM_KUMO_PAIRING_PANEL_H_

#include "kumo_pairing_geometry.h"

#include <functional>
#include <string>
#include <sys/types.h>

#ifdef __OBJC__
@class NSWindow;
#else
class NSWindow;
#endif

namespace kumo {

enum class PairingPanelState {
  kVisible,
  kHelperUnavailable,
  kNoRoom,
  kInvalidGeometry,
  kInvalidRequest,
  kAlreadyOpen,
  kClosed,
};

using PairingCodeCallback = std::function<void(bool accepted, std::string code)>;
using PairingGeometryProvider = std::function<PairingGeometry()>;
using PairingPanelStateCallback = std::function<void(PairingPanelState)>;

// Standalone component; not connected to Chromium or an Apple-helper transport.
// Main thread only. Call only after an explicit request, with the verified helper
// PID. This never launches the helper, opens a challenge, or reads a vault. The
// default bounds provider reads only PID/bounds metadata from CGWindowList. A
// supplied provider replaces that lookup entirely (including for synthetic tests).
//
// The normal-level, movable panel is non-modal, and survives loss of key focus.
// If safe space/bounds disappear, it hides and clears entered text; it can return
// when placement becomes safe. It never moves Apple's windows. State callbacks
// report those transitions. Callers must offer cancellation while it is hidden.
// Cancel/parent close returns false and no code, exactly once. On acceptance all
// field/editor text and observers are cleared before callback. The receiver must
// promptly consume/discard the code; it must never log, persist, or copy it.
// Callbacks run on the main thread, including rejection of off-main Show calls.
PairingPanelState ShowKumoPairingPanel(
    NSWindow* parent,
    pid_t helper_pid,
    PairingCodeCallback callback,
    PairingGeometryProvider geometry_provider = {},
    PairingPanelStateCallback state_callback = {});

PairingPanelState RefreshKumoPairingPanel(NSWindow* parent);
void CancelKumoPairingPanel(NSWindow* parent);

}  // namespace kumo

#endif  // KUMO_NATIVE_CHROMIUM_KUMO_PAIRING_PANEL_H_
