#ifndef KUMO_NATIVE_CHROMIUM_KUMO_PAIRING_GEOMETRY_H_
#define KUMO_NATIVE_CHROMIUM_KUMO_PAIRING_GEOMETRY_H_

#include <cstddef>
#include <optional>
#include <vector>

namespace kumo {

// All rectangles use the same desktop coordinates, in points. No screen or
// application state is read by this geometry-only component.
struct PairingRect {
  double x;
  double y;
  double width;
  double height;
};

struct PairingGeometry {
  std::vector<PairingRect> visible_screens;
  std::vector<PairingRect> helper_windows;
};

struct PairingWindowBounds {
  int owner_pid;
  PairingRect quartz_bounds;
};

// CGWindowList uses top-left desktop coordinates. Convert only windows owned by
// the supplied PID; every layer counts. Screen rectangles are already AppKit
// visible frames. No window titles or content are needed.
PairingGeometry PairingGeometryFromBounds(
    const std::vector<PairingRect>& visible_screens,
    const std::vector<PairingWindowBounds>& windows,
    int helper_pid,
    double primary_screen_top);

bool IsPairingFrameSafe(const PairingRect& frame,
                        const PairingGeometry& geometry,
                        double gap = 12);

enum class PairingPlacementStatus { kPlaced, kUnavailable, kInvalid, kNoRoom };

struct PairingPlacement {
  PairingPlacementStatus status;
  std::optional<PairingRect> frame;
};

// A frame is fully inside one visible screen, separated from every helper
// window by gap points. Preserve current when safe; otherwise find a compact
// placement. Missing bounds fail closed. No placement is promised if screens
// cannot accommodate the minimum frame without overlapping Apple's windows.
PairingPlacement PlacePairingPanel(
    const PairingGeometry& geometry,
    std::optional<PairingRect> current = std::nullopt,
    double preferred_width = 360,
    double preferred_height = 210,
    double minimum_width = 300,
    double minimum_height = 194,
    double gap = 12);

bool IsSixDigitPairingCode(const char16_t* characters, size_t length);

}  // namespace kumo

#endif  // KUMO_NATIVE_CHROMIUM_KUMO_PAIRING_GEOMETRY_H_
