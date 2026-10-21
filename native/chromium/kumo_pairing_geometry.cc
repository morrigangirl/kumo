#include "kumo_pairing_geometry.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace kumo {
namespace {

bool Valid(const PairingRect& rect) {
  return std::isfinite(rect.x) && std::isfinite(rect.y) &&
         std::isfinite(rect.width) && std::isfinite(rect.height) &&
         rect.width > 0 && rect.height > 0 &&
         std::isfinite(rect.x + rect.width) &&
         std::isfinite(rect.y + rect.height);
}

bool Inside(const PairingRect& inner, const PairingRect& outer) {
  return inner.x >= outer.x && inner.y >= outer.y &&
         inner.x + inner.width <= outer.x + outer.width &&
         inner.y + inner.height <= outer.y + outer.height;
}

bool Separated(const PairingRect& a, const PairingRect& b, double gap) {
  return a.x + a.width + gap <= b.x || b.x + b.width + gap <= a.x ||
         a.y + a.height + gap <= b.y || b.y + b.height + gap <= a.y;
}

bool Safe(const PairingRect& frame, const PairingGeometry& geometry, double gap) {
  return std::any_of(geometry.visible_screens.begin(), geometry.visible_screens.end(),
                     [&](const auto& screen) { return Inside(frame, screen); }) &&
         std::all_of(geometry.helper_windows.begin(), geometry.helper_windows.end(),
                     [&](const auto& helper) { return Separated(frame, helper, gap); });
}

}  // namespace

PairingGeometry PairingGeometryFromBounds(
    const std::vector<PairingRect>& visible_screens,
    const std::vector<PairingWindowBounds>& windows,
    int helper_pid,
    double primary_screen_top) {
  PairingGeometry geometry{visible_screens, {}};
  for (const auto& window : windows) {
    if (window.owner_pid != helper_pid)
      continue;
    const auto& bounds = window.quartz_bounds;
    geometry.helper_windows.push_back({bounds.x,
        primary_screen_top - (bounds.y + bounds.height), bounds.width, bounds.height});
  }
  return geometry;
}

bool IsPairingFrameSafe(const PairingRect& frame,
                        const PairingGeometry& geometry,
                        double gap) {
  return Valid(frame) && std::isfinite(gap) && gap >= 0 &&
      !geometry.visible_screens.empty() && !geometry.helper_windows.empty() &&
      std::all_of(geometry.visible_screens.begin(), geometry.visible_screens.end(), Valid) &&
      std::all_of(geometry.helper_windows.begin(), geometry.helper_windows.end(), Valid) &&
      Safe(frame, geometry, gap);
}

PairingPlacement PlacePairingPanel(const PairingGeometry& geometry,
                                   std::optional<PairingRect> current,
                                   double preferred_width,
                                   double preferred_height,
                                   double minimum_width,
                                   double minimum_height,
                                   double gap) {
  if (!std::isfinite(gap) || gap < 0 ||
      !Valid({0, 0, preferred_width, preferred_height}) ||
      !Valid({0, 0, minimum_width, minimum_height}) ||
      minimum_width > preferred_width || minimum_height > preferred_height ||
      (current && !Valid(*current)) ||
      !std::all_of(geometry.visible_screens.begin(), geometry.visible_screens.end(), Valid) ||
      !std::all_of(geometry.helper_windows.begin(), geometry.helper_windows.end(), Valid)) {
    return {PairingPlacementStatus::kInvalid, std::nullopt};
  }
  if (geometry.visible_screens.empty() || geometry.helper_windows.empty())
    return {PairingPlacementStatus::kUnavailable, std::nullopt};
  if (current && current->width >= minimum_width && current->height >= minimum_height &&
      current->width <= preferred_width && current->height <= preferred_height &&
      Safe(*current, geometry, gap)) {
    return {PairingPlacementStatus::kPlaced, current};
  }

  const auto& anchor = geometry.helper_windows.front();
  const double target_x = anchor.x + anchor.width / 2;
  const double target_y = anchor.y + anchor.height / 2;
  double best_score = std::numeric_limits<double>::infinity();
  std::optional<PairingRect> best;
  for (const auto& screen : geometry.visible_screens) {
    // Try the full compact size, then the minimum. Boundary anchors make it
    // possible to find an empty minimum-size rectangle without a pixel scan.
    for (double width : {preferred_width, minimum_width}) {
      for (double height : {preferred_height, minimum_height}) {
        if (width > screen.width || height > screen.height)
          continue;
        std::vector<double> xs{screen.x, screen.x + screen.width - width};
        std::vector<double> ys{screen.y, screen.y + screen.height - height};
        for (const auto& helper : geometry.helper_windows) {
          xs.push_back(helper.x - gap - width);
          xs.push_back(helper.x + helper.width + gap);
          ys.push_back(helper.y - gap - height);
          ys.push_back(helper.y + helper.height + gap);
        }
        for (double x : xs) {
          for (double y : ys) {
            PairingRect frame{x, y, width, height};
            if (!Valid(frame) || !Safe(frame, geometry, gap))
              continue;
            // Prefer keeping the full size where it fits, then stay near the
            // helper. Coordinates are bounded by finite validated screens.
            const double distance = std::hypot(x + width / 2 - target_x,
                                               y + height / 2 - target_y);
            const double shrink = preferred_width - width + preferred_height - height;
            const double score = distance + shrink * 10;
            if (score < best_score) {
              best_score = score;
              best = frame;
            }
          }
        }
      }
    }
  }
  return best ? PairingPlacement{PairingPlacementStatus::kPlaced, best}
              : PairingPlacement{PairingPlacementStatus::kNoRoom, std::nullopt};
}

bool IsSixDigitPairingCode(const char16_t* characters, size_t length) {
  if (!characters || length != 6)
    return false;
  for (size_t i = 0; i < length; ++i) {
    if (characters[i] < u'0' || characters[i] > u'9')
      return false;
  }
  return true;
}

}  // namespace kumo
