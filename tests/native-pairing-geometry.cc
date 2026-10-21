#include "../native/chromium/kumo_pairing_geometry.h"

#include <cmath>
#include <cstdio>
#include <limits>
#include <stdexcept>

namespace {
int assertions = 0;
void Expect(bool condition, const char* message) {
  ++assertions;
  if (!condition)
    throw std::runtime_error(message);
}

void CheckSafe(const kumo::PairingGeometry& geometry,
               const kumo::PairingPlacement& placement) {
  Expect(placement.status == kumo::PairingPlacementStatus::kPlaced && placement.frame.has_value(),
         "expected a usable placement");
  const auto& a = *placement.frame;
  bool contained = false;
  for (const auto& screen : geometry.visible_screens) {
    contained |= a.x >= screen.x && a.y >= screen.y &&
        a.x + a.width <= screen.x + screen.width &&
        a.y + a.height <= screen.y + screen.height;
  }
  Expect(contained, "entry panel must fit wholly inside one visible screen");
  for (const auto& b : geometry.helper_windows) {
    Expect(a.x + a.width + 12 <= b.x || b.x + b.width + 12 <= a.x ||
               a.y + a.height + 12 <= b.y || b.y + b.height + 12 <= a.y,
           "entry panel must have the promised gap from every helper window");
  }
}

void Run() {
  using kumo::PairingGeometry;
  using kumo::PairingPlacementStatus;
  using kumo::PlacePairingPanel;
  PairingGeometry desktop{{{0, 24, 1440, 852}}, {{400, 310, 640, 240}}};
  auto first = PlacePairingPanel(desktop);
  CheckSafe(desktop, first);
  auto same = PlacePairingPanel(desktop, first.frame);
  Expect(same.frame->x == first.frame->x && same.frame->y == first.frame->y,
         "refresh must preserve a safe user placement");
  auto moved = desktop;
  moved.helper_windows = {*first.frame};
  auto repositioned = PlacePairingPanel(moved, first.frame);
  CheckSafe(moved, repositioned);
  Expect(repositioned.frame->x != first.frame->x || repositioned.frame->y != first.frame->y,
         "entry panel must move when the helper occupies its previous frame");

  PairingGeometry small{{{0, 0, 320, 480}}, {{0, 280, 320, 200}}};
  auto compact = PlacePairingPanel(small);
  CheckSafe(small, compact);
  Expect(compact.frame->width == 300, "narrow display must select compact width");
  PairingGeometry short_display{{{0, 0, 800, 400}}, {{0, 206, 800, 194}}};
  auto shorter = PlacePairingPanel(short_display);
  CheckSafe(short_display, shorter);
  Expect(shorter.frame->height == 194, "short display must select compact height");

  PairingGeometry multiple{{{-1280, -200, 1280, 900}, {0, 24, 1440, 852},
                            {200, 1000, 800, 600}},
                           {{0, 24, 1440, 852}, {200, 1000, 800, 600}}};
  auto other_screen = PlacePairingPanel(multiple);
  CheckSafe(multiple, other_screen);
  Expect(other_screen.frame->x < 0, "must use available negative-origin display");
  PairingGeometry vertical{{{0, -900, 700, 900}}, {{0, -600, 700, 250}}};
  CheckSafe(vertical, PlacePairingPanel(vertical));
  auto converted = kumo::PairingGeometryFromBounds(
      {{-1000, -800, 1000, 1600}},
      {{999, {12, 34, 56, 78}}, {123, {-900, -100, 200, 150}},
       {123, {-600, 900, 200, 100}}}, 123, 800);
  Expect(converted.helper_windows.size() == 2,
         "metadata conversion must filter only the explicit owner PID, not layers");
  Expect(converted.helper_windows[0].x == -900 && converted.helper_windows[0].y == 750 &&
             converted.helper_windows[1].y == -200,
         "Quartz conversion must preserve negative origins and vertical screen offsets");
  CheckSafe(converted, PlacePairingPanel(converted));
  PairingGeometry obstacles{{{0, 0, 1200, 800}}, {{350, 200, 500, 400},
                                              {0, 0, 350, 800},
                                              {850, 0, 350, 800}}};
  Expect(PlacePairingPanel(obstacles).status == PairingPlacementStatus::kNoRoom,
         "all helper windows must count, including side windows");
  PairingGeometry full{{{0, 0, 640, 480}}, {{0, 0, 640, 480}}};
  auto blocked = PlacePairingPanel(full);
  Expect(blocked.status == PairingPlacementStatus::kNoRoom && !blocked.frame,
         "full-screen helper must hide entry instead of overlap");
  Expect(PlacePairingPanel({{{0, 0, 299, 193}}, {{500, 500, 10, 10}}}).status ==
             PairingPlacementStatus::kNoRoom,
         "display below minimum size must fail closed");
  Expect(PlacePairingPanel({{}, {{1, 1, 10, 10}}}).status == PairingPlacementStatus::kUnavailable,
         "missing screen bounds must be unavailable");
  Expect(PlacePairingPanel({{{0, 0, 1000, 1000}}, {}}).status == PairingPlacementStatus::kUnavailable,
         "missing helper bounds must be unavailable");
  for (double invalid : {0.0, -1.0, std::numeric_limits<double>::infinity(),
                         std::numeric_limits<double>::quiet_NaN()}) {
    auto bad = desktop;
    bad.helper_windows[0].width = invalid;
    auto result = PlacePairingPanel(bad);
    Expect(result.status == PairingPlacementStatus::kInvalid && !result.frame,
           "invalid helper geometry must never yield placement");
  }
  Expect(PlacePairingPanel(desktop, std::nullopt, 300, 194, 360, 210).status ==
             PairingPlacementStatus::kInvalid,
         "inverted size constraints must fail");
  Expect(PlacePairingPanel(desktop, std::nullopt, 360, 210, 300, 194, -1).status ==
             PairingPlacementStatus::kInvalid,
         "negative gap must fail");
  Expect(kumo::IsSixDigitPairingCode(u"012345", 6), "ASCII code accepts leading zero");
  Expect(!kumo::IsSixDigitPairingCode(u"12345", 5), "short code must fail");
  Expect(!kumo::IsSixDigitPairingCode(u"1234567", 7), "long code must fail");
  Expect(!kumo::IsSixDigitPairingCode(u"１２３４５６", 6), "Unicode lookalike digits must fail");
  Expect(!kumo::IsSixDigitPairingCode(u"123 56", 6), "whitespace must fail");
  Expect(!kumo::IsSixDigitPairingCode(nullptr, 6), "null input must fail");
}
}  // namespace

int main() {
  try {
    Run();
    std::printf("PASS: %d synthetic pairing geometry checks\n", assertions);
    return 0;
  } catch (const std::exception& error) {
    std::fprintf(stderr, "FAIL: %s\n", error.what());
    return 1;
  }
}
