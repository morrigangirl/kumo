// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/relay/kumo_relay_rail.h"
#include <cmath>
#include "base/functional/bind.h"
#include "base/strings/string_number_conversions.h"
#include "base/timer/timer.h"
#include "chrome/browser/kumo/actions/kumo_preferences.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/actions/chrome_action_id.h"
#include "chrome/browser/ui/browser_actions.h"
#include "chrome/browser/ui/browser_window/public/browser_window_interface.h"
#include "chrome/browser/ui/side_panel/side_panel_entry.h"
#include "chrome/browser/ui/side_panel/side_panel_registry.h"
#include "chrome/browser/ui/side_panel/side_panel_ui.h"
#include "components/prefs/pref_change_registrar.h"
#include "ui/base/metadata/metadata_header_macros.h"
#include "ui/base/metadata/metadata_impl_macros.h"
#include "ui/gfx/animation/animation.h"
#include "ui/gfx/canvas.h"
#include "ui/views/controls/button/label_button.h"
#include "ui/views/accessibility/view_accessibility.h"
#include "ui/views/controls/webview/webview.h"
#include "ui/views/widget/widget.h"

namespace kumo {
namespace {
void ShowMissionMemory(BrowserWindowInterface* browser) {
  if (browser->GetProfile()->IsOffTheRecord() ||
      browser->GetProfile()->IsGuestSession())
    return;
  auto* registry = SidePanelRegistry::From(browser);
  auto* panel = SidePanelUI::From(browser);
  if (!registry || !panel)
    return;
  const SidePanelEntry::Key key(SidePanelEntryId::kKumoMissions);
  if (!registry->GetEntryForKey(key)) {
    BrowserActions::From(browser)->root_action_item()->AddChild(
        actions::ActionItem::Builder()
            .SetActionId(kActionSidePanelShowKumoMissions)
            .SetText(u"Mission Memory")
            .SetTooltipText(u"Mission Memory")
            .SetInvokeActionCallback(base::BindRepeating(
                [](BrowserWindowInterface* b, actions::ActionItem*,
                   actions::ActionInvocationContext) { ShowMissionMemory(b); },
                base::Unretained(browser)))
            .Build());
    registry->Register(std::make_unique<SidePanelEntry>(
        key,
        base::BindRepeating(
            [](SidePanelEntryScope& scope) -> std::unique_ptr<views::View> {
              auto view = std::make_unique<views::WebView>(
                  scope.GetBrowserWindowInterface().GetProfile());
              view->SetPreferredSize(gfx::Size(390, 600));
              view->LoadInitialURL(GURL("chrome://kumo-missions/"));
              return view;
            }),
        base::NullCallback()));
  }
  if (panel->IsSidePanelEntryShowing(key))
    panel->Close();
  else
    panel->Show(key);
}
// A native Views button in the real tab rail. Only the narrow accent line
// animates; labels, tabs and page content stay stationary.
class RelayRailButton : public views::LabelButton {
  METADATA_HEADER(RelayRailButton, views::LabelButton)

 public:
  explicit RelayRailButton(BrowserWindowInterface* browser)
      : LabelButton(
            base::BindRepeating(&ShowMissionMemory, base::Unretained(browser)),
            u"RELAY  /  Mission Memory"),
        profile_(browser->GetProfile()) {
    SetTooltipText(u"Open Mission Memory alongside this page");
    SetMinSize(gfx::Size(0, 42));
    prefs_.Init(profile_->GetPrefs());
    prefs_.Add("kumo.start_page", base::BindRepeating(&RelayRailButton::Refresh,
                                                      base::Unretained(this)));
    Refresh();
  }
  void OnBoundsChanged(const gfx::Rect& previous_bounds) override {
    LabelButton::OnBoundsChanged(previous_bounds);
    const std::u16string text = width() < 100 ? u"R" : u"RELAY  /  Mission Memory";
    if (GetText() != text) SetText(text);
    GetViewAccessibility().SetName(u"RELAY / Mission Memory");
  }
  void PaintButtonContents(gfx::Canvas* canvas) override {
    LabelButton::PaintButtonContents(canvas);
    float strength = 1;
    if (pulse_ && gfx::Animation::ShouldRenderRichAnimation() && GetWidget() &&
        GetWidget()->IsActive())
      strength =
          .7f +
          .3f * std::sin(base::TimeTicks::Now().since_origin().InSecondsF() *
                         1.256637);
    if (glow_)
      for (int i = 1; i <= 4; ++i)
        canvas->FillRect(
            gfx::Rect(8, height() - 2 - i, width() - 16, 1),
            SkColorSetA(accent_, static_cast<int>(intensity_ * strength *
                                                  (5 - i) * 10)));
    canvas->FillRect(gfx::Rect(8, height() - 2, width() - 16, 2),
                     SkColorSetA(accent_, static_cast<int>(220 * strength)));
  }

 private:
  void Refresh() {
    const auto p = preferences::Get(profile_);
    unsigned color = 0xa78bfa;
    base::HexStringToUInt(p.FindString("accent")->substr(1), &color);
    accent_ =
        SkColorSetRGB((color >> 16) & 255, (color >> 8) & 255, color & 255);
    const auto* light = p.FindString("illumination");
    glow_ = light && *light != "off";
    pulse_ = light && *light == "pulse" && p.FindBool("motion").value_or(true);
    intensity_ = p.FindInt("intensity").value_or(40) / 100.f;
    timer_.Stop();
    if (pulse_)
      timer_.Start(FROM_HERE, base::Milliseconds(50),
                   base::BindRepeating(&RelayRailButton::Animate,
                                       base::Unretained(this)));
    SchedulePaint();
  }
  void Animate() {
    if (IsDrawn() && GetWidget() && GetWidget()->IsActive() &&
        gfx::Animation::ShouldRenderRichAnimation())
      SchedulePaint();
  }
  raw_ptr<Profile> profile_;
  PrefChangeRegistrar prefs_;
  base::RepeatingTimer timer_;
  SkColor accent_ = SK_ColorWHITE;
  float intensity_ = .4f;
  bool pulse_ = false, glow_ = true;
};
BEGIN_METADATA(RelayRailButton)
END_METADATA
}  // namespace
std::unique_ptr<views::View> CreateRelayRailButton(
    BrowserWindowInterface* browser) {
  return std::make_unique<RelayRailButton>(browser);
}
}  // namespace kumo
