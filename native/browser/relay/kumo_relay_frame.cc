// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/relay/kumo_relay_frame.h"
#include <algorithm>
#include <array>
#include <cmath>
#include "base/functional/bind.h"
#include "base/strings/string_number_conversions.h"
#include "base/timer/timer.h"
#include "chrome/browser/kumo/actions/kumo_preferences.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/views/frame/browser_view.h"
#include "components/prefs/pref_change_registrar.h"
#include "components/prefs/pref_service.h"
#include "ui/base/metadata/metadata_header_macros.h"
#include "ui/base/metadata/metadata_impl_macros.h"
#include "ui/compositor/layer.h"
#include "ui/gfx/animation/animation.h"
#include "ui/gfx/canvas.h"
#include "ui/views/view.h"
#include "ui/views/view_class_properties.h"
#include "ui/views/widget/widget.h"
#include "ui/views/widget/widget_observer.h"
namespace kumo {
namespace {
constexpr int kRelayFrameId = 65030;
constexpr int kEdge = 7;
// Each edge has a small independent compositor texture. Pulsing changes only
// layer opacity: no full-window texture and no page repaint at animation rate.
class RelayEdge : public views::View {
  METADATA_HEADER(RelayEdge, views::View)
 public:
  explicit RelayEdge(int side) : side_(side) {
    SetCanProcessEventsWithinSubtree(false);
    SetPaintToLayer();
    layer()->SetFillsBoundsOpaquely(false);
  }
  void SetStyle(SkColor accent, bool glow, float intensity) {
    accent_ = accent;
    glow_ = glow;
    intensity_ = intensity;
    SchedulePaint();
  }
  void OnPaint(gfx::Canvas* canvas) override {
    const bool horizontal = side_ < 2;
    const int length = horizontal ? width() : height();
    for (int i = 0; i < kEdge; ++i) {
      const int offset = (side_ == 1 || side_ == 3) ? kEdge - 1 - i : i;
      const int alpha = i == 0 ? 145 :
          (glow_ ? static_cast<int>(intensity_ * (kEdge - i) * 20) : 0);
      canvas->FillRect(horizontal ? gfx::Rect(0, offset, length, 1)
                                  : gfx::Rect(offset, 0, 1, length),
                       SkColorSetA(accent_, alpha));
    }
    // Crisp terminal-like corner brackets distinguish the frame even when
    // illumination and motion are disabled.
    const int offset = (side_ == 1 || side_ == 3) ? kEdge - 3 : 1;
    for (int start : {0, std::max(0, length - 32)})
      canvas->FillRect(horizontal ? gfx::Rect(start, offset, std::min(32, length), 2)
                                  : gfx::Rect(offset, start, 2, std::min(32, length)),
                       SkColorSetA(accent_, 225));
  }
 private:
  int side_;
  SkColor accent_ = SK_ColorWHITE;
  bool glow_ = false;
  float intensity_ = 0;
};
BEGIN_METADATA(RelayEdge)
END_METADATA
class RelayFrame : public views::View, public views::WidgetObserver {
  METADATA_HEADER(RelayFrame, views::View)
 public:
  explicit RelayFrame(BrowserView* browser) : browser_(browser) {
    SetID(kRelayFrameId);
    SetProperty(views::kViewIgnoredByLayoutKey, true);
    SetCanProcessEventsWithinSubtree(false);
    SetPaintToLayer(ui::LAYER_NOT_DRAWN);
    for (int i = 0; i < 4; ++i)
      edges_[i] = AddChildView(std::make_unique<RelayEdge>(i));
    prefs_.Init(browser_->browser()->GetProfile()->GetPrefs());
    prefs_.Add("kumo.start_page", base::BindRepeating(&RelayFrame::Refresh,
                                                     base::Unretained(this)));
  }
  ~RelayFrame() override {
    if (observed_widget_) observed_widget_->RemoveObserver(this);
  }
  void AddedToWidget() override {
    observed_widget_ = GetWidget();
    observed_widget_->AddObserver(this);
    Refresh();
  }
  void RemovedFromWidget() override {
    timer_.Stop();
    if (observed_widget_) observed_widget_->RemoveObserver(this);
    observed_widget_ = nullptr;
  }
  void OnWidgetDestroying(views::Widget* widget) override {
    timer_.Stop();
    widget->RemoveObserver(this);
    observed_widget_ = nullptr;
  }
  void OnWidgetActivationChanged(views::Widget*, bool) override { UpdateMotion(); }
  void VisibilityChanged(views::View*, bool) override { UpdateMotion(); }
  void OnBoundsChanged(const gfx::Rect&) override {
    const int w = width(), h = height();
    edges_[0]->SetBounds(0, 0, w, kEdge);
    edges_[1]->SetBounds(0, std::max(0, h - kEdge), w, kEdge);
    edges_[2]->SetBounds(0, kEdge, kEdge, std::max(0, h - 2 * kEdge));
    edges_[3]->SetBounds(std::max(0, w - kEdge), kEdge, kEdge,
                         std::max(0, h - 2 * kEdge));
  }
 private:
  void Refresh() {
    const auto settings = preferences::Get(browser_->browser()->GetProfile());
    const auto* light = settings.FindString("illumination");
    const bool glow = light && *light != "off";
    const float intensity = settings.FindInt("intensity").value_or(40) / 100.f;
    pulse_ = light && *light == "pulse" && intensity > 0 &&
             settings.FindBool("motion").value_or(true);
    for (auto edge : edges_)
      edge->SetStyle(RelayAccent(browser_->browser()->GetProfile()), glow, intensity);
    LayoutRelayFrame(browser_);
    browser_->SchedulePaint();
    UpdateMotion();
  }
  void UpdateMotion() {
    timer_.Stop();
    const bool active = observed_widget_ && observed_widget_->IsActive();
    layer()->SetOpacity(active ? 1.f : .45f);
    if (pulse_ && active && IsDrawn() && gfx::Animation::ShouldRenderRichAnimation())
      timer_.Start(FROM_HERE, base::Milliseconds(50),
                   base::BindRepeating(&RelayFrame::Animate, base::Unretained(this)));
  }
  void Animate() {
    if (!IsDrawn() || !gfx::Animation::ShouldRenderRichAnimation()) {
      UpdateMotion();
      return;
    }
    const double phase = base::TimeTicks::Now().since_origin().InSecondsF() * 1.256637;
    layer()->SetOpacity(.72f + .28f * std::sin(phase));
  }
  raw_ptr<BrowserView> browser_;
  raw_ptr<views::Widget> observed_widget_ = nullptr;
  std::array<raw_ptr<RelayEdge>, 4> edges_;
  PrefChangeRegistrar prefs_;
  base::RepeatingTimer timer_;
  bool pulse_ = false;
};
BEGIN_METADATA(RelayFrame)
END_METADATA
}  // namespace
bool UseRelayFrame(const Profile* profile) {
  if (!profile || profile->IsOffTheRecord() || profile->IsGuestSession()) return false;
  const auto& p = profile->GetPrefs()->GetDict("kumo.start_page");
  const auto* theme = p.FindString("theme");
  return !theme || *theme == "relay";
}
SkColor RelayAccent(Profile* profile) {
  const auto p = preferences::Get(profile);
  unsigned color = 0xa78bfa;
  if (const auto* accent = p.FindString("accent"))
    base::HexStringToUInt(accent->substr(1), &color);
  return SkColorSetRGB((color >> 16) & 255, (color >> 8) & 255, color & 255);
}
void InstallRelayFrame(BrowserView* browser) {
  if (browser->GetIsNormalType()) {
    browser->AddChildView(std::make_unique<RelayFrame>(browser));
    LayoutRelayFrame(browser);
  }
}
void LayoutRelayFrame(BrowserView* browser) {
  auto* frame = browser->GetViewByID(kRelayFrameId);
  if (!frame) return;
  frame->SetVisible(UseRelayFrame(browser->browser()->GetProfile()) &&
                    !browser->IsFullscreen());
  frame->SetBoundsRect(browser->GetLocalBounds());
  if (frame->layer()->parent()) frame->layer()->parent()->StackAtTop(frame->layer());
}
}  // namespace kumo
