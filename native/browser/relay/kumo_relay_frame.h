// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_RELAY_KUMO_RELAY_FRAME_H_
#define CHROME_BROWSER_KUMO_RELAY_KUMO_RELAY_FRAME_H_
#include "third_party/skia/include/core/SkColor.h"
class BrowserView;
class Profile;
namespace kumo {
bool UseRelayFrame(const Profile* profile);
SkColor RelayAccent(Profile* profile);
void InstallRelayFrame(BrowserView* browser);
void LayoutRelayFrame(BrowserView* browser);
}  // namespace kumo
#endif
