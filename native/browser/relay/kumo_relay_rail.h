// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_RELAY_KUMO_RELAY_RAIL_H_
#define CHROME_BROWSER_KUMO_RELAY_KUMO_RELAY_RAIL_H_
#include <memory>
class BrowserWindowInterface;
namespace views {
class View;
}
namespace kumo {
std::unique_ptr<views::View> CreateRelayRailButton(
    BrowserWindowInterface* browser);
}
#endif
