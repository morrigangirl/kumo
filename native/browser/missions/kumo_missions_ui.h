// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_MISSIONS_KUMO_MISSIONS_UI_H_
#define CHROME_BROWSER_KUMO_MISSIONS_KUMO_MISSIONS_UI_H_
#include "content/public/browser/web_ui_controller.h"
#include "content/public/browser/webui_config.h"
namespace kumo {
class KumoMissionsUI : public content::WebUIController {
 public:
  explicit KumoMissionsUI(content::WebUI* web_ui);
};
class KumoMissionsUIConfig
    : public content::DefaultWebUIConfig<KumoMissionsUI> {
 public:
  KumoMissionsUIConfig();
  bool IsWebUIEnabled(content::BrowserContext* context) override;
};
}  // namespace kumo
#endif
