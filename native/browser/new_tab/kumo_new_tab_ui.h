// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_NEW_TAB_KUMO_NEW_TAB_UI_H_
#define CHROME_BROWSER_KUMO_NEW_TAB_KUMO_NEW_TAB_UI_H_

#include "content/public/browser/web_ui_controller.h"
#include "content/public/browser/webui_config.h"

namespace kumo {
class KumoNewTabUI;
class KumoNewTabUIConfig : public content::DefaultWebUIConfig<KumoNewTabUI> {
 public:
  KumoNewTabUIConfig();
  bool IsWebUIEnabled(content::BrowserContext* context) override;
};
class KumoNewTabUI : public content::WebUIController {
 public:
  explicit KumoNewTabUI(content::WebUI* web_ui);
  ~KumoNewTabUI() override;
};
}  // namespace kumo
#endif
