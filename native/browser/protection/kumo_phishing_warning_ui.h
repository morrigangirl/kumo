// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_PROTECTION_KUMO_PHISHING_WARNING_UI_H_
#define CHROME_BROWSER_KUMO_PROTECTION_KUMO_PHISHING_WARNING_UI_H_

#include "content/public/browser/web_ui_controller.h"
#include "content/public/browser/webui_config.h"

namespace kumo {
class KumoPhishingWarningUI : public content::WebUIController {
 public:
  explicit KumoPhishingWarningUI(content::WebUI* web_ui);
  ~KumoPhishingWarningUI() override;
};
class KumoPhishingWarningUIConfig
    : public content::DefaultWebUIConfig<KumoPhishingWarningUI> {
 public:
  KumoPhishingWarningUIConfig()
      : DefaultWebUIConfig("chrome", "kumo-phishing-warning") {}
};
}  // namespace kumo
#endif
