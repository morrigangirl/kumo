// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/new_tab/kumo_new_tab_ui.h"

#include "base/functional/bind.h"
#include "chrome/grit/browser_resources.h"
#include "chrome/browser/kumo/kumo_browser_api.h"
#include "chrome/browser/profiles/profile.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_ui.h"
#include "content/public/browser/web_ui_data_source.h"
#include "content/public/browser/web_ui_message_handler.h"
#include "content/public/common/url_constants.h"
#include "url/gurl.h"
#include "services/network/public/mojom/content_security_policy.mojom.h"

namespace kumo {
namespace {
class NewTabPreferencesHandler : public content::WebUIMessageHandler {
 public:
  void RegisterMessages() override {
    web_ui()->RegisterMessageCallback("kumoNewTabPreferences", base::BindRepeating(
        &NewTabPreferencesHandler::Preferences, base::Unretained(this)));
  }
 private:
  void Preferences(const base::ListValue& args) {
    auto* contents = web_ui()->GetWebContents();
    auto* frame = web_ui()->GetRenderFrameHost();
    if (args.size() != 1 || !args[0].is_string() || !frame ||
        frame != contents->GetPrimaryMainFrame() || !frame->IsActive() ||
        frame->GetLastCommittedURL() != GURL("chrome://kumo-new-tab/") ||
        Profile::FromWebUI(web_ui())->IsOffTheRecord()) return;
    // This read-only surface deliberately exposes no actions, grants or helpers.
    auto status = GetStatus(Profile::FromWebUI(web_ui()));
    const auto* preferences = status.FindDict("preferences");
    AllowJavascript();
    ResolveJavascriptCallback(args[0], preferences ? base::Value(preferences->Clone())
                                                   : base::Value(base::DictValue()));
  }
};
}  // namespace

KumoNewTabUIConfig::KumoNewTabUIConfig()
    : DefaultWebUIConfig(content::kChromeUIScheme, "kumo-new-tab") {}
bool KumoNewTabUIConfig::IsWebUIEnabled(content::BrowserContext* context) {
  return !Profile::FromBrowserContext(context)->IsOffTheRecord();
}
KumoNewTabUI::KumoNewTabUI(content::WebUI* web_ui)
    : content::WebUIController(web_ui) {
  auto* source = content::WebUIDataSource::CreateAndAdd(
      Profile::FromWebUI(web_ui), "kumo-new-tab");
  source->AddResourcePath("new_tab.js", IDR_KUMO_NEW_TAB_JS);
  source->AddResourcePath("new_tab.css", IDR_KUMO_NEW_TAB_CSS);
  source->SetDefaultResource(IDR_KUMO_NEW_TAB_HTML);
  // Local validated wallpaper data is the only additional image source.
  source->OverrideContentSecurityPolicy(network::mojom::CSPDirectiveName::ImgSrc,
      "img-src 'self' data:;");
  source->OverrideContentSecurityPolicy(network::mojom::CSPDirectiveName::FrameSrc,
      "frame-src 'none';");
  source->OverrideContentSecurityPolicy(network::mojom::CSPDirectiveName::ConnectSrc,
      "connect-src 'none';");
  web_ui->AddMessageHandler(std::make_unique<NewTabPreferencesHandler>());
}
KumoNewTabUI::~KumoNewTabUI() = default;
}  // namespace kumo
