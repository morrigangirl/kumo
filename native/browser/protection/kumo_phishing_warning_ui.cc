// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/protection/kumo_phishing_warning_ui.h"

#include "base/functional/bind.h"
#include "chrome/browser/kumo/protection/kumo_protection_service.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/grit/browser_resources.h"
#include "content/public/browser/navigation_controller.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_ui.h"
#include "content/public/browser/web_ui_data_source.h"
#include "content/public/browser/web_ui_message_handler.h"
#include "services/network/public/mojom/content_security_policy.mojom.h"
#include "ui/base/page_transition_types.h"
#include "url/gurl.h"

namespace kumo {
namespace {
class WarningHandler final : public content::WebUIMessageHandler {
 public:
  void RegisterMessages() override {
    web_ui()->RegisterMessageCallback("getWarning", base::BindRepeating(&WarningHandler::Get, base::Unretained(this)));
    web_ui()->RegisterMessageCallback("leaveWarning", base::BindRepeating(&WarningHandler::Leave, base::Unretained(this)));
    web_ui()->RegisterMessageCallback("continueWarning", base::BindRepeating(&WarningHandler::Continue, base::Unretained(this)));
  }
 private:
  bool Trusted(bool gesture) {
    auto* frame = web_ui()->GetRenderFrameHost();
    auto* contents = web_ui()->GetWebContents();
    return frame && frame->IsActive() && frame->IsInPrimaryMainFrame() &&
        frame == contents->GetPrimaryMainFrame() &&
        frame->GetLastCommittedURL().SchemeIs("chrome") &&
        frame->GetLastCommittedURL().host() == "kumo-phishing-warning" &&
        (!gesture || frame->ConsumeTransientUserActivation());
  }
  KumoProtectionService* Service() {
    return KumoProtectionService::Get(Profile::FromWebUI(web_ui()));
  }
  void Get(const base::ListValue& arguments) {
    if (arguments.size() != 1 || !arguments[0].is_string() || !Trusted(false)) return;
    AllowJavascript();
    ResolveJavascriptCallback(arguments[0], Service()->WarningDetails(web_ui()->GetWebContents()));
  }
  void Leave(const base::ListValue& arguments) {
    if (!arguments.empty() || !Trusted(true)) return;
    // Leaving an expired ticket is always safe and never follows page data.
    if (!Service()->ResolveWarning(web_ui()->GetWebContents(), false)) {
      web_ui()->GetWebContents()->GetController().LoadURL(GURL("about:blank"),
          content::Referrer(), ui::PAGE_TRANSITION_AUTO_TOPLEVEL, std::string());
    }
  }
  void Continue(const base::ListValue& arguments) {
    if (!arguments.empty() || !Trusted(true)) return;
    Service()->ResolveWarning(web_ui()->GetWebContents(), true);
  }
};
}  // namespace
KumoPhishingWarningUI::KumoPhishingWarningUI(content::WebUI* web_ui)
    : content::WebUIController(web_ui) {
  auto* source = content::WebUIDataSource::CreateAndAdd(
      Profile::FromWebUI(web_ui), "kumo-phishing-warning");
  source->SetDefaultResource(IDR_KUMO_PROTECTION_WARNING_HTML);
  source->AddResourcePath("protection_warning.js", IDR_KUMO_PROTECTION_WARNING_JS);
  source->AddResourcePath("protection_warning.css", IDR_KUMO_PROTECTION_WARNING_CSS);
  source->OverrideContentSecurityPolicy(network::mojom::CSPDirectiveName::FrameSrc, "frame-src 'none';");
  source->OverrideContentSecurityPolicy(network::mojom::CSPDirectiveName::ConnectSrc, "connect-src 'none';");
  web_ui->AddMessageHandler(std::make_unique<WarningHandler>());
}
KumoPhishingWarningUI::~KumoPhishingWarningUI() = default;
}  // namespace kumo
