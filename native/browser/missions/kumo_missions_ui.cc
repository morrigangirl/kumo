// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/missions/kumo_missions_ui.h"
#include "base/functional/bind.h"
#include "chrome/browser/kumo/actions/kumo_preferences.h"
#include "chrome/browser/kumo/agents/kumo_agent_service.h"
#include "chrome/browser/kumo/missions/kumo_mission_store.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/browser_window/public/browser_window_interface.h"
#include "chrome/browser/ui/browser_window/public/browser_window_interface_iterator.h"
#include "chrome/grit/browser_resources.h"
#include "content/public/browser/page_navigator.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/visibility.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_ui.h"
#include "content/public/browser/web_ui_data_source.h"
#include "content/public/browser/web_ui_message_handler.h"
#include "services/network/public/mojom/content_security_policy.mojom.h"
#include "ui/base/base_window.h"
#include "ui/base/page_transition_types.h"

namespace kumo {
namespace {
base::DictValue Failure(std::string_view text) {
  return base::DictValue().Set("ok", false).Set("error", std::string(text));
}
class MissionsHandler : public content::WebUIMessageHandler {
 public:
  void RegisterMessages() override {
    web_ui()->RegisterMessageCallback(
        "kumoMissions",
        base::BindRepeating(&MissionsHandler::Handle, base::Unretained(this)));
  }

 private:
  void Handle(const base::ListValue& args) {
    if (args.size() != 3 || !args[0].is_string() || !args[1].is_string() ||
        !args[2].is_dict())
      return;
    auto* contents = web_ui()->GetWebContents();
    auto* frame = web_ui()->GetRenderFrameHost();
    auto* profile = Profile::FromWebUI(web_ui());
    if (!frame || frame != contents->GetPrimaryMainFrame() ||
        !frame->IsActive() ||
        frame->GetLastCommittedURL() != GURL("chrome://kumo-missions/") ||
        profile->IsOffTheRecord() || profile->IsGuestSession())
      return;
    const auto& action = args[1].GetString();
    const auto& p = args[2].GetDict();
    AllowJavascript();
    if (action != "status" &&
        (contents->GetVisibility() != content::Visibility::VISIBLE ||
         !frame->ConsumeTransientUserActivation())) {
      ResolveJavascriptCallback(args[0],
                                Failure("Use a button in Mission Memory."));
      return;
    }
    ResolveJavascriptCallback(args[0], Run(profile, action, p));
  }
  base::DictValue Run(Profile* profile,
                      const std::string& action,
                      const base::DictValue& p) {
    auto* agent = KumoAgentService::Get(profile);
    if (action == "settings" && p.empty()) {
      for (auto* browser : GetAllBrowserWindowInterfaces())
        if (browser->GetProfile() == profile &&
            browser->GetWindow()->GetNativeWindow() ==
                web_ui()->GetWebContents()->GetTopLevelNativeWindow()) {
          browser->OpenURL(content::OpenURLParams::CreateBrowserInitiated(
                               GURL("chrome://settings/kumo"),
                               WindowOpenDisposition::NEW_FOREGROUND_TAB,
                               ui::PAGE_TRANSITION_TYPED),
                           {});
          return base::DictValue().Set("ok", true);
        }
      return Failure("Open an ordinary Kumo window first.");
    }
    if (action == "status" && p.empty())
      return base::DictValue()
          .Set("ok", true)
          .Set("missions", missions::List(profile->GetPrefs()))
          .Set("tabs", agent->GetEligibleTabs())
          .Set("sharing", agent->MissionStatus())
          .Set("preferences", preferences::Get(profile));
    if (action == "share" && p.size() == 1 && p.FindList("ids"))
      return agent->SetMissionGrants(*p.FindList("ids"));
    if (action == "revoke" && p.empty()) {
      agent->RevokeMissions();
      return base::DictValue().Set("ok", true);
    }
    if (action == "save" && p.size() == 3 && p.FindDict("fields") &&
        p.FindList("tabIds") && p.FindBool("capture")) {
      const auto& fields = *p.FindDict("fields");
      const auto& ids = *p.FindList("tabIds");
      if (ids.size() > 50)
        return Failure("Choose at most 50 tabs per mission.");
      base::ListValue sources;
      if (*p.FindBool("capture")) {
        auto tabs = agent->GetEligibleTabs();
        std::set<int> selected;
        for (const auto& id : ids) {
          if (!id.is_int() || !selected.insert(id.GetInt()).second)
            return Failure("Invalid tab selection.");
          bool found = false;
          for (const auto& tab : tabs)
            if (tab.GetDict().FindInt("tabId") == id.GetInt()) {
              sources.Append(
                  base::DictValue()
                      .Set("url", *tab.GetDict().FindString("url"))
                      .Set("title", *tab.GetDict().FindString("title")));
              found = true;
              break;
            }
          if (!found)
            return Failure("A selected tab changed. Refresh the tab list.");
        }
      } else if (const auto* id = fields.FindString("id")) {
        for (const auto& m : missions::List(profile->GetPrefs()))
          if (*m.GetDict().FindString("id") == *id)
            sources = m.GetDict().FindList("sources")->Clone();
      }
      return missions::Save(profile->GetPrefs(), fields, std::move(sources));
    }
    if (((action == "delete" || action == "restore") && p.size() == 1 &&
         p.FindString("id")) ||
        (action == "open" && p.size() == 2 && p.FindString("id") &&
         p.FindInt("index") && *p.FindInt("index") >= 0)) {
      const auto& id = *p.FindString("id");
      if (action == "delete") {
        // Remove the grant before deleting so a recreated item cannot inherit
        // it.
        auto status = agent->MissionStatus();
        auto ids = status.FindList("grants")->Clone();
        ids.EraseIf([&](const base::Value& v) { return v.GetString() == id; });
        agent->SetMissionGrants(ids);
        return missions::Remove(profile->GetPrefs(), id);
      }
      for (const auto& m : missions::List(profile->GetPrefs()))
        if (*m.GetDict().FindString("id") == id) {
          BrowserWindowInterface* target = nullptr;
          for (auto* browser : GetAllBrowserWindowInterfaces())
            if (browser->GetProfile() == profile &&
                browser->GetWindow()->GetNativeWindow() ==
                    web_ui()->GetWebContents()->GetTopLevelNativeWindow()) {
              target = browser;
              break;
            }
          if (!target)
            return Failure("Open an ordinary Kumo window first.");
          const auto* sources = m.GetDict().FindList("sources");
          if (action == "open" &&
              static_cast<size_t>(*p.FindInt("index")) >= sources->size())
            return Failure("This source no longer exists.");
          int index = 0;
          for (const auto& source : *sources) {
            if (action == "open" && index++ != *p.FindInt("index"))
              continue;
            target->OpenURL(content::OpenURLParams::CreateBrowserInitiated(
                                GURL(*source.GetDict().FindString("url")),
                                action == "open"
                                    ? WindowOpenDisposition::NEW_FOREGROUND_TAB
                                    : WindowOpenDisposition::NEW_BACKGROUND_TAB,
                                ui::PAGE_TRANSITION_AUTO_BOOKMARK),
                            {});
          }
          return base::DictValue().Set("ok", true);
        }
    }
    return Failure("This Mission Memory action is invalid.");
  }
};
}  // namespace
KumoMissionsUIConfig::KumoMissionsUIConfig()
    : DefaultWebUIConfig("chrome", "kumo-missions") {}
bool KumoMissionsUIConfig::IsWebUIEnabled(content::BrowserContext* context) {
  auto* profile = Profile::FromBrowserContext(context);
  return !profile->IsOffTheRecord() && !profile->IsGuestSession();
}
KumoMissionsUI::KumoMissionsUI(content::WebUI* ui) : WebUIController(ui) {
  auto* source = content::WebUIDataSource::CreateAndAdd(Profile::FromWebUI(ui),
                                                        "kumo-missions");
  source->AddResourcePath("missions.js", IDR_KUMO_MISSIONS_JS);
  source->AddResourcePath("missions.css", IDR_KUMO_MISSIONS_CSS);
  source->SetDefaultResource(IDR_KUMO_MISSIONS_HTML);
  source->OverrideContentSecurityPolicy(
      network::mojom::CSPDirectiveName::ConnectSrc, "connect-src 'none';");
  source->OverrideContentSecurityPolicy(
      network::mojom::CSPDirectiveName::FrameSrc, "frame-src 'none';");
  ui->AddMessageHandler(std::make_unique<MissionsHandler>());
}
}  // namespace kumo
