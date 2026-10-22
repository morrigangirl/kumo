#include "chrome/browser/kumo/kumo_browser_api.h"

#import <Foundation/Foundation.h>

#include <algorithm>
#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/memory/weak_ptr.h"
#include "base/memory/raw_ptr.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/sys_string_conversions.h"
#include "base/supports_user_data.h"
#include "base/task/thread_pool.h"
#include "chrome/browser/kumo/actions/kumo_helper_process.h"
#include "chrome/browser/kumo/actions/kumo_preferences.h"
#include "chrome/browser/kumo/agents/kumo_agent_service.h"
#include "chrome/browser/kumo/protection/kumo_protection_service.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/themes/theme_service.h"
#include "chrome/browser/themes/theme_service_factory.h"
#include "components/pref_registry/pref_registry_syncable.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/visibility.h"
#include "content/public/browser/web_contents.h"
#include "third_party/skia/include/core/SkColor.h"

namespace kumo {
namespace {
const char kActionStateKey = 0;

base::DictValue Error(std::string_view message) {
  return base::DictValue().Set("ok", false).Set("message", message);
}
base::DictValue Success(std::string_view message) {
  return base::DictValue().Set("ok", true).Set("message", message);
}
bool Keys(const base::DictValue& input,
          std::initializer_list<std::string_view> allowed) {
  for (const auto [key, value] : input) {
    if (std::ranges::find(allowed, key) == allowed.end())
      return false;
  }
  return true;
}

// All tasks use fixed app-relative executables and arguments constructed here.
// No renderer data is interpreted as a command, pathname, or environment.
base::DictValue RefreshHelpers(base::FilePath contents, std::string profile_id) {
  auto scanner = RunVerifiedHelper(contents,
      base::FilePath("Helpers/KumoMalware.app/Contents/MacOS/KumoMalwareHost"),
      {"--status"}, base::Seconds(30));
  auto updates = RunVerifiedHelper(contents,
      base::FilePath("Helpers/KumoUpdater.app/Contents/MacOS/KumoUpdater"),
      {"--status"}, base::Seconds(30));
  auto codex = RunVerifiedHelper(contents,
      base::FilePath("Resources/agent-bridge/bin/node"),
      {"--jitless", "--no-expose-wasm", contents.AppendASCII("Resources/agent-bridge/cli.mjs").value(),
       "provider-status", "--profile", profile_id, "--provider", "codex-desktop"},
      base::Seconds(30));
  auto claude = RunVerifiedHelper(contents,
      base::FilePath("Resources/agent-bridge/bin/node"),
      {"--jitless", "--no-expose-wasm", contents.AppendASCII("Resources/agent-bridge/cli.mjs").value(),
       "provider-status", "--profile", profile_id, "--provider", "claude-desktop"},
      base::Seconds(30));
  return base::DictValue().Set("downloadProtection", std::move(scanner))
      .Set("updates", std::move(updates)).Set("clients",
          base::DictValue().Set("codex", std::move(codex))
              .Set("claude", std::move(claude)));
}

class ActionState final : public base::SupportsUserData::Data {
 public:
  explicit ActionState(Profile* profile) : profile_(profile) { Refresh(); }
  ~ActionState() override = default;

  void Refresh() {
    if (refreshing_ || busy_)
      return;
    refreshing_ = true;
    const auto generation = generation_;
    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
        base::BindOnce(&RefreshHelpers, GetContentsPath(),
                      KumoAgentService::Get(profile_)->GetRuntimeId()),
        base::BindOnce(&ActionState::Refreshed, weak_.GetWeakPtr(), generation));
  }

  base::DictValue Status() {
    const bool stale = last_refresh_.is_null() ||
        base::TimeTicks::Now() - last_refresh_ >= base::Seconds(30);
    if (stale)
      Refresh();
    auto state = cached_.Clone();
    state.Set("helperStatus", base::DictValue().Set("refreshing", refreshing_)
        .Set("stale", stale).Set("ageSeconds", last_refresh_.is_null() ? -1.0 :
            (base::TimeTicks::Now() - last_refresh_).InSecondsF()));
    state.Set("operation", base::DictValue().Set("busy", busy_)
        .Set("name", operation_).Set("result", last_result_.Clone()));
    return state;
  }

  void Run(std::string operation, base::FilePath executable,
           std::vector<std::string> arguments, ResultCallback callback,
           base::TimeDelta timeout = base::Seconds(180)) {
    if (busy_) {
      std::move(callback).Run(Error("Another Kumo operation is still running."));
      return;
    }
    busy_ = true;
    operation_ = operation;
    ++generation_;
    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
        base::BindOnce(&RunVerifiedHelper, GetContentsPath(), executable,
                      std::move(arguments), timeout),
        base::BindOnce(&ActionState::Finished, weak_.GetWeakPtr(),
                      std::move(operation), std::move(callback)));
  }

 private:
  void Refreshed(unsigned generation, base::DictValue result) {
    refreshing_ = false;
    if (generation == generation_ && !busy_) {
      cached_ = std::move(result);
      last_refresh_ = base::TimeTicks::Now();
    } else if (!busy_)
      Refresh();
  }
  void Finished(std::string operation, ResultCallback callback,
                base::DictValue result) {
    busy_ = false;
    // A vendor install requiring a macOS window is an intermediate state,
    // never a successful protection-ready result.
    if (result.FindString("status") &&
        *result.FindString("status") == "awaiting-administrator-installation") {
      result.Set("ok", false);
      result.Set("message", "Complete the Apple Installer window, then choose "
                            "Install or repair protection here to continue.");
    } else if (!result.FindString("message")) {
      const bool ok = result.FindBool("ok").value_or(false);
      result.Set("message", ok ? "The operation completed." :
          "Setup needs attention. Your existing configuration was retained.");
    }
    // Internal repair diagnostics must not become command instructions or
    // disclose user configuration/filesystem paths in the Settings UI.
    result.Remove("nextCommand");
    result.Remove("packagePath");
    result.Remove("manifestPath");
    result.Remove("codexConfig");
    result.Remove("claudeConfig");
    last_result_ = result.Clone();
    std::move(callback).Run(std::move(result));
    Refresh();
  }
  raw_ptr<Profile> profile_;
  bool busy_ = false;
  bool refreshing_ = false;
  unsigned generation_ = 0;
  base::TimeTicks last_refresh_;
  std::string operation_;
  base::DictValue cached_;
  base::DictValue last_result_;
  base::WeakPtrFactory<ActionState> weak_{this};
};

ActionState* State(Profile* profile) {
  auto* state = static_cast<ActionState*>(profile->GetUserData(&kActionStateKey));
  if (!state) {
    auto value = std::make_unique<ActionState>(profile);
    state = value.get();
    profile->SetUserData(&kActionStateKey, std::move(value));
  }
  return state;
}
void CheckUpdates(Profile* profile, ResultCallback callback) {
  State(profile)->Run("updates.check", base::FilePath("MacOS/Kumo"),
      {"--kumo-check-for-updates"}, std::move(callback), base::Seconds(30));
}
}  // namespace

base::DictValue GetStatus(Profile* profile) {
  if (!profile || profile->IsOffTheRecord() || profile->IsGuestSession())
    return Error("Open Kumo Settings in a regular browser profile.");
  auto result = State(profile)->Status();
  NSBundle* bundle = [NSBundle bundleWithPath:
      base::SysUTF8ToNSString(GetContentsPath().DirName().value())];
  NSString* version = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
  NSString* build = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"];
  result.Set("schemaVersion", 1);
  result.Set("version", base::SysNSStringToUTF8(version ?: @"Development"));
  result.Set("build", base::SysNSStringToUTF8(build ?: @"unavailable"));
  result.Set("preferences", preferences::Get(profile));
  result.Set("protection", KumoProtectionService::Get(profile)->GetStatus());
  result.Set("agents", KumoAgentService::Get(profile)->GetStatus());
  result.Set("tabs", KumoAgentService::Get(profile)->GetEligibleTabs());
  return result;
}

void PerformAction(content::WebContents* initiator, std::string_view operation,
                   const base::DictValue& parameters, ResultCallback callback) {
  auto* frame = initiator ? initiator->GetPrimaryMainFrame() : nullptr;
  const GURL url = initiator ? initiator->GetLastCommittedURL() : GURL();
  auto* profile = initiator ?
      Profile::FromBrowserContext(initiator->GetBrowserContext()) : nullptr;
  if (!frame || !frame->IsActive() ||
      initiator->GetVisibility() != content::Visibility::VISIBLE ||
      !url.SchemeIs("chrome") || url.host() != "settings" ||
      url.path() != "/kumo" || !profile || profile->IsOffTheRecord() ||
      profile->IsGuestSession() || !frame->ConsumeTransientUserActivation()) {
    std::move(callback).Run(Error("Use a button in the active Kumo Settings page."));
    return;
  }
  if (operation == "preferences.set") {
    std::move(callback).Run(preferences::SetPartial(profile, parameters));
  } else if (operation == "preferences.import" &&
             Keys(parameters, {"preferences"}) &&
             parameters.FindDict("preferences")) {
    std::move(callback).Run(preferences::SetPartial(
        profile, *parameters.FindDict("preferences")));
  } else if (operation == "preferences.export" && parameters.empty()) {
    std::move(callback).Run(Success("Preferences exported.")
        .Set("preferences", preferences::Get(profile)));
  } else if (operation == "appearance.applyTheme" && parameters.empty()) {
    auto prefs = preferences::Get(profile);
    unsigned color;
    const auto* accent = prefs.FindString("accent");
    if (!accent || !base::HexStringToUInt(accent->substr(1), &color)) {
      std::move(callback).Run(Error("Choose a valid palette color first."));
      return;
    }
    ThemeServiceFactory::GetForProfile(profile)->BuildAutogeneratedThemeFromColor(
        SkColorSetRGB((color >> 16) & 255, (color >> 8) & 255, color & 255));
    std::move(callback).Run(Success("Palette applied to the browser."));
  } else if ((operation == "phishing.setEnabled" ||
              operation == "malware.setEnabled") &&
             Keys(parameters, {"enabled"}) && parameters.FindBool("enabled")) {
    auto* protection = KumoProtectionService::Get(profile);
    if (operation == "phishing.setEnabled")
      protection->SetPhishingEnabled(*parameters.FindBool("enabled"));
    else
      protection->SetMalwareEnabled(*parameters.FindBool("enabled"));
    std::move(callback).Run(Success("Protection preference saved."));
  } else if (operation == "malware.update" && parameters.empty()) {
    KumoProtectionService::Get(profile)->UpdateDomains(std::move(callback));
  } else if (operation == "agents.grant" &&
             Keys(parameters, {"grants", "allowNewTabs"}) &&
             parameters.FindList("grants") &&
             parameters.FindBool("allowNewTabs")) {
    KumoAgentService::Get(profile)->SetGrants(*parameters.FindList("grants"),
        *parameters.FindBool("allowNewTabs"), std::move(callback));
  } else if (operation == "agents.revoke" && parameters.empty()) {
    KumoAgentService::Get(profile)->Revoke();
    std::move(callback).Run(Success("All agent access revoked."));
  } else if (operation == "agents.refresh" && parameters.empty()) {
    State(profile)->Refresh();
    std::move(callback).Run(Success("Refreshing client status."));
  } else if (operation == "updates.check" && parameters.empty()) {
    CheckUpdates(profile, std::move(callback));
  } else if ((operation == "protection.setup" ||
              operation == "definitions.update") && parameters.empty()) {
    State(profile)->Run(std::string(operation), base::FilePath("MacOS/KumoMalwareSetup"),
        operation == "definitions.update" ? std::vector<std::string>{"--update"} :
                                             std::vector<std::string>{},
        std::move(callback), base::Minutes(10));
  } else if ((operation == "agents.connectCodex" ||
              operation == "agents.connectClaude") && parameters.empty()) {
    const auto contents = GetContentsPath();
    State(profile)->Run(std::string(operation),
        base::FilePath("Resources/agent-bridge/bin/node"),
        {"--jitless", "--no-expose-wasm", contents.AppendASCII("Resources/agent-bridge/cli.mjs").value(),
         "provider-configure", "--profile", KumoAgentService::Get(profile)->GetRuntimeId(),
         "--provider", operation == "agents.connectCodex" ? "codex-desktop" : "claude-desktop"},
        std::move(callback));
  } else {
    std::move(callback).Run(Error("This Kumo action or its parameters are invalid."));
  }
}

void CheckForUpdatesFromMenu(Profile* profile) {
  if (profile && !profile->IsOffTheRecord() && !profile->IsGuestSession())
    CheckUpdates(profile, base::BindOnce([](base::DictValue) {}));
}
void RegisterProfilePrefs(user_prefs::PrefRegistrySyncable* registry) {
  preferences::Register(registry);
  KumoProtectionService::RegisterProfilePrefs(registry);
}
void AttachToWebContents(content::WebContents* web_contents) {
  auto* profile = Profile::FromBrowserContext(web_contents->GetBrowserContext());
  if (!profile->IsOffTheRecord() && !profile->IsGuestSession()) {
    KumoProtectionService::Get(profile)->AttachToWebContents(web_contents);
    KumoAgentService::AttachToWebContents(web_contents);
  }
}
}  // namespace kumo
