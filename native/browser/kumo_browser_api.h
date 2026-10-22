// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_KUMO_BROWSER_API_H_
#define CHROME_BROWSER_KUMO_KUMO_BROWSER_API_H_

#include <string_view>

#include "base/functional/callback.h"
#include "base/values.h"

class Profile;
namespace content {
class WebContents;
}
namespace user_prefs {
class PrefRegistrySyncable;
}

namespace kumo {

using ResultCallback = base::OnceCallback<void(base::DictValue)>;

// Read-only, cached state. This never starts a privileged operation, grants
// agent access, or returns an account credential or a configuration file.
base::DictValue GetStatus(Profile* profile);

// The browser validates the active primary Settings document and consumes its
// transient user activation before dispatching one fixed operation. Unknown
// operations and extra parameters fail before any helper can start.
//
// Fixed operation names:
//   updates.check, protection.setup, definitions.update,
//   agents.connectCodex, agents.connectClaude, agents.refresh,
//   agents.grant, agents.revoke, phishing.setEnabled,
//   malware.setEnabled, malware.update, preferences.set,
//   preferences.import, preferences.export, appearance.applyTheme.
// No operation accepts a command, executable, environment or filesystem path.
void PerformAction(content::WebContents* initiator,
                   std::string_view operation,
                   const base::DictValue& parameters,
                   ResultCallback callback);

// Menu actions use their native trusted command dispatch, not a renderer
// message or a fabricated user activation.
void CheckForUpdatesFromMenu(Profile* profile);

void RegisterProfilePrefs(user_prefs::PrefRegistrySyncable* registry);
void AttachToWebContents(content::WebContents* web_contents);

}  // namespace kumo

#endif  // CHROME_BROWSER_KUMO_KUMO_BROWSER_API_H_
