#ifndef CHROME_BROWSER_KUMO_ACTIONS_KUMO_PREFERENCES_H_
#define CHROME_BROWSER_KUMO_ACTIONS_KUMO_PREFERENCES_H_

#include "base/values.h"
class Profile;
class PrefService;
namespace user_prefs { class PrefRegistrySyncable; }

namespace kumo::preferences {
void Register(user_prefs::PrefRegistrySyncable* registry);
// The same persisted validation logic is usable without a browser lifecycle.
base::DictValue Get(PrefService* prefs);
base::DictValue SetPartial(PrefService* prefs, const base::DictValue& input);
bool ImportLegacy(PrefService* prefs, const base::DictValue& input);
base::DictValue Get(Profile* profile);
base::DictValue SetPartial(Profile* profile, const base::DictValue& input);
// Imports only a validated old product setting, never grants or credentials.
// Existing native user settings always win. False means malformed legacy data.
bool ImportLegacy(Profile* profile, const base::DictValue& input);
}  // namespace kumo::preferences
#endif
