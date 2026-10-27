// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_MISSIONS_KUMO_MISSION_STORE_H_
#define CHROME_BROWSER_KUMO_MISSIONS_KUMO_MISSION_STORE_H_
#include <set>
#include <string>
#include "base/values.h"
class PrefService;
namespace user_prefs {
class PrefRegistrySyncable;
}
namespace kumo::missions {
void Register(user_prefs::PrefRegistrySyncable* registry);
base::ListValue List(PrefService* prefs);
// URLs/titles supplied here must come from browser-owned tab metadata.
base::DictValue Save(PrefService* prefs,
                     const base::DictValue& fields,
                     base::ListValue sources);
base::DictValue Remove(PrefService* prefs, const std::string& id);
base::DictValue Read(PrefService* prefs,
                     const std::set<std::string>& grants,
                     std::string_view action,
                     const base::DictValue& params);
bool ValidRequest(std::string_view action, const base::DictValue& params);
}  // namespace kumo::missions
#endif
