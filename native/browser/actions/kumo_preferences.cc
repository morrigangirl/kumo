// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/actions/kumo_preferences.h"
#include "chrome/browser/profiles/profile.h"

namespace kumo::preferences {
base::DictValue Get(Profile* profile) {
  return Get(profile->GetPrefs());
}
base::DictValue SetPartial(Profile* profile, const base::DictValue& input) {
  return SetPartial(profile->GetPrefs(), input);
}
bool ImportLegacy(Profile* profile, const base::DictValue& input) {
  return ImportLegacy(profile->GetPrefs(), input);
}
}  // namespace kumo::preferences
