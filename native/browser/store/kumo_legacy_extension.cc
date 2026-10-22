// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/store/kumo_legacy_extension.h"

#include "chrome/browser/kumo/protection/kumo_protection_service.h"
#include "chrome/browser/profiles/profile.h"
#include "components/prefs/pref_service.h"
#include "extensions/browser/extension_prefs.h"

namespace kumo {
void RetireLegacyProductExtension(Profile* profile) {
  if (!profile || profile->IsOffTheRecord() || profile->IsGuestSession())
    return;
  auto* protection = KumoProtectionService::Get(profile);
  if (!protection || !protection->MigrationComplete())
    return;
  // DeleteExtensionPrefs removes only its registration/pref-value map. Never
  // invoke extension uninstall or StorageFrontend::DeleteStorageSoon here.
  auto* prefs = extensions::ExtensionPrefs::Get(profile);
  if (prefs) {
    prefs->DeleteExtensionPrefs("eldkgppmnhligdekahicdcdndcoongio");
    profile->GetPrefs()->CommitPendingWrite();
  }
}
}  // namespace kumo
