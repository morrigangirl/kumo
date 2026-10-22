// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_STORE_KUMO_LEGACY_EXTENSION_H_
#define CHROME_BROWSER_KUMO_STORE_KUMO_LEGACY_EXTENSION_H_
class Profile;
namespace kumo {
// Retire only the old product registration after native preference migration
// has committed. The extension's storage is retained for recovery.
void RetireLegacyProductExtension(Profile* profile);
}  // namespace kumo
#endif
