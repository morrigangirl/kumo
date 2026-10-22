// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/network/kumo_network_admission.h"
#include "base/functional/bind.h"
#include "chrome/browser/kumo/protection/kumo_protection_service.h"
#include "chrome/browser/profiles/profile.h"
#include "url/gurl.h"

namespace kumo {
void AllowNetworkConnection(Profile* profile, const GURL& target,
                               base::OnceCallback<void(bool)> callback) {
  auto* service = KumoProtectionService::Get(profile);
  AwaitNetworkAdmission(base::BindRepeating(
      [](base::WeakPtr<KumoProtectionService> service, const GURL& target)
          -> std::optional<bool> {
        if (!service) return false;
        if (!service->DomainsReady()) return std::nullopt;
        return !service->ShouldBlock(target);
      }, service->GetWeakPtr(), target), std::move(callback), base::Seconds(15));
}
}  // namespace kumo
