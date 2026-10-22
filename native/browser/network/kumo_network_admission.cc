// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/network/kumo_network_admission.h"
#include "base/functional/bind.h"
#include "chrome/browser/kumo/network/kumo_url_loader_factory.h"
#include "chrome/browser/kumo/protection/kumo_protection_service.h"
#include "chrome/browser/profiles/profile.h"
#include "content/public/browser/browser_context.h"
#include "url/gurl.h"

namespace kumo {
void AllowNetworkConnection(Profile* profile, const GURL& target,
                               base::OnceCallback<void(bool)> callback) {
  auto* service = KumoProtectionService::Get(profile);
  AllowNetworkConnection(profile->GetWeakPtr(), service->GetWeakPtr(), target,
                         std::move(callback));
}
void AllowNetworkConnection(base::WeakPtr<content::BrowserContext> context,
                            base::WeakPtr<KumoProtectionService> service,
                            const GURL& target,
                            base::OnceCallback<void(bool)> callback) {
  AwaitNetworkAdmission(base::BindRepeating(
      [](base::WeakPtr<content::BrowserContext> context,
          base::WeakPtr<KumoProtectionService> service, const GURL& target)
          -> std::optional<bool> {
        if (!context || !service) return false;
        if (!service->DomainsReady()) return std::nullopt;
        return !service->ShouldBlock(target);
      }, std::move(context), std::move(service), target), std::move(callback),
      base::Seconds(15));
}
void ProxyDomainURLLoaderFactory(Profile* profile,
                                 network::URLLoaderFactoryBuilder& builder,
                                 network::mojom::URLLoaderFactoryOverride*
                                     factory_override) {
  auto* service = KumoProtectionService::Get(profile);
  AppendDomainURLLoaderFactory(builder, base::BindRepeating(
      [](base::WeakPtr<content::BrowserContext> context,
          base::WeakPtr<KumoProtectionService> service, const GURL& target,
          base::OnceCallback<void(bool)> callback) {
        AllowNetworkConnection(std::move(context), std::move(service), target,
                               std::move(callback));
      }, profile->GetWeakPtr(), service->GetWeakPtr()), factory_override);
}
}  // namespace kumo
