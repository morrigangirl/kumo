// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_NETWORK_KUMO_NETWORK_ADMISSION_H_
#define CHROME_BROWSER_KUMO_NETWORK_KUMO_NETWORK_ADMISSION_H_
#include <optional>
#include "base/functional/callback.h"
#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
class GURL;
class Profile;
namespace content { class BrowserContext; }
namespace network { class URLLoaderFactoryBuilder; }
namespace network::mojom { class URLLoaderFactoryOverride; }
namespace kumo {
class KumoProtectionService;
// No value means initialization is pending. False rejects; true admits. Kept
// separate from transport creation so a timeout can never accidentally connect.
using AdmissionProbe = base::RepeatingCallback<std::optional<bool>()>;
void AwaitNetworkAdmission(AdmissionProbe probe,
                           base::OnceCallback<void(bool)> callback,
                           base::TimeDelta timeout);
void AllowNetworkConnection(Profile* profile, const GURL& target,
                               base::OnceCallback<void(bool)> callback);
void AllowNetworkConnection(base::WeakPtr<content::BrowserContext> context,
                            base::WeakPtr<KumoProtectionService> service,
                            const GURL& target,
                            base::OnceCallback<void(bool)> callback);
void ProxyDomainURLLoaderFactory(Profile* profile,
                                 network::URLLoaderFactoryBuilder& builder,
                                 network::mojom::URLLoaderFactoryOverride*
                                     factory_override);
}  // namespace kumo
#endif
