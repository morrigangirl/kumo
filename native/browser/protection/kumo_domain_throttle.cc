// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/protection/kumo_protection_service.h"

#include "base/functional/bind.h"
#include "base/memory/weak_ptr.h"
#include "base/timer/timer.h"
#include "net/base/net_errors.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/resource_request.h"
#include "third_party/blink/public/common/loader/url_loader_throttle.h"
#include "url/gurl.h"

namespace kumo {
namespace {
class DomainThrottle final : public blink::URLLoaderThrottle {
 public:
  explicit DomainThrottle(base::WeakPtr<KumoProtectionService> service)
      : service_(std::move(service)) {}
  void WillStartRequest(network::ResourceRequest* request, bool* defer) override {
    CheckOrDefer(request->url, defer);
  }
  void WillRedirectRequest(net::RedirectInfo* redirect,
      const network::mojom::URLResponseHead&, bool* defer,
      network::HttpRequestHeadersUpdateParams*) override {
    // Inspect the destination before following it. A benign first hop never
    // exempts a listed redirect destination or any of its subdomains.
    CheckOrDefer(redirect->new_url, defer);
  }
  const char* NameForLoggingWillStartRequest() override { return "KumoDomainProtection"; }
 private:
  void CheckOrDefer(const GURL& url, bool* defer) {
    if (!service_ || !(url.SchemeIsHTTPOrHTTPS() || url.SchemeIsWSOrWSS())) return;
    if (service_->DomainsReady()) {
      if (service_->ShouldBlock(url))
        delegate_->CancelWithError(net::ERR_BLOCKED_BY_CLIENT, "KumoDangerousDomain");
      return;
    }
    pending_ = url; *defer = true;
    // Disk/migration initialization is bounded. An unavailable list is exposed
    // as unavailable in Settings; it never becomes a false safe-site verdict.
    timeout_.Start(FROM_HERE, base::Seconds(15), this, &DomainThrottle::Ready);
    service_->WhenDomainsReady(base::BindOnce(&DomainThrottle::Ready, weak_.GetWeakPtr()));
  }
  void Ready() {
    if (!pending_.is_valid()) return;
    timeout_.Stop();
    const bool blocked = service_ && service_->ShouldBlock(pending_);
    pending_ = GURL();
    if (blocked) delegate_->CancelWithError(net::ERR_BLOCKED_BY_CLIENT, "KumoDangerousDomain");
    else delegate_->Resume();
  }
  base::WeakPtr<KumoProtectionService> service_;
  GURL pending_;
  base::OneShotTimer timeout_;
  base::WeakPtrFactory<DomainThrottle> weak_{this};
};
}  // namespace
std::unique_ptr<blink::URLLoaderThrottle> CreateProtectionThrottle(Profile* profile) {
  return std::make_unique<DomainThrottle>(KumoProtectionService::Get(profile)->GetWeakPtr());
}
}  // namespace kumo
