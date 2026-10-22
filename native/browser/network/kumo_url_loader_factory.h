// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_NETWORK_KUMO_URL_LOADER_FACTORY_H_
#define CHROME_BROWSER_KUMO_NETWORK_KUMO_URL_LOADER_FACTORY_H_

#include "base/functional/callback.h"

class GURL;
namespace network { class URLLoaderFactoryBuilder; }
namespace network::mojom { class URLLoaderFactoryOverride; }

namespace kumo {
// Called on the owning sequence. The callback must settle once, including
// unavailable policy/context cases. No request body or headers are inspected.
using DomainAdmission = base::RepeatingCallback<void(
    const GURL&, base::OnceCallback<void(bool)>)>;

// Append after other request-rewriting factories, before the network terminal.
// Every clone retains this gate. Requests own their downstream connection and
// remain valid if their original factory receiver closes.
void AppendDomainURLLoaderFactory(network::URLLoaderFactoryBuilder& builder,
                                 DomainAdmission admission,
                                 network::mojom::URLLoaderFactoryOverride*
                                     factory_override = nullptr);
}  // namespace kumo

#endif
