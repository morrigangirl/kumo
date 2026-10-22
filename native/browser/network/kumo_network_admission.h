// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_NETWORK_KUMO_NETWORK_ADMISSION_H_
#define CHROME_BROWSER_KUMO_NETWORK_KUMO_NETWORK_ADMISSION_H_
#include <optional>
#include "base/functional/callback.h"
#include "base/time/time.h"
class GURL;
class Profile;
namespace kumo {
// No value means initialization is pending. False rejects; true admits. Kept
// separate from transport creation so a timeout can never accidentally connect.
using AdmissionProbe = base::RepeatingCallback<std::optional<bool>()>;
void AwaitNetworkAdmission(AdmissionProbe probe,
                           base::OnceCallback<void(bool)> callback,
                           base::TimeDelta timeout);
void AllowNetworkConnection(Profile* profile, const GURL& target,
                               base::OnceCallback<void(bool)> callback);
}  // namespace kumo
#endif
