// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/network/kumo_network_admission.h"
#include <algorithm>
#include "base/functional/bind.h"
#include "base/memory/ref_counted.h"
#include "base/task/single_thread_task_runner.h"

namespace kumo {
namespace {
class Admission final : public base::RefCounted<Admission> {
 public:
  Admission(AdmissionProbe probe, base::OnceCallback<void(bool)> callback,
            base::TimeDelta timeout)
      : probe_(std::move(probe)), callback_(std::move(callback)),
        deadline_(base::TimeTicks::Now() + timeout) {}
  void Poll() {
    const auto remaining = deadline_ - base::TimeTicks::Now();
    if (remaining <= base::TimeDelta()) {
      std::move(callback_).Run(false);
      return;
    }
    if (const auto result = probe_.Run()) {
      std::move(callback_).Run(*result);
      return;
    }
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE, base::BindOnce(&Admission::Poll, base::WrapRefCounted(this)),
        std::min(base::Milliseconds(50), remaining));
  }
 private:
  friend class base::RefCounted<Admission>;
  ~Admission() = default;
  AdmissionProbe probe_;
  base::OnceCallback<void(bool)> callback_;
  base::TimeTicks deadline_;
};
}  // namespace
void AwaitNetworkAdmission(AdmissionProbe probe,
                           base::OnceCallback<void(bool)> callback,
                           base::TimeDelta timeout) {
  base::MakeRefCounted<Admission>(std::move(probe), std::move(callback), timeout)->Poll();
}
}  // namespace kumo
