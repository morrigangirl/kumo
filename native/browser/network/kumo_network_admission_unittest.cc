// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/network/kumo_network_admission.h"
#include "base/functional/bind.h"
#include "base/test/task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
namespace kumo {
namespace {
class KumoNetworkAdmissionTest : public testing::Test {
 protected:
  void Begin() {
    AwaitNetworkAdmission(base::BindRepeating(
        [](std::optional<bool>* value) { return *value; }, &probe_),
        base::BindOnce([](int* calls, bool* result, bool allowed) {
          ++*calls; *result = allowed;
        }, &calls_, &allowed_), base::Seconds(15));
  }
  base::test::TaskEnvironment tasks_{base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  std::optional<bool> probe_;
  int calls_ = 0;
  bool allowed_ = false;
};
TEST_F(KumoNetworkAdmissionTest, AllowsReadyLegitimateConnectionExactlyOnce) {
  probe_ = true; Begin(); EXPECT_EQ(calls_, 1); EXPECT_TRUE(allowed_);
  tasks_.FastForwardBy(base::Seconds(20)); EXPECT_EQ(calls_, 1);
}
TEST_F(KumoNetworkAdmissionTest, BlocksListedDomainWithoutOpeningTransport) {
  probe_ = false; Begin(); EXPECT_EQ(calls_, 1); EXPECT_FALSE(allowed_);
}
TEST_F(KumoNetworkAdmissionTest, DefersUntilDomainInitializationFinishes) {
  Begin(); EXPECT_EQ(calls_, 0);
  tasks_.FastForwardBy(base::Milliseconds(100)); EXPECT_EQ(calls_, 0);
  probe_ = true; tasks_.FastForwardBy(base::Milliseconds(50));
  EXPECT_EQ(calls_, 1); EXPECT_TRUE(allowed_);
}
TEST_F(KumoNetworkAdmissionTest, InitializationTimeoutRejectsAndNeverLaterAdmits) {
  Begin(); tasks_.FastForwardBy(base::Seconds(15));
  EXPECT_EQ(calls_, 1); EXPECT_FALSE(allowed_);
  probe_ = true; tasks_.FastForwardBy(base::Seconds(30)); EXPECT_EQ(calls_, 1);
}
TEST_F(KumoNetworkAdmissionTest, DestroyedBrowserContextProbeRejectsPendingConnection) {
  Begin(); probe_ = false; tasks_.FastForwardBy(base::Milliseconds(50));
  EXPECT_EQ(calls_, 1); EXPECT_FALSE(allowed_);
}
}  // namespace
}  // namespace kumo
