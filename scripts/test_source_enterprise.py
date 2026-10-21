#!/usr/bin/env python3
"""Test-only cancellation, adjacent-source preservation and linker regressions."""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("kumo_source_enterprise", Path(__file__).with_name("source.py"))
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)
RELATIVE = "chrome/browser/enterprise/signin/profile_management_disclaimer_service.cc"
PINNED_ENTERPRISE_PREIMAGE = source.ENTERPRISE_PROFILE_PREIMAGE_SHA256
REAL_SOURCE = Path(os.environ.get("KUMO_SOURCE_TEST_TREE", Path(__file__).resolve().parents[1] /
                                  "build/source-156.0.8078.47/recipe/build/src"))

# The testing branch mirrors Chromium 156. The adjacent call sentinel below
# comes from unpatched upstream; the common patches already remove that actual
# production branch. It checks rewrite scope, not enabled Google account creation.
# The test-only factory is deliberately undefined in the compiled fixture.
TEST_BRANCH = """  if (profile_separation_policies_for_testing_.has_value() ||
      user_choice_for_testing_.has_value()) {
    CHECK_IS_TEST();
    state_->profile_creation_controller =
        ManagedProfileCreationController::CreateManagedProfileForTesting(
            &profile_.get(), GetExtendedAccountInfo(state_->account_id),
            *state_->access_point,
            base::BindOnce(&ProfileManagementDisclaimerService::
                               OnManagedProfileCreationResult,
                           weak_ptr_factory_.GetWeakPtr()),
            profile_separation_policies_for_testing_.value_or(
                std::move(profile_separation_policies)),
            user_choice_for_testing_);
    return;
  }
"""
ADJACENT_CALL_SENTINEL = """
  state_->profile_creation_controller =
      ManagedProfileCreationController::CreateManagedProfile(
          &profile_.get(), GetExtendedAccountInfo(state_->account_id),
          // The access point always has a value if the account_id is set.
          *state_->access_point,
          base::BindOnce(&ProfileManagementDisclaimerService::
                             OnManagedProfileCreationResult,
                         weak_ptr_factory_.GetWeakPtr()),
          std::move(profile_separation_policies));
"""
CANCEL_BRANCH = """  if (profile_separation_policies_for_testing_.has_value() ||
      user_choice_for_testing_.has_value()) {
    CHECK_IS_TEST();
    // KUMO_ENTERPRISE_PROFILE_COMPATIBILITY_V1
    // Browser-account profile creation is disabled by the pinned ungoogled
    // patches. Decline this test-only request through the existing reset path.
    state_->profile_to_continue_in = nullptr;
    Reset();
    return;
  }
"""
PREFIX = """// Owned fixture modeled on Chromium 156's separate method branches.
void ProfileManagementDisclaimerService::OnProfileSeparationPoliciesFetched(
    policy::ProfileSeparationPolicies profile_separation_policies) {
  if (!state_ || state_->account_id.empty()) {
    Reset();
    return;
  }
  CHECK(state_->access_point.has_value());

"""
BEFORE = PREFIX + TEST_BRANCH + ADJACENT_CALL_SENTINEL + "}\n"

HARNESS = r'''#include <cassert>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#define CHECK(value) assert(value)
#define CHECK_IS_TEST() (++test_checks)
int test_checks = 0;
int production_calls = 0;
namespace policy { using ProfileSeparationPolicies = int; }
namespace base {
template<class... Args> int BindOnce(Args&&...) { return 0; }
}
struct Profile {};
struct ProfileRef { Profile value; Profile& get() { return value; } };
struct Factory { int GetWeakPtr() { return 0; } };
struct ManagedProfileCreationController {
  static std::unique_ptr<int> CreateManagedProfileForTesting(
      Profile*, int, int, int, int, std::optional<int>);
  static std::unique_ptr<int> CreateManagedProfile(Profile*, int, int, int, int) {
    ++production_calls;
    return std::make_unique<int>(42);
  }
};
struct State {
  std::string account_id = "owned-fixture";
  std::optional<int> access_point = 7;
  Profile* profile_to_continue_in = reinterpret_cast<Profile*>(1);
  std::unique_ptr<int> profile_creation_controller;
};
struct ProfileManagementDisclaimerService {
  std::unique_ptr<State> state_ = std::make_unique<State>();
  std::optional<int> profile_separation_policies_for_testing_;
  std::optional<int> user_choice_for_testing_;
  ProfileRef profile_;
  Factory weak_ptr_factory_;
  int resets = 0;
  Profile* last_continuation = reinterpret_cast<Profile*>(1);
  int GetExtendedAccountInfo(const std::string&) { return 0; }
  void OnManagedProfileCreationResult(int) {}
  void Reset() {
    ++resets;
    if (state_) last_continuation = state_->profile_to_continue_in;
    state_.reset();
  }
  void OnProfileSeparationPoliciesFetched(policy::ProfileSeparationPolicies);
};
__METHOD__
int main() {
  ProfileManagementDisclaimerService normal;
  normal.OnProfileSeparationPoliciesFetched(9);
  assert(production_calls == 1 && test_checks == 0 && normal.resets == 0);
  assert(normal.state_ && normal.state_->profile_creation_controller);
  for (int flags : {1, 2, 3}) {
    ProfileManagementDisclaimerService testing;
    if (flags & 1) testing.profile_separation_policies_for_testing_ = 5;
    if (flags & 2) testing.user_choice_for_testing_ = 6;
    testing.OnProfileSeparationPoliciesFetched(9);
    assert(!testing.state_ && testing.resets == 1);
    assert(testing.last_continuation == nullptr && production_calls == 1);
  }
  assert(test_checks == 3);
}
'''


class EnterpriseCompatibility(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kumo-enterprise-156-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / RELATIVE
        self.path.parent.mkdir(parents=True)
        self.path.write_text(BEFORE)
        # Synthetic fixtures have their own exact whole-file preimage. The
        # production constant remains pinned to the separately audited source.
        self.pin = mock.patch.object(source, "ENTERPRISE_PROFILE_PREIMAGE_SHA256",
                                     hashlib.sha256(BEFORE.encode()).hexdigest())
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def test_only_testing_factory_branch_changes_adjacent_call_sentinel_is_preserved(self):
        source.enterprise_profile_compatibility(self.root)
        after = self.path.read_text()
        self.assertTrue(after.startswith(PREFIX))
        self.assertTrue(after.endswith(ADJACENT_CALL_SENTINEL + "}\n"))
        self.assertNotIn("CreateManagedProfileForTesting", after)
        self.assertEqual(after.count("CHECK_IS_TEST();"), 1)
        self.assertEqual(after.count("state_->profile_to_continue_in = nullptr;"), 1)
        self.assertEqual(after.count("KUMO_ENTERPRISE_PROFILE_COMPATIBILITY_V1"), 1)

    def test_drift_and_replay_leave_input_unchanged(self):
        self.path.write_text(BEFORE + "// changed\n")
        changed = self.path.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "preimage changed"):
            source.enterprise_profile_compatibility(self.root)
        self.assertEqual(self.path.read_bytes(), changed)
        self.path.write_text(BEFORE)
        source.enterprise_profile_compatibility(self.root)
        after = self.path.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "preimage changed"):
            source.enterprise_profile_compatibility(self.root)
        self.assertEqual(self.path.read_bytes(), after)

    def test_unexpected_branch_with_matching_fixture_hash_is_still_rejected(self):
        changed = BEFORE.replace("user_choice_for_testing_.has_value()", "different_test_flag_", 1)
        self.path.write_text(changed)
        with mock.patch.object(source, "ENTERPRISE_PROFILE_PREIMAGE_SHA256", hashlib.sha256(changed.encode()).hexdigest()):
            with self.assertRaisesRegex(RuntimeError, "testing branch changed"):
                source.enterprise_profile_compatibility(self.root)
        self.assertEqual(self.path.read_text(), changed)

    @unittest.skipUnless(shutil.which("clang++"), "A C++ compiler is required for the small offline fixture")
    def test_removed_factory_no_longer_links_and_cancellation_and_adjacent_sentinel_execute(self):
        source.enterprise_profile_compatibility(self.root)
        after = self.path.read_text()
        for label, method in (("original", BEFORE), ("patched", after)):
            cpp = self.root / (label + ".cc")
            executable = self.root / label
            cpp.write_text(HARNESS.replace("__METHOD__", method))
            result = subprocess.run([shutil.which("clang++"), "-std=c++20", "-O0", str(cpp), "-o", str(executable)],
                                    capture_output=True, text=True, timeout=30)
            if label == "original":
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("CreateManagedProfileForTesting", result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                subprocess.run([str(executable)], check=True, capture_output=True, timeout=10)

    def test_actual_postcommon_source_keeps_production_account_creation_removed(self):
        path = REAL_SOURCE / RELATIVE
        if not path.is_file():
            self.skipTest("The pinned post-common Chromium 156 source is unavailable")
        before = path.read_text()
        if "KUMO_ENTERPRISE_PROFILE_COMPATIBILITY_V1" in before:
            self.assertEqual(before.count(CANCEL_BRANCH), 1)
            before = before.replace(CANCEL_BRANCH, TEST_BRANCH, 1)
        self.assertEqual(hashlib.sha256(before.encode()).hexdigest(), PINNED_ENTERPRISE_PREIMAGE)
        self.assertNotIn("CreateManagedProfile(", before)
        self.assertEqual(before.count("CreateManagedProfileForTesting("), 1)
        copied = self.root / "actual-copy" / RELATIVE
        copied.parent.mkdir(parents=True)
        copied.write_text(before)
        with mock.patch.object(source, "ENTERPRISE_PROFILE_PREIMAGE_SHA256", PINNED_ENTERPRISE_PREIMAGE):
            source.enterprise_profile_compatibility(self.root / "actual-copy")
        after = copied.read_text()
        self.assertNotIn("CreateManagedProfile(", after)
        self.assertNotIn("CreateManagedProfileForTesting(", after)
        self.assertEqual(after.count(CANCEL_BRANCH), 1)
        self.assertEqual(after.replace(CANCEL_BRANCH, TEST_BRANCH, 1), before)


if __name__ == "__main__":
    unittest.main()
