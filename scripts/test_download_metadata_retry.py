#!/usr/bin/env python3
"""Exercise the actual native retry policy with owned files and fault injection.

The C++ fixture compiles the marked production block verbatim. Its callback stands
in for a complete scan attempt; no test callback or configurable host ships in
the browser. Actual browser/helper rescans are verified separately.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "native/chromium/kumo_download_guard.mm"
STRICT_SAMEFILE_SHA256 = "1dd11060878062bf39ffb488f4fa004e820819fc6913863ab8038a2250459322"

FIXTURE = r'''
#include <sys/stat.h>
#include <sys/xattr.h>
#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <unistd.h>
#include <cassert>
#include <cstdio>
#include <functional>
#include <optional>
#include <string>
#include <vector>

// PRODUCTION_POLICY

using D = ScanAttemptDisposition;
std::string FixtureSHA256(const std::string& bytes) {
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  assert(CC_SHA256(bytes.data(), static_cast<CC_LONG>(bytes.size()), digest));
  const char hex[] = "0123456789abcdef";
  std::string result;
  for (unsigned char byte : digest) {
    result.push_back(hex[byte >> 4]);
    result.push_back(hex[byte & 15]);
  }
  return result;
}
struct OwnedFile {
  char path[64] = "/private/tmp/kumo-metadata-retry-XXXXXX";
  int fd = -1;
  int metadata_version = 0;
  OwnedFile() {
    int writer = mkstemp(path);
    assert(writer >= 0);
    const std::string value = "Kumo inert antivirus browser QA fixture.\n";
    assert(write(writer, value.data(), value.size()) == 41);
    assert(close(writer) == 0);
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0);
  }
  ~OwnedFile() { close(fd); unlink(path); }
  struct stat state() const {
    struct stat value;
    assert(fstat(fd, &value) == 0);
    return value;
  }
  struct stat named() const {
    struct stat value;
    assert(lstat(path, &value) == 0);
    return value;
  }
  std::string snapshot() const {
    char buffer[128];
    const ssize_t bytes = pread(fd, buffer, sizeof(buffer), 0);
    assert(bytes >= 0);
    return std::string(buffer, static_cast<size_t>(bytes));
  }
  void metadata_change() {
    const auto before = state();
    usleep(2000);
    ++metadata_version;
    assert(setxattr(path, "app.kumo.qa.metadata-retry", &metadata_version,
                    sizeof(metadata_version), 0, 0) == 0);
    const auto after = state();
    assert(SameMetadataExceptChangeTime(before, after));
    assert(!SameFile(before, after));
  }
  void content_change() {
    const std::string original = snapshot();
    std::string changed = original;
    changed[0] = 'X';
    const auto before = state();
    int writer = open(path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(writer >= 0);
    assert(pwrite(writer, changed.data(), changed.size(), 0) == 41);
    const struct timespec restored_times[] = {before.st_atimespec,
                                             before.st_mtimespec};
    assert(futimens(writer, restored_times) == 0);
    close(writer);
    assert(SameMetadataExceptChangeTime(before, state()));
    assert(snapshot() != original);
  }
};

struct RunOptions {
  bool repeat_metadata = false;
  bool change_before_snapshot = false;
  bool change_before_helper = false;
  bool cancel_retry = false;
  bool expire_retry = false;
  bool change_content = false;
  bool change_content_after_first_posthash = false;
  bool browser_hash_mismatch = false;
  std::string second_verdict = "no-known-malware";
};
struct RunResult { D disposition; int attempts; int snapshots; int helpers; };

RunResult RunOwnedSequence(const RunOptions& options) {
  OwnedFile file;
  std::optional<struct stat> baseline;
  std::string first_snapshot_sha;
  int attempts = 0, snapshots = 0, helpers = 0;
  const auto disposition = RunBoundedMetadataScan([&](bool retry) {
    ++attempts;
    if (retry && (options.cancel_retry || options.expire_retry))
      return D::kReject;
    if (retry && options.change_before_snapshot)
      file.metadata_change();
    const auto before = file.state();
    const auto named = file.named();
    if (!AtMetadataRetryBaseline(before, before, named) ||
        (retry && (!baseline || !AtMetadataRetryBaseline(*baseline, before, named))))
      return D::kReject;
    const std::string snapshot = file.snapshot();
    ++snapshots;
    const std::string snapshot_sha = FixtureSHA256(snapshot);
    if (!SnapshotHashMatches(snapshot_sha, "", first_snapshot_sha))
      return D::kReject;
    if (first_snapshot_sha.empty())
      first_snapshot_sha = snapshot_sha;
    if (retry && options.change_before_helper)
      file.metadata_change();
    if (!AtMetadataRetryBaseline(before, file.state(), file.named()))
      return D::kReject;
    ++helpers;
    if (!retry || options.repeat_metadata)
      file.metadata_change();
    if (options.change_content)
      file.content_change();
    const std::string posthash = FixtureSHA256(file.snapshot());
    if (!retry && options.change_content_after_first_posthash) {
      assert(posthash == snapshot_sha);
      file.content_change();  // Exact race: after hash A, before poststat B.
      assert(SameMetadataExceptChangeTime(before, file.state()));
    }
    const auto after = file.state();
    const auto result = ClassifyScanAttempt(
        retry ? options.second_verdict : "no-known-malware",
        snapshot_sha == posthash && !options.browser_hash_mismatch,
        true, before, after, file.named());
    if (result == D::kRetryMetadata)
      baseline = after;
    return result;
  });
  return {disposition, attempts, snapshots, helpers};
}

int main(int argc, char** argv) {
  assert(argc == 2);
  const std::string scenario = argv[1];
  if (scenario == "single_metadata_update_rescans") {
    const auto result = RunOwnedSequence({});
    assert(result.disposition == D::kClean);
    assert(result.attempts == 2 && result.snapshots == 2 && result.helpers == 2);
  } else if (scenario == "posthash_before_poststat_content_change_without_browser_hash_fails") {
    RunOptions options; options.change_content_after_first_posthash = true;
    const auto result = RunOwnedSequence(options);
    assert(result.disposition == D::kReject);
    assert(result.attempts == 2 && result.snapshots == 2 && result.helpers == 1);
  } else if (scenario == "second_metadata_update_fails") {
    RunOptions options; options.repeat_metadata = true;
    const auto result = RunOwnedSequence(options);
    assert(result.disposition == D::kReject);
    assert(result.attempts == 2 && result.snapshots == 2 && result.helpers == 2);
  } else if (scenario == "baseline_drift_before_snapshot_fails") {
    RunOptions options; options.change_before_snapshot = true;
    const auto result = RunOwnedSequence(options);
    assert(result.disposition == D::kReject);
    assert(result.attempts == 2 && result.snapshots == 1 && result.helpers == 1);
  } else if (scenario == "baseline_drift_before_helper_fails") {
    RunOptions options; options.change_before_helper = true;
    const auto result = RunOwnedSequence(options);
    assert(result.disposition == D::kReject);
    assert(result.attempts == 2 && result.snapshots == 2 && result.helpers == 1);
  } else if (scenario == "cancel_or_deadline_stops_retry") {
    for (bool cancel : {false, true}) {
      RunOptions options; options.cancel_retry = cancel; options.expire_retry = !cancel;
      const auto result = RunOwnedSequence(options);
      assert(result.disposition == D::kReject);
      assert(result.attempts == 2 && result.snapshots == 1 && result.helpers == 1);
    }
  } else if (scenario == "same_size_restored_mtime_content_or_browser_hash_never_retries") {
    for (bool content : {false, true}) {
      RunOptions options; options.change_content = content; options.browser_hash_mismatch = !content;
      const auto result = RunOwnedSequence(options);
      assert(result.disposition == D::kReject);
      assert(result.attempts == 1 && result.snapshots == 1 && result.helpers == 1);
    }
  } else if (scenario == "second_nonclean_result_cannot_release") {
    for (const std::string verdict : {"malware", "unavailable", "limited", "invalid"}) {
      RunOptions options; options.second_verdict = verdict;
      const auto result = RunOwnedSequence(options);
      assert(result.disposition == (verdict == "malware" ? D::kInfected : D::kReject));
      assert(result.attempts == 2 && result.snapshots == 2 && result.helpers == 2);
    }
  } else if (scenario == "first_nonclean_result_never_retries") {
    OwnedFile file; const auto before = file.state(); file.metadata_change(); const auto after = file.state();
    for (const std::string verdict : {"malware", "unavailable", "limited", "invalid"}) {
      int attempts = 0;
      const auto result = RunBoundedMetadataScan([&](bool retry) {
        assert(!retry); ++attempts;
        return ClassifyScanAttempt(verdict, true, true, before, after, after);
      });
      assert(result == D::kReject && attempts == 1);
    }
  } else if (scenario == "unchanged_clean_or_malware_scan_runs_once") {
    OwnedFile file; const auto state = file.state();
    for (const std::string verdict : {"no-known-malware", "malware"}) {
      int attempts = 0;
      const auto result = RunBoundedMetadataScan([&](bool retry) {
        assert(!retry); ++attempts;
        return ClassifyScanAttempt(verdict, true, true, state, state, state);
      });
      assert(result == (verdict == "malware" ? D::kInfected : D::kClean));
      assert(attempts == 1);
    }
  } else if (scenario == "identity_permissions_and_mtime_drift_never_retry") {
    OwnedFile file; const auto before = file.state(); file.metadata_change(); const auto after = file.state();
    const std::vector<std::function<void(struct stat&)>> mutations = {
      [](auto& s) { ++s.st_dev; }, [](auto& s) { ++s.st_ino; },
      [](auto& s) { ++s.st_uid; }, [](auto& s) { ++s.st_gid; },
      [](auto& s) { s.st_mode ^= S_IXUSR; }, [](auto& s) { s.st_flags ^= UF_NODUMP; },
      [](auto& s) { s.st_nlink = 2; }, [](auto& s) { ++s.st_size; },
      [](auto& s) { ++s.st_mtimespec.tv_sec; }, [](auto& s) { s.st_mtimespec.tv_nsec ^= 1; },
      [](auto& s) { s.st_mode = (s.st_mode & ~S_IFMT) | S_IFLNK; },
    };
    for (const auto& mutate : mutations) {
      auto changed = after; mutate(changed); int attempts = 0;
      const auto result = RunBoundedMetadataScan([&](bool retry) {
        assert(!retry); ++attempts;
        return ClassifyScanAttempt("no-known-malware", true, true, before, changed, changed);
      });
      assert(result == D::kReject && attempts == 1);
      assert(!AtMetadataRetryBaseline(after, changed, changed));
    }
  } else if (scenario == "named_path_and_fd_must_agree_strictly") {
    OwnedFile file; const auto before = file.state(); file.metadata_change(); const auto after = file.state();
    auto named = after; named.st_ctimespec.tv_nsec ^= 1;
    assert(ClassifyScanAttempt("no-known-malware", true, true, before, after, named) == D::kReject);
    named = after; ++named.st_ino;
    assert(ClassifyScanAttempt("no-known-malware", true, true, before, after, named) == D::kReject);
  } else if (scenario == "inactive_or_inexact_attempt_cannot_retry") {
    OwnedFile file; const auto before = file.state(); file.metadata_change(); const auto after = file.state();
    assert(ClassifyScanAttempt("no-known-malware", true, false, before, after, after) == D::kReject);
    assert(ClassifyScanAttempt("no-known-malware", false, true, before, after, after) == D::kReject);
  } else {
    return 64;
  }
  std::puts(("PASS " + scenario).c_str());
}
'''


class MetadataRetryTests(unittest.TestCase):
    def test_strict_samefile_is_unchanged(self):
        source = GUARD.read_text()
        start = source.index("bool SameFile(")
        end = source.index("\n}\n", start) + 3
        self.assertEqual(hashlib.sha256(source[start:end].encode()).hexdigest(),
                         STRICT_SAMEFILE_SHA256)

    @unittest.skipUnless(sys.platform == "darwin", "Requires actual macOS stat/xattr semantics")
    def test_actual_production_policy_native_scenarios(self):
        source = GUARD.read_text()
        begin = "// BEGIN KUMO_METADATA_RETRY_POLICY\n"
        end = "// END KUMO_METADATA_RETRY_POLICY"
        self.assertEqual(source.count(begin), 1)
        self.assertEqual(source.count(end), 1)
        policy = source.split(begin, 1)[1].split(end, 1)[0]
        compiler = os.environ.get("KUMO_METADATA_RETRY_CXX", "/usr/bin/clang++")
        sdk = subprocess.run(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
                             check=True, capture_output=True, text=True).stdout.strip()
        scenarios = [
            "single_metadata_update_rescans", "second_metadata_update_fails",
            "posthash_before_poststat_content_change_without_browser_hash_fails",
            "baseline_drift_before_snapshot_fails", "baseline_drift_before_helper_fails",
            "cancel_or_deadline_stops_retry", "same_size_restored_mtime_content_or_browser_hash_never_retries",
            "second_nonclean_result_cannot_release", "first_nonclean_result_never_retries",
            "unchanged_clean_or_malware_scan_runs_once",
            "identity_permissions_and_mtime_drift_never_retry",
            "named_path_and_fd_must_agree_strictly", "inactive_or_inexact_attempt_cannot_retry",
        ]
        with tempfile.TemporaryDirectory(prefix="kumo-metadata-retry-test-") as directory:
            cpp = Path(directory) / "fixture.cc"
            binary = Path(directory) / "fixture"
            cpp.write_text(FIXTURE.replace("// PRODUCTION_POLICY", policy, 1))
            compiled = subprocess.run([compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror",
                                       "-isysroot", sdk, str(cpp), "-o", str(binary)],
                                      capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            for scenario in scenarios:
                with self.subTest(scenario=scenario):
                    result = subprocess.run([str(binary), scenario], capture_output=True,
                                            text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stdout.strip(), "PASS " + scenario)


if __name__ == "__main__":
    unittest.main()
