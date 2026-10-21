// Copyright 2026 Kumo Authors. Licensed under the MIT license.
// KUMO_DOWNLOAD_MALWARE_GUARD_V1
// Normal downloads remain incomplete until a descriptor-bound local scan passes.
// No URL, profile/account data, user-selected executable or browser message is
// forwarded. The .crdownload completion hold is not an OS access-control boundary
// against another process running as this user.

#include "chrome/browser/download/kumo_download_guard.h"

#include <Security/Security.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/apple/bundle_locations.h"
#include "base/apple/scoped_cftyperef.h"
#include "base/check.h"
#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/no_destructor.h"
#include "base/posix/eintr_wrapper.h"
#include "base/process/kill.h"
#include "base/process/launch.h"
#include "base/process/process.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "base/values.h"
#include "chrome/browser/download/download_completion_blocker.h"
#include "components/download/public/common/download_danger_type.h"
#include "components/download/public/common/download_interrupt_reasons.h"
#include "components/download/public/common/download_item.h"
#include "content/public/browser/browser_thread.h"
#include "crypto/hash.h"

namespace kumo {
namespace {

constexpr int64_t kMaxScanBytes = 1024LL * 1024 * 1024;
constexpr size_t kMaxProtocolBytes = 8192;
constexpr size_t kMaximumPendingScans = 9;  // One active, eight queued.
constexpr base::TimeDelta kScanTimeout = base::Seconds(180);
const char kGuardUserDataKey = 0;
// UI-thread only; a single sequenced worker also bounds native scanner memory.
size_t g_pending_scans = 0;

struct ScanControl {
  std::atomic_bool cancelled{false};
};

struct ScanInput {
  base::FilePath path;
  std::string guid;
  std::string browser_hash;
  int64_t bytes = -1;
  base::TimeTicks deadline;
};

struct ScanResult {
  bool clean = false;
  bool infected = false;
  std::string guid;
  std::string sha256;
  int64_t bytes = -1;
};

bool WithinDeadline(const ScanInput& input, const ScanControl& control) {
  return !control.cancelled.load(std::memory_order_relaxed) &&
         base::TimeTicks::Now() < input.deadline;
}

// BEGIN KUMO_METADATA_RETRY_POLICY
bool SameFile(const struct stat& a, const struct stat& b) {
  return S_ISREG(a.st_mode) && S_ISREG(b.st_mode) && a.st_dev == b.st_dev &&
         a.st_ino == b.st_ino && a.st_size == b.st_size && a.st_uid == b.st_uid &&
         a.st_nlink == 1 && b.st_nlink == 1 &&
         a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec &&
         a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
         a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec &&
         a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec;
}

// OS metadata can update ctime while a completed download is held for scanning.
// Never release such a generation directly: only an otherwise identical file
// may receive one fresh snapshot and complete scan within the original budget.
bool SameMetadataExceptChangeTime(const struct stat& a, const struct stat& b) {
  return S_ISREG(a.st_mode) && S_ISREG(b.st_mode) && a.st_dev == b.st_dev &&
         a.st_ino == b.st_ino && a.st_uid == b.st_uid && a.st_gid == b.st_gid &&
         a.st_mode == b.st_mode && a.st_flags == b.st_flags &&
         a.st_nlink == 1 && b.st_nlink == 1 && a.st_size == b.st_size &&
         a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec &&
         a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec;
}

bool AtMetadataRetryBaseline(const struct stat& baseline,
                             const struct stat& descriptor,
                             const struct stat& named) {
  return SameFile(baseline, descriptor) && SameFile(baseline, named) &&
         SameMetadataExceptChangeTime(baseline, descriptor) &&
         SameMetadataExceptChangeTime(baseline, named);
}

enum class ScanAttemptDisposition { kReject, kClean, kInfected, kRetryMetadata };

bool SnapshotHashMatches(const std::string& actual,
                         const std::string& browser_hash,
                         const std::string& first_snapshot_sha) {
  return actual.size() == 64 &&
         (browser_hash.empty() || actual == browser_hash) &&
         (first_snapshot_sha.empty() || actual == first_snapshot_sha);
}

ScanAttemptDisposition ClassifyScanAttempt(
    const std::string& verdict,
    bool exact_content,
    bool active,
    const struct stat& before,
    const struct stat& after,
    const struct stat& named_after) {
  if (!exact_content || !active)
    return ScanAttemptDisposition::kReject;
  if (SameFile(before, after) && SameFile(before, named_after)) {
    if (verdict == "no-known-malware")
      return ScanAttemptDisposition::kClean;
    return verdict == "malware" ? ScanAttemptDisposition::kInfected
                                : ScanAttemptDisposition::kReject;
  }
  if (verdict != "no-known-malware" ||
      !SameMetadataExceptChangeTime(before, after) ||
      !SameMetadataExceptChangeTime(before, named_after) ||
      !AtMetadataRetryBaseline(after, after, named_after)) {
    return ScanAttemptDisposition::kReject;
  }
  return ScanAttemptDisposition::kRetryMetadata;
}

template <typename Attempt>
ScanAttemptDisposition RunBoundedMetadataScan(Attempt attempt) {
  auto disposition = attempt(false);
  if (disposition != ScanAttemptDisposition::kRetryMetadata)
    return disposition;
  disposition = attempt(true);
  return disposition == ScanAttemptDisposition::kRetryMetadata
             ? ScanAttemptDisposition::kReject
             : disposition;
}
// END KUMO_METADATA_RETRY_POLICY

std::optional<std::string> HashDescriptor(int descriptor,
                                         const ScanInput& input,
                                         const ScanControl& control,
                                         int snapshot_writer = -1) {
  crypto::hash::Hasher hasher(crypto::hash::kSha256);
  std::array<uint8_t, 256 * 1024> buffer;
  int64_t offset = 0;
  while (offset < input.bytes) {
    if (!WithinDeadline(input, control))
      return std::nullopt;
    size_t wanted = std::min(static_cast<int64_t>(buffer.size()),
                             input.bytes - offset);
    ssize_t received = HANDLE_EINTR(
        pread(descriptor, buffer.data(), wanted, static_cast<off_t>(offset)));
    if (received <= 0)
      return std::nullopt;
    ssize_t written = 0;
    while (snapshot_writer >= 0 && written < received) {
      if (!WithinDeadline(input, control))
        return std::nullopt;
      const auto remaining = base::span(buffer).subspan(
          static_cast<size_t>(written), static_cast<size_t>(received - written));
      ssize_t count = HANDLE_EINTR(write(snapshot_writer, remaining.data(),
                                        remaining.size()));
      if (count <= 0)
        return std::nullopt;
      written += count;
    }
    hasher.Update(base::span(buffer).first(static_cast<size_t>(received)));
    offset += received;
  }
  // An independently checked stat and a read at the bound reject appended data.
  uint8_t extra;
  if (!WithinDeadline(input, control) ||
      HANDLE_EINTR(pread(descriptor, &extra, 1, static_cast<off_t>(offset))) != 0)
    return std::nullopt;
  std::array<uint8_t, crypto::hash::kSha256Size> digest;
  hasher.Finish(digest);
  return base::HexEncodeLower(digest);
}

struct PrivateSnapshot {
  base::ScopedFD descriptor;
  std::string sha256;
};

std::optional<PrivateSnapshot> MakePrivateSnapshot(
    int original, const ScanInput& input, const ScanControl& control) {
  base::ScopedTempDir directory;
  if (!directory.CreateUniqueTempDir())
    return std::nullopt;
  const base::FilePath path = directory.GetPath().AppendASCII("snapshot");
  base::ScopedFD writer(HANDLE_EINTR(open(path.value().c_str(),
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)));
  base::ScopedFD reader(HANDLE_EINTR(open(path.value().c_str(),
      O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
  struct stat writable;
  struct stat readable;
  if (!writer.is_valid() || !reader.is_valid() ||
      fstat(writer.get(), &writable) != 0 || fstat(reader.get(), &readable) != 0 ||
      !SameFile(writable, readable) || unlink(path.value().c_str()) != 0 ||
      !directory.Delete())
    return std::nullopt;
  // No pathname exists before the first content byte is copied. The helper
  // receives only the read descriptor; close the sole writer before launch.
  std::optional<std::string> digest =
      HashDescriptor(original, input, control, writer.get());
  if (!digest || HANDLE_EINTR(fsync(writer.get())) != 0)
    return std::nullopt;
  writer.reset();
  if (fstat(reader.get(), &readable) != 0 || !S_ISREG(readable.st_mode) ||
      readable.st_nlink != 0 || readable.st_size != input.bytes)
    return std::nullopt;
  return PrivateSnapshot{std::move(reader), *digest};
}

// The helper is sealed in this exact application bundle, with a fixed bundle
// identifier and this browser's Apple team. No Native Messaging registration,
// environment variable, preference, web page or extension selects a scanner.
std::optional<base::FilePath> VerifiedHelperPath() {
  base::FilePath outer;
  if (!base::NormalizeFilePath(base::apple::OuterBundlePath(), &outer))
    return std::nullopt;
  const base::FilePath bundle =
      outer.AppendASCII("Contents/Helpers/KumoMalware.app");
  const base::FilePath executable =
      bundle.AppendASCII("Contents/MacOS/KumoMalwareHost");
  base::FilePath resolved;
  if (!base::NormalizeFilePath(executable, &resolved) || resolved != executable)
    return std::nullopt;
  struct stat executable_stat;
  if (lstat(executable.value().c_str(), &executable_stat) != 0 ||
      !S_ISREG(executable_stat.st_mode))
    return std::nullopt;

  base::apple::ScopedCFTypeRef<SecCodeRef> self;
  base::apple::ScopedCFTypeRef<CFDictionaryRef> information;
  if (SecCodeCopySelf(kSecCSDefaultFlags, self.InitializeInto()) != errSecSuccess ||
      SecCodeCopySigningInformation(self.get(), kSecCSSigningInformation,
                                   information.InitializeInto()) != errSecSuccess)
    return std::nullopt;
  CFTypeRef team_value =
      CFDictionaryGetValue(information.get(), kSecCodeInfoTeamIdentifier);
  if (!team_value || CFGetTypeID(team_value) != CFStringGetTypeID())
    return std::nullopt;
  std::array<char, 11> team = {};
  if (!CFStringGetCString(static_cast<CFStringRef>(team_value), team.data(),
                          team.size(), kCFStringEncodingASCII))
    return std::nullopt;
  const std::string team_string(team.data());
  if (team_string.size() != 10 || team_string.find_first_not_of(
          "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != std::string::npos)
    return std::nullopt;
  const std::string requirement_text =
      "anchor apple generic and identifier \"app.kumo.malware\" and "
      "certificate leaf[subject.OU] = \"" + team_string + "\"";
  base::apple::ScopedCFTypeRef<CFStringRef> requirement_string(
      CFStringCreateWithCString(kCFAllocatorDefault, requirement_text.c_str(),
                                kCFStringEncodingUTF8));
  base::apple::ScopedCFTypeRef<SecRequirementRef> requirement;
  base::apple::ScopedCFTypeRef<CFURLRef> bundle_url(CFURLCreateFromFileSystemRepresentation(
      kCFAllocatorDefault, reinterpret_cast<const UInt8*>(bundle.value().data()),
      bundle.value().size(), true));
  base::apple::ScopedCFTypeRef<SecStaticCodeRef> code;
  if (!requirement_string || !bundle_url ||
      SecRequirementCreateWithString(requirement_string.get(), kSecCSDefaultFlags,
                                    requirement.InitializeInto()) != errSecSuccess ||
      SecStaticCodeCreateWithPath(bundle_url.get(), kSecCSDefaultFlags,
                                 code.InitializeInto()) != errSecSuccess ||
      SecStaticCodeCheckValidity(code.get(),
          kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSNoNetworkAccess,
          requirement.get()) != errSecSuccess)
    return std::nullopt;
  return executable;
}

class OwnedHelper {
 public:
  explicit OwnedHelper(base::Process process) : process_(std::move(process)) {}
  ~OwnedHelper() {
    siginfo_t status = {};
    if (InspectOwnedChild(&status)) {
      // waitid(WNOWAIT) proves this is still our unreaped child. Keep its PID
      // reserved while terminating the whole group, including a scanner left
      // behind by a crashing helper. Never signal a group after reaping its
      // leader: the PID could then have been reused by an unrelated process.
      kill(-process_.Pid(), SIGKILL);
      base::EnsureProcessTerminated(std::move(process_));
    }
  }
  bool Reap(int* exit_code) {
    siginfo_t information = {};
    if (!InspectOwnedChild(&information)) {
      *exit_code = -1;
      return reaped_;
    }
    if (information.si_pid == 0)
      return false;
    // The exited leader remains waitable until waitpid below. Its reserved PID
    // makes this group signal safe even when the leader exited before ClamAV.
    kill(-process_.Pid(), SIGKILL);
    int status = 0;
    const pid_t waited = HANDLE_EINTR(waitpid(process_.Pid(), &status, WNOHANG));
    if (waited == process_.Pid()) {
      *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
      reaped_ = true;
      process_.Close();
      return true;
    }
    if (waited < 0 && errno == ECHILD) {
      // Another reaper won the status race. Ownership is gone; do not signal
      // this PID/group again, and fail the scan rather than trusting a result.
      *exit_code = -1;
      reaped_ = true;
      process_.Close();
      return true;
    }
    return false;
  }

 private:
  bool InspectOwnedChild(siginfo_t* information) {
    if (!process_.IsValid() || reaped_)
      return false;
    if (HANDLE_EINTR(waitid(P_PID, static_cast<id_t>(process_.Pid()), information,
                           WEXITED | WNOHANG | WNOWAIT)) == 0)
      return information->si_pid == 0 || information->si_pid == process_.Pid();
    if (errno == ECHILD) {
      reaped_ = true;
      process_.Close();
    }
    return false;
  }

  base::Process process_;
  bool reaped_ = false;
};

std::optional<std::string> RunHelper(const base::FilePath& executable,
                                     int descriptor,
                                     const std::string& request,
                                     const ScanInput& input,
                                     const ScanControl& control) {
  int input_pair[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, input_pair) != 0)
    return std::nullopt;
  base::ScopedFD input_read(input_pair[0]);
  base::ScopedFD input_write(input_pair[1]);
  const int no_sigpipe = 1;
  if (setsockopt(input_write.get(), SOL_SOCKET, SO_NOSIGPIPE,
                 &no_sigpipe, sizeof(no_sigpipe)) != 0)
    return std::nullopt;
  int output_pair[2];
  if (pipe(output_pair) != 0)
    return std::nullopt;
  base::ScopedFD output_read(output_pair[0]);
  base::ScopedFD output_write(output_pair[1]);
  const int flags = fcntl(output_read.get(), F_GETFL);
  if (flags < 0 || fcntl(output_read.get(), F_SETFL, flags | O_NONBLOCK) != 0)
    return std::nullopt;
  base::ScopedFD null_error(HANDLE_EINTR(open("/dev/null", O_WRONLY | O_CLOEXEC)));
  if (!null_error.is_valid() || !WithinDeadline(input, control))
    return std::nullopt;
  base::LaunchOptions options;
  options.new_process_group = true;
  options.clear_environment = true;
  options.environment["HOME"] = base::GetHomeDir().value();
  options.environment["PATH"] = "/usr/bin:/bin";
  options.fds_to_remap = {{input_read.get(), STDIN_FILENO},
                          {output_write.get(), STDOUT_FILENO},
                          {null_error.get(), STDERR_FILENO}, {descriptor, 3}};
  base::Process process = base::LaunchProcess(base::CommandLine(executable), options);
  if (!process.IsValid())
    return std::nullopt;
  OwnedHelper child(std::move(process));
  input_read.reset();
  output_write.reset();
  if (request.size() > kMaxProtocolBytes ||
      HANDLE_EINTR(send(input_write.get(), request.data(), request.size(), 0)) !=
          static_cast<ssize_t>(request.size()))
    return std::nullopt;
  input_write.reset();

  std::string output;
  bool eof = false;
  bool exited = false;
  int exit_code = -1;
  while (WithinDeadline(input, control)) {
    if (!eof) {
      std::array<char, 1024> buffer;
      ssize_t count = HANDLE_EINTR(read(output_read.get(), buffer.data(), buffer.size()));
      if (count > 0) {
        if (output.size() + static_cast<size_t>(count) > kMaxProtocolBytes)
          return std::nullopt;
        output.append(buffer.data(), static_cast<size_t>(count));
      } else if (count == 0) {
        eof = true;
      } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        return std::nullopt;
      }
    }
    if (!exited)
      exited = child.Reap(&exit_code);
    if (eof && exited)
      return exit_code == 0 ? std::make_optional(output) : std::nullopt;
    struct pollfd event = {output_read.get(), POLLIN | POLLHUP, 0};
    if (HANDLE_EINTR(poll(eof ? nullptr : &event, eof ? 0 : 1, 50)) < 0)
      return std::nullopt;
  }
  return std::nullopt;
}

ScanResult ScanFile(ScanInput input, std::shared_ptr<ScanControl> control) {
  ScanResult result;
  result.guid = input.guid;
  result.bytes = input.bytes;
  if (!WithinDeadline(input, *control) || input.bytes < 0 ||
      input.bytes > kMaxScanBytes || input.path.empty())
    return result;
  base::ScopedFD descriptor(HANDLE_EINTR(open(input.path.value().c_str(),
                                             O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
  if (!descriptor.is_valid())
    return result;
  std::optional<struct stat> retry_baseline;
  std::string first_snapshot_sha;  // Bound once, including without a browser hash.
  const auto disposition = RunBoundedMetadataScan([&](bool retry) {
    struct stat before;
    struct stat named;
    if (!WithinDeadline(input, *control) ||
        fstat(descriptor.get(), &before) != 0 ||
        lstat(input.path.value().c_str(), &named) != 0 ||
        !AtMetadataRetryBaseline(before, before, named) ||
        before.st_uid != getuid() || before.st_size != input.bytes ||
        (retry && (!retry_baseline ||
                   !AtMetadataRetryBaseline(*retry_baseline, before, named)))) {
      return ScanAttemptDisposition::kReject;
    }
    std::optional<PrivateSnapshot> snapshot =
        MakePrivateSnapshot(descriptor.get(), input, *control);
    if (!snapshot || !SnapshotHashMatches(snapshot->sha256, input.browser_hash,
                                         first_snapshot_sha)) {
      return ScanAttemptDisposition::kReject;
    }
    if (first_snapshot_sha.empty())
      first_snapshot_sha = snapshot->sha256;
    result.sha256 = snapshot->sha256;
    std::optional<base::FilePath> executable = VerifiedHelperPath();
    struct stat before_helper;
    struct stat named_before_helper;
    if (!executable || !WithinDeadline(input, *control) ||
        fstat(descriptor.get(), &before_helper) != 0 ||
        lstat(input.path.value().c_str(), &named_before_helper) != 0 ||
        !AtMetadataRetryBaseline(before, before_helper, named_before_helper)) {
      return ScanAttemptDisposition::kReject;
    }
    base::DictValue request;
    request.Set("version", 1);
    request.Set("requestId", input.guid);
    request.Set("bytes", static_cast<int>(input.bytes));
    request.Set("sha256", snapshot->sha256);
    std::string encoded;
    if (!base::JSONWriter::Write(request, &encoded))
      return ScanAttemptDisposition::kReject;
    encoded.push_back('\n');
    std::optional<std::string> output =
        RunHelper(*executable, snapshot->descriptor.get(), encoded, input, *control);
    if (!output || output->empty() || output->back() != '\n' ||
        output->find('\n') != output->size() - 1) {
      return ScanAttemptDisposition::kReject;
    }
    auto reply = base::JSONReader::ReadDict(*output, base::JSON_PARSE_RFC, 4);
    if (!reply || reply->size() != 6 || reply->FindInt("version") != 1 ||
        !reply->FindString("requestId") ||
        *reply->FindString("requestId") != input.guid ||
        !reply->FindString("sha256") ||
        *reply->FindString("sha256") != snapshot->sha256 ||
        reply->FindInt("bytes") != input.bytes ||
        !reply->FindString("reason") || reply->FindString("reason")->size() > 512) {
      return ScanAttemptDisposition::kReject;
    }
    const std::string* verdict = reply->FindString("verdict");
    if (!verdict || (*verdict != "no-known-malware" && *verdict != "malware" &&
                     *verdict != "unavailable" && *verdict != "limited")) {
      return ScanAttemptDisposition::kReject;
    }
    struct stat after;
    struct stat named_after;
    std::optional<std::string> after_digest =
        HashDescriptor(descriptor.get(), input, *control);
    if (fstat(descriptor.get(), &after) != 0 ||
        lstat(input.path.value().c_str(), &named_after) != 0) {
      return ScanAttemptDisposition::kReject;
    }
    const bool exact_content =
        after_digest && *after_digest == snapshot->sha256 &&
        (input.browser_hash.empty() || *after_digest == input.browser_hash);
    const auto attempt_disposition = ClassifyScanAttempt(
        *verdict, exact_content, WithinDeadline(input, *control), before, after,
        named_after);
    if (attempt_disposition == ScanAttemptDisposition::kRetryMetadata)
      retry_baseline = after;
    return attempt_disposition;
  });
  result.clean = disposition == ScanAttemptDisposition::kClean;
  result.infected = disposition == ScanAttemptDisposition::kInfected;
  return result;
}

scoped_refptr<base::SequencedTaskRunner> ScannerRunner() {
  static base::NoDestructor<scoped_refptr<base::SequencedTaskRunner>> runner(
      base::ThreadPool::CreateSequencedTaskRunner(
          {base::MayBlock(), base::TaskPriority::USER_VISIBLE,
           base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN}));
  return *runner;
}

class DownloadGuard : public DownloadCompletionBlocker,
                      public download::DownloadItem::Observer {
 public:
  explicit DownloadGuard(download::DownloadItem* item)
      : item_(item), control_(std::make_shared<ScanControl>()) {
    item_->AddObserver(this);
    input_.path = item_->GetFullPath();
    input_.guid = item_->GetGuid();
    input_.bytes = item_->GetReceivedBytes();
    if (item_->GetHash().size() == crypto::hash::kSha256Size)
      input_.browser_hash = base::HexEncodeLower(item_->GetHash());
    input_.deadline = base::TimeTicks::Now() + kScanTimeout;
  }

  ~DownloadGuard() override {
    control_->cancelled.store(true, std::memory_order_relaxed);
    if (item_)
      item_->RemoveObserver(this);
  }

  void Start() {
    timer_.Start(FROM_HERE, kScanTimeout,
                 base::BindOnce(&DownloadGuard::Fail,
                                weak_factory_.GetWeakPtr(), false));
    if (!item_->AllDataSaved() || item_->IsSavePackageDownload() ||
        input_.path.empty() || input_.guid.empty() || input_.guid.size() > 64 ||
        input_.bytes < 0 || input_.bytes > kMaxScanBytes ||
        (!item_->GetHash().empty() && input_.browser_hash.empty()) ||
        g_pending_scans >= kMaximumPendingScans) {
      // Post, rather than destroy/cancel the DownloadItem inside its own
      // ShouldCompleteDownload stack. The callback is deliberately not run.
      base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&DownloadGuard::Fail,
                                   weak_factory_.GetWeakPtr(), false));
      return;
    }
    ++g_pending_scans;
    ScannerRunner()->PostTaskAndReplyWithResult(
        FROM_HERE, base::BindOnce(&ScanFile, input_, control_),
        base::BindOnce(
            [](base::WeakPtr<DownloadGuard> guard, ScanResult result) {
              DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
              CHECK_GT(g_pending_scans, 0u);
              --g_pending_scans;
              if (guard)
                guard->Finish(std::move(result));
            }, weak_factory_.GetWeakPtr()));
  }

  void OnDownloadDestroyed(download::DownloadItem* item) override {
    control_->cancelled.store(true, std::memory_order_relaxed);
    item_ = nullptr;
    timer_.Stop();
    weak_factory_.InvalidateWeakPtrs();
  }

  void OnDownloadUpdated(download::DownloadItem* item) override {
    if (item->GetState() != download::DownloadItem::IN_PROGRESS) {
      control_->cancelled.store(true, std::memory_order_relaxed);
      timer_.Stop();
      weak_factory_.InvalidateWeakPtrs();
    }
  }

  bool CanRelease() const {
    return is_complete() && StillCurrent() &&
           !control_->cancelled.load(std::memory_order_relaxed);
  }

  bool IsObsolete() const {
    return control_->cancelled.load(std::memory_order_relaxed) || !StillCurrent();
  }

 private:
  bool StillCurrent() const {
    return item_ && item_->GetState() == download::DownloadItem::IN_PROGRESS &&
           item_->AllDataSaved() && item_->GetGuid() == input_.guid &&
           item_->GetFullPath() == input_.path &&
           item_->GetReceivedBytes() == input_.bytes &&
           (item_->GetHash().empty() ? input_.browser_hash.empty()
                                    : base::HexEncodeLower(item_->GetHash()) == input_.browser_hash);
  }

  void Finish(ScanResult result) {
    if (control_->cancelled.load(std::memory_order_relaxed))
      return;
    if (!StillCurrent() || result.guid != input_.guid ||
        result.bytes != input_.bytes || !result.clean ||
        result.sha256.size() != 64 ||
        (!input_.browser_hash.empty() && result.sha256 != input_.browser_hash) ||
        base::TimeTicks::Now() >= input_.deadline) {
      Fail(result.infected);
      return;
    }
    timer_.Stop();
    CompleteDownload();  // May delete this; never access members afterward.
  }

  void Fail(bool infected) {
    timer_.Stop();
    control_->cancelled.store(true, std::memory_order_relaxed);
    if (!item_ || item_->GetState() != download::DownloadItem::IN_PROGRESS)
      return;
    if (!item_->AllDataSaved() && !item_->IsSavePackageDownload()) {
      item_->Cancel(false);
      return;
    }
    // This API interrupts non-resumably and discards the intermediate file.
    // It cannot release the final rename, auto-open, or the CRX installer.
    item_->OnContentCheckCompleted(
        download::DOWNLOAD_DANGER_TYPE_NOT_DANGEROUS,
        infected ? download::DOWNLOAD_INTERRUPT_REASON_FILE_VIRUS_INFECTED
                 : download::DOWNLOAD_INTERRUPT_REASON_FILE_SECURITY_CHECK_FAILED);
  }

  raw_ptr<download::DownloadItem> item_;
  ScanInput input_;
  std::shared_ptr<ScanControl> control_;
  base::OneShotTimer timer_;
  base::WeakPtrFactory<DownloadGuard> weak_factory_{this};
};

}  // namespace

bool IsDownloadMalwareChecked(download::DownloadItem* item,
                              base::OnceClosure* completion_callback) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  auto* guard = static_cast<DownloadGuard*>(item->GetUserData(&kGuardUserDataKey));
  if (guard && guard->CanRelease())
    return true;
  if (guard && (guard->is_complete() || guard->IsObsolete())) {
    // A resumed/replaced generation cannot reuse an earlier clean verdict.
    item->RemoveUserData(&kGuardUserDataKey);
    guard = nullptr;
  }
  if (!guard) {
    auto created = std::make_unique<DownloadGuard>(item);
    guard = created.get();
    item->SetUserData(&kGuardUserDataKey, std::move(created));
    guard->set_callback(std::move(*completion_callback));
    guard->Start();
  } else {
    guard->set_callback(std::move(*completion_callback));
  }
  return false;
}

}  // namespace kumo
