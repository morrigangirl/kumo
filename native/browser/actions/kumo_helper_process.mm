#include "chrome/browser/kumo/actions/kumo_helper_process.h"

#import <Foundation/Foundation.h>
#include <Security/Security.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <optional>

#include "base/apple/scoped_cftyperef.h"
#include "base/command_line.h"
#include "base/files/scoped_file.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "base/path_service.h"
#include "base/posix/eintr_wrapper.h"
#include "base/process/kill.h"
#include "base/process/launch.h"
#include "base/process/process.h"
#include "base/strings/string_util.h"
#include "base/base_paths.h"

namespace kumo {
namespace {

base::DictValue Failure(std::string_view reason) {
  return base::DictValue().Set("ok", false).Set("reason", reason);
}

std::optional<std::string> OwnTeam() {
  base::apple::ScopedCFTypeRef<SecCodeRef> self;
  base::apple::ScopedCFTypeRef<CFDictionaryRef> info;
  if (SecCodeCopySelf(kSecCSDefaultFlags, self.InitializeInto()) != errSecSuccess ||
      SecCodeCopySigningInformation(self.get(), kSecCSSigningInformation,
                                   info.InitializeInto()) != errSecSuccess)
    return std::nullopt;
  auto value = CFDictionaryGetValue(info.get(), kSecCodeInfoTeamIdentifier);
  if (!value || CFGetTypeID(value) != CFStringGetTypeID())
    return std::nullopt;
  std::array<char, 11> bytes = {};
  if (!CFStringGetCString(static_cast<CFStringRef>(value), bytes.data(),
                          bytes.size(), kCFStringEncodingASCII))
    return std::nullopt;
  std::string team(bytes.data());
  if (team.size() != 10 ||
      team.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") !=
          std::string::npos)
    return std::nullopt;
  return team;
}

bool CheckCode(const base::FilePath& path, const std::string& requirement,
               bool directory) {
  base::apple::ScopedCFTypeRef<CFURLRef> url(
      CFURLCreateFromFileSystemRepresentation(
          kCFAllocatorDefault,
          reinterpret_cast<const UInt8*>(path.value().data()),
          path.value().size(), directory));
  base::apple::ScopedCFTypeRef<CFStringRef> expression(
      CFStringCreateWithCString(kCFAllocatorDefault, requirement.c_str(),
                                kCFStringEncodingUTF8));
  base::apple::ScopedCFTypeRef<SecRequirementRef> policy;
  base::apple::ScopedCFTypeRef<SecStaticCodeRef> code;
  return url && expression &&
      SecRequirementCreateWithString(expression.get(), kSecCSDefaultFlags,
                                      policy.InitializeInto()) == errSecSuccess &&
      SecStaticCodeCreateWithPath(url.get(), kSecCSDefaultFlags,
                                  code.InitializeInto()) == errSecSuccess &&
      SecStaticCodeCheckValidity(code.get(),
          kSecCSStrictValidate | kSecCSCheckAllArchitectures |
              kSecCSNoNetworkAccess,
          policy.get()) == errSecSuccess;
}

// Retain ownership until the group is stopped. Never signal a reaped PID that
// the OS could have reused for an unrelated process.
class Child {
 public:
  explicit Child(base::Process process) : process_(std::move(process)) {}
  ~Child() {
    siginfo_t info = {};
    if (!reaped_ && Inspect(&info)) {
      kill(-process_.Pid(), SIGKILL);
      base::EnsureProcessTerminated(std::move(process_));
    }
  }
  bool Reap(int* exit_code) {
    if (reaped_)
      return true;
    siginfo_t info = {};
    if (!Inspect(&info) || info.si_pid == 0)
      return false;
    // The process remains unreaped while any owned descendants are stopped.
    kill(-process_.Pid(), SIGKILL);
    int status = 0;
    if (HANDLE_EINTR(waitpid(process_.Pid(), &status, 0)) != process_.Pid())
      return false;
    reaped_ = true;
    *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return true;
  }

 private:
  bool Inspect(siginfo_t* info) const {
    return HANDLE_EINTR(waitid(P_PID, process_.Pid(), info,
                              WEXITED | WNOHANG | WNOWAIT)) == 0;
  }
  base::Process process_;
  bool reaped_ = false;
};
}  // namespace

base::FilePath GetContentsPath() {
  base::FilePath executable_directory;
  if (!base::PathService::Get(base::DIR_EXE, &executable_directory) ||
      executable_directory.BaseName().value() != "MacOS")
    return {};
  return executable_directory.DirName();
}

bool VerifyHelper(const base::FilePath& contents,
                  const base::FilePath& relative_executable) {
  if (contents.empty() || contents.BaseName().value() != "Contents" ||
      relative_executable.IsAbsolute() || relative_executable.ReferencesParent())
    return false;
  const auto team = OwnTeam();
  if (!team)
    return false;
  const std::string requirement =
      "anchor apple generic and certificate leaf[subject.OU] = \"" +
      *team + "\"";
  return CheckCode(contents.DirName(),
                   requirement + " and identifier \"app.kumo.browser\"", true) &&
         CheckCode(contents.Append(relative_executable), requirement, false);
}

base::DictValue RunVerifiedHelper(
    const base::FilePath& contents,
    const base::FilePath& relative_executable,
    const std::vector<std::string>& fixed_arguments,
    base::TimeDelta timeout) {
  if (!VerifyHelper(contents, relative_executable))
    return Failure("The installed Kumo helper could not be verified.");
  int descriptors[2];
  if (pipe(descriptors) != 0)
    return Failure("Kumo could not prepare its helper connection.");
  base::ScopedFD output(descriptors[0]), child_output(descriptors[1]);
  base::ScopedFD null_input(HANDLE_EINTR(open("/dev/null", O_RDONLY | O_CLOEXEC)));
  base::ScopedFD null_error(HANDLE_EINTR(open("/dev/null", O_WRONLY | O_CLOEXEC)));
  const int flags = fcntl(output.get(), F_GETFL);
  if (flags < 0 || fcntl(output.get(), F_SETFL, flags | O_NONBLOCK) != 0 ||
      !null_input.is_valid() || !null_error.is_valid())
    return Failure("Kumo could not prepare its helper connection.");
  base::CommandLine command(contents.Append(relative_executable));
  for (const auto& argument : fixed_arguments)
    command.AppendArg(argument);
  base::LaunchOptions options;
  options.new_process_group = true;
  options.clear_environment = true;
  options.environment["HOME"] = base::GetHomeDir().value();
  options.environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin";
  options.environment["KUMO_SETUP_NONINTERACTIVE"] = "1";
  options.fds_to_remap = {{null_input.get(), STDIN_FILENO},
                          {child_output.get(), STDOUT_FILENO},
                          {null_error.get(), STDERR_FILENO}};
  auto process = base::LaunchProcess(command, options);
  if (!process.IsValid())
    return Failure("macOS could not start Kumo's verified helper.");
  Child child(std::move(process));
  child_output.reset();
  const auto deadline = base::TimeTicks::Now() + timeout;
  std::string response;
  bool eof = false, exited = false;
  int exit_code = -1;
  while (base::TimeTicks::Now() < deadline) {
    if (!eof) {
      std::array<char, 4096> bytes;
      ssize_t count = HANDLE_EINTR(read(output.get(), bytes.data(), bytes.size()));
      if (count > 0) {
        if (response.size() + count > 65536)
          return Failure("Kumo's helper response exceeded its safety limit.");
        response.append(bytes.data(), count);
      } else if (count == 0) {
        eof = true;
      } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        return Failure("Kumo's helper connection failed.");
      }
    }
    if (!exited)
      exited = child.Reap(&exit_code);
    if (eof && exited) {
      base::TrimWhitespaceASCII(response, base::TRIM_ALL, &response);
      // Helpers return exactly one bounded JSON value; no shell output or
      // arbitrary diagnostic text is interpreted as a successful operation.
      auto value = base::JSONReader::ReadDict(response, base::JSON_PARSE_RFC, 16);
      if (!value)
        return Failure("Kumo's helper did not return a valid result.");
      auto result = std::move(*value);
      result.Set("exitCode", exit_code);
      if (exit_code != 0)
        result.Set("ok", false);
      return result;
    }
    pollfd event = {output.get(), POLLIN | POLLHUP, 0};
    if (HANDLE_EINTR(poll(eof ? nullptr : &event, eof ? 0 : 1, 40)) < 0)
      return Failure("Kumo's helper connection failed.");
  }
  return Failure("The operation timed out. Your existing setup was retained.");
}

}  // namespace kumo
