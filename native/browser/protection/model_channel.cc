// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/protection/model_channel.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <array>
#include <string>
#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/process/launch.h"
#include "base/time/time.h"
#include "chrome/browser/kumo/actions/kumo_helper_process.h"

namespace kumo::protection {
namespace {
constexpr size_t kMaximumFrame = 256 * 1024;
base::DictValue Failure() {
  return base::DictValue().Set("ok", false).Set("available", false)
      .Set("error", "model-unavailable");
}
}  // namespace

void ModelCancellation::Cancel() {
  generation.fetch_add(1);
  base::AutoLock hold(lock);
  if (pid > 0)
    kill(pid, SIGTERM);
}

ModelChannel::ModelChannel(base::FilePath helper,
                           std::shared_ptr<ModelCancellation> cancellation)
    : helper_(std::move(helper)), cancellation_(std::move(cancellation)) {}
ModelChannel::~ModelChannel() { Stop(); }

bool ModelChannel::Start() {
  if (process_.IsValid())
    return true;
  const auto contents = kumo::GetContentsPath();
  const base::FilePath relative("Helpers/KumoPhishing.app/Contents/MacOS/KumoPhishingHost");
  if (contents.empty() || contents.Append(relative) != helper_ ||
      !kumo::VerifyHelper(contents, relative))
    return false;
  int input[2], output[2];
  if (pipe(input) != 0)
    return false;
  if (pipe(output) != 0) {
    close(input[0]); close(input[1]);
    return false;
  }
  for (int fd : {input[0], input[1], output[0], output[1]})
    fcntl(fd, F_SETFD, FD_CLOEXEC);
  const int errors = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (errors < 0) {
    for (int fd : {input[0], input[1], output[0], output[1]}) close(fd);
    return false;
  }
  base::CommandLine command(helper_);
  // This is a distinct browser pipe protocol, never an extension origin.
  command.AppendArg("--browser-stdio");
  base::LaunchOptions options;
  options.clear_environment = true;
  options.environment["PATH"] = "/usr/bin:/bin";
  base::FilePath temporary;
  if (base::GetTempDir(&temporary))
    options.environment["TMPDIR"] = temporary.value();
  options.fds_to_remap = {{input[0], STDIN_FILENO}, {output[1], STDOUT_FILENO},
                          {errors, STDERR_FILENO}};
  {
    base::AutoLock hold(cancellation_->lock);
    process_ = base::LaunchProcess(command, options);
    cancellation_->pid = process_.IsValid() ? process_.Pid() : -1;
  }
  close(input[0]); close(output[1]); close(errors);
  if (!process_.IsValid()) {
    close(input[1]); close(output[0]);
    return false;
  }
  input_ = input[1]; output_ = output[0];
#if defined(F_SETNOSIGPIPE)
  fcntl(input_, F_SETNOSIGPIPE, 1);
#endif
  fcntl(input_, F_SETFL, fcntl(input_, F_GETFL) | O_NONBLOCK);
  fcntl(output_, F_SETFL, fcntl(output_, F_GETFL) | O_NONBLOCK);
  return true;
}

void ModelChannel::Stop() {
  if (input_ >= 0) { close(input_); input_ = -1; }
  if (output_ >= 0) { close(output_); output_ = -1; }
  {
    base::AutoLock hold(cancellation_->lock);
    // Retire the shared PID before reaping it. UI cancellation cannot signal
    // a recycled PID and never waits behind a blocking process wait.
    cancellation_->pid = -1;
  }
  if (process_.IsValid()) {
    process_.Terminate(0, false);
    int code = 0;
    if (!process_.WaitForExitWithTimeout(base::Seconds(2), &code)) {
      kill(process_.Pid(), SIGKILL);
      process_.WaitForExitWithTimeout(base::Seconds(2), &code);
    }
    process_.Close();
  }
}

bool ModelChannel::Transfer(bool writing, char* bytes, size_t size,
                            uint64_t generation) {
  const auto deadline = base::TimeTicks::Now() + base::Seconds(15);
  size_t offset = 0;
  while (offset < size) {
    if (generation != cancellation_->generation.load() ||
        base::TimeTicks::Now() >= deadline)
      return false;
    pollfd fd{writing ? input_ : output_,
              static_cast<short>(writing ? POLLOUT : POLLIN), 0};
    const int status = poll(&fd, 1, 100);
    if (status < 0 && errno == EINTR) continue;
    if (status < 0 || fd.revents & (POLLERR | POLLNVAL)) return false;
    if (status == 0) continue;
    const ssize_t count = writing ? write(input_, bytes + offset, size - offset)
                                  : read(output_, bytes + offset, size - offset);
    if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
    if (count <= 0) return false;
    offset += count;
  }
  return true;
}

base::DictValue ModelChannel::Request(base::DictValue request,
                                        uint64_t generation) {
  const std::string* id = request.FindString("id");
  std::string body;
  if (!id || generation != cancellation_->generation.load() ||
      !base::JSONWriter::Write(request, &body) || body.empty() ||
      body.size() > kMaximumFrame || !Start())
    return Failure();
  std::array<char, 4> header;
  const uint32_t size = body.size();
  for (size_t i = 0; i < 4; ++i) header[i] = (size >> (i * 8)) & 255;
  if (!Transfer(true, header.data(), header.size(), generation) ||
      !Transfer(true, body.data(), body.size(), generation) ||
      !Transfer(false, header.data(), header.size(), generation)) {
    Stop(); return Failure();
  }
  uint32_t count = 0;
  for (size_t i = 0; i < 4; ++i)
    count |= static_cast<uint32_t>(static_cast<unsigned char>(header[i])) << (i * 8);
  if (count == 0 || count > kMaximumFrame) { Stop(); return Failure(); }
  std::string response(count, '\0');
  if (!Transfer(false, response.data(), response.size(), generation)) {
    Stop(); return Failure();
  }
  auto parsed = base::JSONReader::ReadDict(response, base::JSON_PARSE_RFC, 32);
  if (!parsed || !parsed->FindString("id") || *parsed->FindString("id") != *id) {
    Stop(); return Failure();
  }
  if (generation != cancellation_->generation.load()) return Failure();
  return std::move(*parsed);
}
}  // namespace kumo::protection
