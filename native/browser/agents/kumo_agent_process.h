// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_AGENTS_KUMO_AGENT_PROCESS_H_
#define CHROME_BROWSER_KUMO_AGENTS_KUMO_AGENT_PROCESS_H_

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace kumo::internal {

// Receives only the direct child returned by the browser's fixed LaunchProcess.
// Taking it is a one-way ownership transfer, including simultaneous Stop calls.
// No other code may wait for this child or signal its PID after taking it.
class OwnedAgentChild {
 public:
  explicit OwnedAgentChild(pid_t child) : child_(child) {}
  OwnedAgentChild(const OwnedAgentChild&) = delete;
  OwnedAgentChild& operator=(const OwnedAgentChild&) = delete;
  pid_t Take() { return child_.exchange(0, std::memory_order_acq_rel); }

 private:
  std::atomic<pid_t> child_;
};

enum class AgentReapResult { kReaped, kNotOurChild, kError };

// Worker-only. WNOWAIT establishes direct-child ownership without releasing the
// PID for reuse. Exclusive ownership is retained until the single final waitpid.
// An already-reaped/non-child PID (ECHILD) is never signalled. Do not use a
// process-wide wait(-1) reaper concurrently with this owner's child.
inline AgentReapResult ReapOwnedAgentChild(
    pid_t child,
    std::chrono::milliseconds grace = std::chrono::seconds(2)) {
  if (child <= 1 || child == getpid())
    return AgentReapResult::kNotOurChild;

  enum class State { kRunning, kExited, kNotOurChild, kError };
  const auto inspect = [child]() {
    siginfo_t info{};
    int result;
    do {
      result = waitid(P_PID, child, &info, WEXITED | WNOHANG | WNOWAIT);
    } while (result < 0 && errno == EINTR);
    if (result < 0)
      return errno == ECHILD ? State::kNotOurChild : State::kError;
    return info.si_pid == child ? State::kExited : State::kRunning;
  };
  const auto reap = [child]() {
    pid_t result;
    do {
      result = waitpid(child, nullptr, 0);
    } while (result < 0 && errno == EINTR);
    if (result == child)
      return AgentReapResult::kReaped;
    return result < 0 && errno == ECHILD ? AgentReapResult::kNotOurChild
                                        : AgentReapResult::kError;
  };
  const auto finish = [&reap](State state) {
    if (state == State::kExited)
      return reap();
    return state == State::kNotOurChild ? AgentReapResult::kNotOurChild
                                        : AgentReapResult::kError;
  };

  auto state = inspect();
  if (state != State::kRunning)
    return finish(state);
  if (kill(child, SIGTERM) < 0 && errno != ESRCH)
    return AgentReapResult::kError;

  const auto deadline = std::chrono::steady_clock::now() + grace;
  do {
    state = inspect();
    if (state != State::kRunning)
      return finish(state);
    if (std::chrono::steady_clock::now() >= deadline)
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  } while (true);

  // The child has never been reaped, so its PID still belongs to this owner.
  // Recheck immediately before escalation; an unexpected ECHILD fails closed.
  state = inspect();
  if (state != State::kRunning)
    return finish(state);
  if (kill(child, SIGKILL) < 0 && errno != ESRCH)
    return AgentReapResult::kError;
  return reap();
}

}  // namespace kumo::internal
#endif  // CHROME_BROWSER_KUMO_AGENTS_KUMO_AGENT_PROCESS_H_
