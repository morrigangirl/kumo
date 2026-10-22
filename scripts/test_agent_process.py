#!/usr/bin/env python3
"""Run the shipping native agent ownership/reaper against disposable real children."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AgentProcess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='kumo-child-', dir='/private/tmp')
        directory = Path(cls.temp.name)
        source = directory / 'fixture.cc'
        source.write_text(r'''
#include "native/browser/agents/kumo_agent_process.h"
#include <iostream>
#include <vector>
#include <cstdlib>

using kumo::internal::AgentReapResult;
using kumo::internal::OwnedAgentChild;
using kumo::internal::ReapOwnedAgentChild;
using namespace std::chrono_literals;

pid_t Spawn(bool ignore_term, bool exit_early = false) {
  int ready[2]; if (pipe(ready)) std::exit(90);
  const pid_t child = fork();
  if (child < 0) std::exit(91);
  if (!child) {
    close(ready[0]);
    signal(SIGTERM, ignore_term ? SIG_IGN : +[](int) { _exit(17); });
    char byte = 'r'; if (write(ready[1], &byte, 1) != 1) _exit(92);
    close(ready[1]);
    if (exit_early) _exit(18);
    for (;;) pause();
  }
  close(ready[1]); char byte;
  if (read(ready[0], &byte, 1) != 1) std::exit(93);
  close(ready[0]); return child;
}
bool Reaped(pid_t child) {
  return waitpid(child, nullptr, WNOHANG) == -1 && errno == ECHILD;
}
int main(int argc, char** argv) {
  if (argc != 2) return 94;
  const std::string mode(argv[1]);
  const auto start = std::chrono::steady_clock::now();
  bool passed = false;
  if (mode == "graceful" || mode == "ignores-term" || mode == "exited" || mode == "stopped") {
    const pid_t child = Spawn(mode == "ignores-term", mode == "exited");
    if (mode == "exited") {
      siginfo_t info{};
      if (waitid(P_PID, child, &info, WEXITED | WNOWAIT)) return 95;
    }
    if (mode == "stopped") {
      if (kill(child, SIGSTOP) || waitpid(child, nullptr, WUNTRACED) != child) return 96;
    }
    const auto result = ReapOwnedAgentChild(child, mode == "stopped" ? 100ms : 2000ms);
    passed = result == AgentReapResult::kReaped && Reaped(child);
  } else if (mode == "concurrent") {
    const pid_t child = Spawn(true); OwnedAgentChild owner(child);
    std::atomic<int> taken{0}, completed{0}; std::vector<std::thread> workers;
    for (int index = 0; index < 16; ++index) workers.emplace_back([&] {
      const pid_t owned = owner.Take();
      if (owned > 0) { ++taken; if (ReapOwnedAgentChild(owned, 100ms) == AgentReapResult::kReaped) ++completed; }
    });
    for (auto& worker : workers) worker.join();
    passed = taken == 1 && completed == 1 && owner.Take() == 0 && Reaped(child);
  } else if (mode == "already-reaped") {
    const pid_t child = Spawn(false, true);
    if (waitpid(child, nullptr, 0) != child) return 97;
    passed = ReapOwnedAgentChild(child) == AgentReapResult::kNotOurChild;
  } else if (mode == "not-child") {
    // A live grandchild is not owned by this process. ECHILD must not send TERM
    // or KILL to it; only its real parent is allowed to finish and reap it.
    int ready[2], control[2]; if (pipe(ready) || pipe(control)) return 98;
    const pid_t parent = fork();
    if (parent < 0) return 99;
    if (!parent) {
      close(ready[0]); close(control[1]);
      const pid_t grandchild = Spawn(false);
      if (write(ready[1], &grandchild, sizeof(grandchild)) != sizeof(grandchild)) _exit(100);
      close(ready[1]); char byte;
      if (read(control[0], &byte, 1) != 1) _exit(101);
      const bool alive = kill(grandchild, 0) == 0;
      const auto result = ReapOwnedAgentChild(grandchild);
      _exit(alive && result == AgentReapResult::kReaped ? 0 : 102);
    }
    close(ready[1]); close(control[0]); pid_t grandchild = 0;
    if (read(ready[0], &grandchild, sizeof(grandchild)) != sizeof(grandchild)) return 103;
    close(ready[0]);
    const bool refused = ReapOwnedAgentChild(grandchild) == AgentReapResult::kNotOurChild;
    char byte = 'x'; if (write(control[1], &byte, 1) != 1) return 104; close(control[1]);
    int status = 0; if (waitpid(parent, &status, 0) != parent) return 105;
    passed = refused && WIFEXITED(status) && WEXITSTATUS(status) == 0;
  } else if (mode == "invalid") {
    passed = ReapOwnedAgentChild(0) == AgentReapResult::kNotOurChild &&
             ReapOwnedAgentChild(-1) == AgentReapResult::kNotOurChild &&
             ReapOwnedAgentChild(getpid()) == AgentReapResult::kNotOurChild;
  } else return 106;
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
  std::cout << passed << " " << elapsed << std::endl;
  return passed ? 0 : 107;
}
''')
        cls.executable = directory / 'fixture'
        subprocess.run(['clang++', '-std=c++20', '-pthread', '-Wall', '-Wextra', '-Werror',
                        '-I', str(ROOT), str(source), '-o', str(cls.executable)],
                       check=True, capture_output=True, timeout=60)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def run_case(self, mode):
        result = subprocess.run([str(self.executable), mode], check=True, capture_output=True,
                                text=True, timeout=6)
        passed, milliseconds = (int(value) for value in result.stdout.split())
        self.assertEqual(passed, 1)
        return milliseconds

    def test_graceful_child_exits_and_is_reaped(self): self.assertLess(self.run_case('graceful'), 1000)
    def test_already_exited_child_is_reaped_without_signals(self): self.assertLess(self.run_case('exited'), 1000)
    def test_ignored_term_escalates_then_reaps(self):
        elapsed = self.run_case('ignores-term'); self.assertGreaterEqual(elapsed, 1900); self.assertLess(elapsed, 3500)
    def test_stopped_child_cannot_stall_cleanup(self): self.assertLess(self.run_case('stopped'), 1000)
    def test_concurrent_stop_transfers_child_exactly_once(self): self.assertLess(self.run_case('concurrent'), 1000)
    def test_already_reaped_pid_is_never_signalled(self): self.assertLess(self.run_case('already-reaped'), 1000)
    def test_live_nonchild_is_refused_and_left_alive(self): self.assertLess(self.run_case('not-child'), 1000)
    def test_invalid_and_own_pid_are_refused(self): self.assertLess(self.run_case('invalid'), 1000)


if __name__ == '__main__': unittest.main(verbosity=2)
