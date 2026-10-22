#!/usr/bin/env python3
"""Compile and exercise the actual native agent framing/backpressure helper."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AgentPipe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='kumo-pipe-', dir='/private/tmp')
        directory = Path(cls.temp.name)
        source = directory / 'fixture.cc'
        source.write_text(r'''
#include "native/browser/agents/kumo_agent_pipe.h"
#include <fcntl.h>
#include <iostream>
#include <thread>
int main(int argc, char** argv) {
  int fds[2]; if (pipe(fds)) return 90;
  fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL) | O_NONBLOCK);
  fcntl(fds[1], F_SETNOSIGPIPE, 1);
  std::atomic_bool stop{false};
  std::string mode(argv[1]);
  const auto start = std::chrono::steady_clock::now();
  bool result = false;
  if (mode == "success") {
    result = kumo::internal::WriteAgentFrame(fds[1], "hello", stop);
    char frame[9]{}; if (read(fds[0], frame, sizeof(frame)) != 9) return 91;
    if (static_cast<unsigned char>(frame[0]) != 5 || frame[1] || frame[2] || frame[3] || std::string(frame + 4, 5) != "hello") return 92;
  } else if (mode == "closed") {
    close(fds[0]); fds[0] = -1;
    result = kumo::internal::WriteAgentFrame(fds[1], "hello", stop);
  } else if (mode == "oversize") {
    result = kumo::internal::WriteAgentFrame(fds[1], std::string(1024 * 1024 + 1, 'x'), stop);
  } else if (mode == "cancel") {
    std::thread cancel([&] { std::this_thread::sleep_for(std::chrono::milliseconds(100)); stop.store(true); });
    result = kumo::internal::WriteAgentFrame(fds[1], std::string(1024 * 1024, 'x'), stop);
    cancel.join();
  } else if (mode == "timeout") {
    result = kumo::internal::WriteAgentFrame(fds[1], std::string(1024 * 1024, 'x'), stop);
  } else return 93;
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
  if (fds[0] >= 0) close(fds[0]); close(fds[1]);
  std::cout << result << " " << elapsed << std::endl;
}
''')
        cls.executable = directory / 'fixture'
        subprocess.run(['clang++', '-std=c++20', '-pthread', '-I', str(ROOT), str(source), '-o', str(cls.executable)], check=True, capture_output=True, timeout=60)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def run_case(self, mode):
        result = subprocess.run([str(self.executable), mode], check=True, capture_output=True, text=True, timeout=5)
        return tuple(int(value) for value in result.stdout.split())

    def test_exact_little_endian_frame_reaches_reader(self): self.assertEqual(self.run_case('success')[0], 1)
    def test_closed_reader_fails_without_sigpipe(self): self.assertEqual(self.run_case('closed')[0], 0)
    def test_oversize_message_is_rejected(self): self.assertEqual(self.run_case('oversize')[0], 0)
    def test_stalled_reader_cancels_promptly(self):
        success, milliseconds = self.run_case('cancel'); self.assertEqual(success, 0); self.assertLess(milliseconds, 750)
    def test_stalled_reader_has_bounded_deadline(self):
        success, milliseconds = self.run_case('timeout'); self.assertEqual(success, 0); self.assertGreaterEqual(milliseconds, 1900); self.assertLess(milliseconds, 3000)


if __name__ == '__main__': unittest.main(verbosity=2)
