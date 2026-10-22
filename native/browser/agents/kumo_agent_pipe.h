// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_AGENTS_KUMO_AGENT_PIPE_H_
#define CHROME_BROWSER_KUMO_AGENTS_KUMO_AGENT_PIPE_H_

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <poll.h>
#include <string>
#include <string_view>
#include <unistd.h>

namespace kumo::internal {
// The descriptor must be O_NONBLOCK and owned by this worker. Cancellation is
// checked every 25 ms; a child that stops reading cannot stall browser shutdown.
inline bool WriteAgentFrame(int descriptor,
                            std::string_view body,
                            const std::atomic_bool& stopped) {
  if (body.empty() || body.size() > 1024 * 1024)
    return false;
  const uint32_t length = body.size();
  std::string frame(4, '\0');
  for (int index = 0; index < 4; ++index)
    frame[index] = (length >> (index * 8)) & 255;
  frame.append(body);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  size_t offset = 0;
  while (offset < frame.size()) {
    if (stopped.load(std::memory_order_acquire) ||
        std::chrono::steady_clock::now() >= deadline)
      return false;
    const ssize_t count = write(descriptor, frame.data() + offset,
                                frame.size() - offset);
    if (count > 0) {
      offset += count;
      continue;
    }
    if (count < 0 && errno == EINTR)
      continue;
    if (count >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
      return false;
    pollfd ready = {descriptor, POLLOUT, 0};
    const int result = poll(&ready, 1, 25);
    if (result < 0 && errno != EINTR)
      return false;
    if (result > 0 && (ready.revents & (POLLERR | POLLHUP | POLLNVAL)))
      return false;
  }
  return true;
}
}  // namespace kumo::internal
#endif
