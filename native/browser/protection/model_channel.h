// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_PROTECTION_MODEL_CHANNEL_H_
#define CHROME_BROWSER_KUMO_PROTECTION_MODEL_CHANNEL_H_

#include <atomic>
#include <memory>
#include "base/files/file_path.h"
#include "base/process/process.h"
#include "base/synchronization/lock.h"
#include "base/values.h"

namespace kumo::protection {
// UI cancellation only signals this channel's unreaped child under the same
// lock used to clear its PID. No process-name matching or external PID input.
struct ModelCancellation {
  std::atomic<uint64_t> generation{0};
  base::Lock lock;
  int pid = -1;
  void Cancel();
};

// Lives on one MayBlock sequenced task runner. A single sandboxed Core ML host
// serves bounded, sequential requests over private inherited pipes.
class ModelChannel {
 public:
  ModelChannel(base::FilePath helper,
               std::shared_ptr<ModelCancellation> cancellation);
  ~ModelChannel();
  base::DictValue Request(base::DictValue request, uint64_t generation);
  void Stop();
 private:
  bool Start();
  bool Transfer(bool writing, char* bytes, size_t size, uint64_t generation);
  base::FilePath helper_;
  std::shared_ptr<ModelCancellation> cancellation_;
  base::Process process_;
  int input_ = -1;
  int output_ = -1;
};
}  // namespace kumo::protection
#endif
