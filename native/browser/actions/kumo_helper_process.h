#ifndef CHROME_BROWSER_KUMO_ACTIONS_KUMO_HELPER_PROCESS_H_
#define CHROME_BROWSER_KUMO_ACTIONS_KUMO_HELPER_PROCESS_H_

#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/time/time.h"
#include "base/values.h"

namespace kumo {

// Fixed app-relative helpers only. Call the blocking functions on a MayBlock
// worker, never the browser UI thread. The current browser's signing team and
// its sealed app resources are verified before a helper is started.
base::FilePath GetContentsPath();
bool VerifyHelper(const base::FilePath& contents,
                  const base::FilePath& relative_executable);
base::DictValue RunVerifiedHelper(
    const base::FilePath& contents,
    const base::FilePath& relative_executable,
    const std::vector<std::string>& fixed_arguments,
    base::TimeDelta timeout = base::Seconds(180));

}  // namespace kumo
#endif
