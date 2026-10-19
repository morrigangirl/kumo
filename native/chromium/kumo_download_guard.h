// Copyright 2026 Kumo Authors. Licensed under the MIT license.
#ifndef CHROME_BROWSER_DOWNLOAD_KUMO_DOWNLOAD_GUARD_H_
#define CHROME_BROWSER_DOWNLOAD_KUMO_DOWNLOAD_GUARD_H_

#include "base/functional/callback_forward.h"

namespace download {
class DownloadItem;
}

namespace kumo {

// Returns false while a local malware scan blocks final rename/automatic open.
// Consumes |completion_callback| only when blocking. An unavailable, failed,
// limited or infected scan interrupts and discards the unfinished download.
// Call before any optional Safe Browsing/trusted-source early returns.
bool IsDownloadMalwareChecked(download::DownloadItem* item,
                              base::OnceClosure* completion_callback);

}  // namespace kumo

#endif  // CHROME_BROWSER_DOWNLOAD_KUMO_DOWNLOAD_GUARD_H_
