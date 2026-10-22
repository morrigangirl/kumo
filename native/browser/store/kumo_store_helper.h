// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_STORE_KUMO_STORE_HELPER_H_
#define CHROME_BROWSER_KUMO_STORE_KUMO_STORE_HELPER_H_
namespace content { class WebContents; }
namespace kumo {
void AttachStoreHelper(content::WebContents* contents);
}  // namespace kumo
#endif
