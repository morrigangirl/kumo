#import <AppKit/AppKit.h>

#include "kumo_password_context.h"
#include "kumo_password_panel.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include "base/functional/callback_helpers.h"
#include "chrome/browser/password_manager/chrome_password_manager_client.h"
#include "components/autofill/core/common/form_field_data.h"
#include "components/autofill/core/common/unique_ids.h"
#include "components/password_manager/content/browser/content_password_manager_driver.h"
#include "content/public/browser/navigation_handle.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_contents_observer.h"
#include "content/public/browser/visibility.h"
#include "content/public/browser/weak_document_ptr.h"
#include "ui/gfx/native_ui_types.h"
#include "url/origin.h"

namespace kumo {
namespace {
// The browser owns this request. No password passes through an extension, a
// native messaging host, a clipboard, JavaScript, or an agent transport.
class NativePasswordRequest final : public content::WebContentsObserver {
 public:
  NativePasswordRequest(content::RenderFrameHost* frame, uint64_t field_id)
      : content::WebContentsObserver(content::WebContents::FromRenderFrameHost(frame)),
        document_(frame->GetWeakDocumentPtr()),
        origin_(frame->GetLastCommittedOrigin()),
        field_id_(field_id),
        window_(web_contents()->GetTopLevelNativeWindow().GetNativeNSWindow()) {}

  NSWindow* window() const { return window_; }
  std::string origin() const { return origin_.Serialize(); }

  void Complete(bool accepted, std::u16string value) {
    Observe(nullptr);
    auto* frame = document_.AsRenderFrameHostIfValid();
    if (accepted && !cancelled_ && value.size() <= 16384 && frame &&
        CanFillFromApplePasswords(frame, field_id_) &&
        frame->GetLastCommittedOrigin() == origin_) {
      if (auto* driver = password_manager::ContentPasswordManagerDriver::
              GetForRenderFrameHost(frame)) {
        // Explicit renderer field ID avoids a focus-change race while the
        // native sheet is open. Chromium's own driver validates the target.
        driver->FillField(autofill::FieldRendererId(field_id_), value,
                          autofill::kAutofilledOnUserTrigger, base::DoNothing());
      }
    }
    std::fill(value.begin(), value.end(), u'\0');
  }

  void DidStartNavigation(content::NavigationHandle* handle) override {
    // Cancel even same-site navigations. Never carry selected credentials into
    // a different document while a sheet is waiting for the person.
    if (handle->IsInPrimaryMainFrame())
      Cancel();
  }
  void RenderFrameDeleted(content::RenderFrameHost* frame) override {
    if (!document_.AsRenderFrameHostIfValid() ||
        frame == document_.AsRenderFrameHostIfValid())
      Cancel();
  }
  void OnVisibilityChanged(content::Visibility visibility) override {
    // A system credential/authentication window may cover the selected tab.
    // Hidden/minimized windows and nonselected tabs still cancel immediately.
    if (visibility == content::Visibility::HIDDEN)
      Cancel();
  }
  void WebContentsDestroyed() override { Cancel(); }

 private:
  void Cancel() {
    cancelled_ = true;
    CancelKumoPasswordPanel(window_);
  }
  content::WeakDocumentPtr document_;
  const url::Origin origin_;
  const uint64_t field_id_;
  __weak NSWindow* window_;
  bool cancelled_ = false;
};
}  // namespace

bool CanFillFromApplePasswords(content::RenderFrameHost* frame, uint64_t field_id) {
  // Start with HTTPS top-level documents only. Cross-origin/embedded frames,
  // browser pages, stale documents, and insecure destinations fail closed.
  if (!frame || field_id == 0 || !frame->IsActive() ||
      !frame->IsInPrimaryMainFrame() ||
      !frame->GetLastCommittedURL().SchemeIs("https") ||
      frame->GetLastCommittedOrigin().opaque()) {
    return false;
  }
  auto* client = ChromePasswordManagerClient::FromWebContents(
      content::WebContents::FromRenderFrameHost(frame));
  // Reuse Chromium's certificate-error and page/policy gates. This is distinct
  // from enabling its own credential saving; check again before delivering.
  return client && client->IsFillingEnabled(frame->GetLastCommittedOrigin(),
                                           frame->GetLastCommittedURL());
}

void FillFromApplePasswords(content::RenderFrameHost* frame,
                           uint64_t field_id,
                           bool is_password) {
  if (!CanFillFromApplePasswords(frame, field_id))
    return;
  auto request = std::make_shared<NativePasswordRequest>(frame, field_id);
  ShowKumoPasswordPanel(
      request->window(), request->origin(), is_password,
      [request](bool accepted, std::u16string value) {
        request->Complete(accepted, std::move(value));
      });
}
}  // namespace kumo
