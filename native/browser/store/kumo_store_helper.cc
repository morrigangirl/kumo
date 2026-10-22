// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/store/kumo_store_helper.h"

#include "base/memory/raw_ptr.h"
#include "base/strings/escape.h"
#include "base/strings/string_split.h"
#include "base/version_info/version_info.h"
#include "chrome/browser/infobars/confirm_infobar_creator.h"
#include "chrome/browser/profiles/profile.h"
#include "components/download/public/common/download_url_parameters.h"
#include "components/infobars/content/content_infobar_manager.h"
#include "components/infobars/core/confirm_infobar_delegate.h"
#include "components/infobars/core/infobar.h"
#include "content/public/browser/download_manager.h"
#include "content/public/browser/navigation_handle.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_contents_observer.h"
#include "content/public/browser/web_contents_user_data.h"
#include "content/public/browser/weak_document_ptr.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/mojom/fetch_api.mojom.h"

namespace kumo {
namespace {
std::string StoreId(const GURL& url) {
  if (!url.is_valid() || !url.SchemeIs("https") ||
      url.host() != "chromewebstore.google.com" || url.EffectiveIntPort() != 443 ||
      url.has_username() || url.has_password()) return {};
  auto parts = base::SplitString(url.path(), "/", base::KEEP_WHITESPACE,
                                base::SPLIT_WANT_NONEMPTY);
  if ((parts.size() != 2 && parts.size() != 3) || parts[0] != "detail") return {};
  const auto& id = parts.back();
  if (id.size() != 32 || id.find_first_not_of("abcdefghijklmnop") != std::string::npos) return {};
  return id;
}

class StoreInfoBar final : public ConfirmInfoBarDelegate {
 public:
  StoreInfoBar(content::WebContents* contents, std::string id)
      : contents_(contents), document_(contents->GetPrimaryMainFrame()->GetWeakDocumentPtr()), id_(std::move(id)) {}
  InfoBarIdentifier GetIdentifier() const override { return KUMO_STORE_INSTALL_INFOBAR_DELEGATE; }
  std::u16string GetMessageText() const override { return u"Install this extension or theme in Kumo?"; }
  int GetButtons() const override { return BUTTON_OK; }
  std::u16string GetButtonLabel(InfoBarButton) const override { return u"Install in Kumo"; }
  bool Accept() override {
    auto* frame = document_.AsRenderFrameHostIfValid();
    if (!frame || frame != contents_->GetPrimaryMainFrame() || !frame->IsActive() ||
        StoreId(frame->GetLastCommittedURL()) != id_ ||
        Profile::FromBrowserContext(contents_->GetBrowserContext())->IsOffTheRecord()) return true;
    const auto annotation = net::DefineNetworkTrafficAnnotation("kumo_explicit_store_download", R"(
      semantics { sender: "Kumo extension installation" description: "Downloads the signed extension selected on a Chrome Web Store detail page after a native browser button click." trigger: "The person clicks Install in Kumo in the browser-owned infobar." data: "The public extension ID and browser engine version. No account credentials or browsing history." destination: GOOGLE_OWNED_SERVICE }
      policy { cookies_allowed: NO setting: "This download occurs only after explicit user action." policy_exception_justification: "Not a background service." })");
    const GURL url("https://clients2.google.com/service/update2/crx?response=redirect&prodversion=" +
                   std::string(version_info::GetVersionNumber()) + "&acceptformat=crx3&x=" +
                   base::EscapeQueryParamValue("id="+id_+"&installsource=ondemand&uc", false));
    auto parameters = frame->CreateDownloadUrlParameters(url, annotation);
    parameters->set_content_initiated(false);
    parameters->set_has_user_gesture(true);
    parameters->set_credentials_mode(network::mojom::CredentialsMode::kOmit);
    parameters->set_referrer(GURL());
    // Chromium's ordinary download, CRX signature, consent and antivirus gates
    // remain in control. This does not preapprove an extension or its permissions.
    Profile::FromBrowserContext(contents_->GetBrowserContext())->GetDownloadManager()->DownloadUrl(std::move(parameters));
    return true;
  }
 private:
  raw_ptr<content::WebContents> contents_;
  content::WeakDocumentPtr document_;
  const std::string id_;
};

class StoreObserver final : public content::WebContentsObserver,
                            public content::WebContentsUserData<StoreObserver> {
 public:
  void DidFinishNavigation(content::NavigationHandle* handle) override {
    if (!handle->HasCommitted() || !handle->IsInPrimaryMainFrame()) return;
    auto* manager = infobars::ContentInfoBarManager::FromWebContents(web_contents());
    if (!manager) return;
    for (const auto& bar : manager->infobars()) {
      if (bar->delegate()->GetIdentifier() == infobars::InfoBarDelegate::KUMO_STORE_INSTALL_INFOBAR_DELEGATE) {
        manager->RemoveInfoBar(bar.get()); break;
      }
    }
    const std::string id = StoreId(handle->GetURL());
    if (id.empty()) return;
    manager->AddInfoBar(CreateConfirmInfoBar(std::make_unique<StoreInfoBar>(web_contents(), id)));
  }
 private:
  friend class content::WebContentsUserData<StoreObserver>;
  explicit StoreObserver(content::WebContents* contents)
      : content::WebContentsObserver(contents), content::WebContentsUserData<StoreObserver>(*contents) {}
  WEB_CONTENTS_USER_DATA_KEY_DECL();
};
WEB_CONTENTS_USER_DATA_KEY_IMPL(StoreObserver);
}  // namespace
void AttachStoreHelper(content::WebContents* contents) {
  if (!Profile::FromBrowserContext(contents->GetBrowserContext())->IsOffTheRecord())
    StoreObserver::CreateForWebContents(contents);
}
}  // namespace kumo
