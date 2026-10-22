// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/settings/kumo_settings_handler.h"

#include "base/functional/bind.h"
#include "chrome/browser/kumo/kumo_browser_api.h"
#include "chrome/browser/profiles/profile.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/visibility.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_ui.h"
#include "url/gurl.h"

namespace kumo {
KumoSettingsHandler::KumoSettingsHandler() = default;
KumoSettingsHandler::~KumoSettingsHandler() = default;

void KumoSettingsHandler::RegisterMessages() {
  web_ui()->RegisterMessageCallback("kumoGetStatus", base::BindRepeating(
      &KumoSettingsHandler::HandleStatus, base::Unretained(this)));
  web_ui()->RegisterMessageCallback("kumoPerformAction", base::BindRepeating(
      &KumoSettingsHandler::HandleAction, base::Unretained(this)));
}

void KumoSettingsHandler::OnJavascriptDisallowed() {
  weak_factory_.InvalidateWeakPtrs();
}

content::RenderFrameHost* KumoSettingsHandler::SettingsDocument(
    bool require_foreground_kumo) {
  content::WebContents* contents = web_ui()->GetWebContents();
  content::RenderFrameHost* frame = web_ui()->GetRenderFrameHost();
  const GURL url = frame ? frame->GetLastCommittedURL() : GURL();
  if (!contents || !frame || frame != contents->GetPrimaryMainFrame() ||
      !frame->IsActive() ||
      !url.SchemeIs("chrome") || url.host() != "settings" ||
      (require_foreground_kumo && (url.path() != "/kumo" ||
          contents->GetVisibility() != content::Visibility::VISIBLE)) ||
      url.has_username() || url.has_password() ||
      url.has_port() ||
      Profile::FromWebUI(web_ui())->IsOffTheRecord()) {
    return nullptr;
  }
  return frame;
}

void KumoSettingsHandler::HandleStatus(const base::ListValue& args) {
  if (args.size() != 1 || !args[0].is_string()) return;
  auto* frame = SettingsDocument();
  if (!frame) return;
  AllowJavascript();
  Reply(frame->GetWeakDocumentPtr(), args[0].Clone(),
        GetStatus(Profile::FromWebUI(web_ui())));
}

void KumoSettingsHandler::HandleAction(const base::ListValue& args) {
  if (args.size() != 3 || !args[0].is_string() || !args[1].is_string() ||
      !args[2].is_dict() || args[1].GetString().size() > 64) return;
  auto* frame = SettingsDocument();
  if (!frame) return;
  AllowJavascript();
  auto document = frame->GetWeakDocumentPtr();
  // PerformAction validates this document again, consumes its transient
  // activation, and accepts only the browser's fixed operation/parameter schema.
  PerformAction(web_ui()->GetWebContents(), args[1].GetString(),
                args[2].GetDict(), base::BindOnce(&KumoSettingsHandler::Reply,
                    weak_factory_.GetWeakPtr(), document, args[0].Clone()));
}

void KumoSettingsHandler::Reply(content::WeakDocumentPtr document,
                                base::Value callback_id,
                                base::DictValue value) {
  // Admission requires the foreground Kumo section. A completion must still
  // settle its original promise if the person switches tabs or Settings
  // sections. The weak document check below rejects replacement documents.
  auto* current = SettingsDocument(false);
  if (!IsJavascriptAllowed() || !current ||
      document.AsRenderFrameHostIfValid() != current) return;
  ResolveJavascriptCallback(callback_id, base::Value(std::move(value)));
}
}  // namespace kumo
