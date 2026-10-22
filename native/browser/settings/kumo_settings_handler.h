// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_SETTINGS_KUMO_SETTINGS_HANDLER_H_
#define CHROME_BROWSER_KUMO_SETTINGS_KUMO_SETTINGS_HANDLER_H_

#include "base/memory/weak_ptr.h"
#include "base/values.h"
#include "content/public/browser/web_ui_message_handler.h"
#include "content/public/browser/weak_document_ptr.h"

namespace content { class RenderFrameHost; }

namespace kumo {
class KumoSettingsHandler : public content::WebUIMessageHandler {
 public:
  KumoSettingsHandler();
  ~KumoSettingsHandler() override;
  void RegisterMessages() override;
  void OnJavascriptDisallowed() override;

 private:
  content::RenderFrameHost* SettingsDocument(bool require_foreground_kumo = true);
  void HandleStatus(const base::ListValue& args);
  void HandleAction(const base::ListValue& args);
  void Reply(content::WeakDocumentPtr document,
             base::Value callback_id,
             base::DictValue value);
  base::WeakPtrFactory<KumoSettingsHandler> weak_factory_{this};
};
}  // namespace kumo
#endif
