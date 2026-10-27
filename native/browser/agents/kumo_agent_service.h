// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_AGENTS_KUMO_AGENT_SERVICE_H_
#define CHROME_BROWSER_KUMO_AGENTS_KUMO_AGENT_SERVICE_H_

#include <map>
#include <set>
#include <string>
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/supports_user_data.h"
#include "base/values.h"
#include "content/public/browser/weak_document_ptr.h"
class Profile;
namespace content { class WebContents; }
namespace kumo {
class AgentPipe;
// Session-only browser authority. No extension or renderer can publish grants
// directly to the helper. All methods run on the browser UI sequence.
class KumoAgentService : public base::SupportsUserData::Data {
 public:
  static KumoAgentService* Get(Profile* profile);
  static void AttachToWebContents(content::WebContents* contents);
  explicit KumoAgentService(Profile* profile);
  ~KumoAgentService() override;
  base::DictValue GetStatus();
  base::ListValue GetEligibleTabs();
  void SetGrants(const base::ListValue& grants, bool allow_new_tabs,
                 base::OnceCallback<void(base::DictValue)> callback);
  void Revoke();
  base::DictValue SetMissionGrants(const base::ListValue& ids);
  void RevokeMissions();
  base::DictValue MissionStatus();
  std::string GetRuntimeId() const;
  void TabChanged(content::WebContents* contents, bool destroyed, bool committed = false);
 private:
  void Start();
  void OnPipeReady(scoped_refptr<AgentPipe> pipe);
  void OnMessage(base::DictValue message);
  void OnDisconnected();
  void SendState();
  void Send(base::DictValue message);
  void RunCommand(const base::DictValue& message);
  void FinishDOM(std::string id, int tab_id, uint64_t epoch,
                 content::WeakDocumentPtr document, base::Value value);
  void Reply(std::string_view id, base::Value result);
  void Error(std::string_view id, std::string_view error);
  content::WebContents* FindTab(int id) const;
  bool Eligible(content::WebContents* contents) const;
  bool Authorized(content::WebContents* contents) const;
  raw_ptr<Profile> profile_;
  std::map<int, std::string> grants_;
  std::set<std::string> mission_grants_;
  base::ListValue mission_audit_;
  bool enabled_ = false;
  bool allow_new_tabs_ = false;
  bool connected_ = false;
  std::string runtime_id_;
  std::string error_;
  uint64_t epoch_ = 0;
  scoped_refptr<AgentPipe> pipe_;
  base::WeakPtrFactory<KumoAgentService> weak_factory_{this};
};
}  // namespace kumo
#endif
