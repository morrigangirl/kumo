// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/agents/kumo_agent_service.h"
#include <array>
#include "base/time/time.h"
#include "chrome/browser/kumo/missions/kumo_mission_store.h"
#include <atomic>
#include <cmath>
#include <set>
#include <utility>
#include <unistd.h>
#include <fcntl.h>
#include "base/apple/bundle_locations.h"
#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/process/launch.h"
#include "base/process/process.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/lock.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "chrome/browser/kumo/agents/kumo_agent_dom.h"
#include "chrome/browser/kumo/agents/kumo_agent_pipe.h"
#include "chrome/browser/kumo/agents/kumo_agent_process.h"
#include "chrome/browser/kumo/actions/kumo_helper_process.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/browser_window/public/browser_window_interface.h"
#include "chrome/browser/ui/browser_window/public/browser_window_interface_iterator.h"
#include "chrome/browser/ui/tabs/tab_strip_model.h"
#include "chrome/common/chrome_isolated_world_ids.h"
#include "components/sessions/content/session_tab_helper.h"
#include "content/public/browser/navigation_controller.h"
#include "content/public/browser/navigation_handle.h"
#include "content/public/browser/page_navigator.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_contents_observer.h"
#include "crypto/hash.h"
#include "ui/base/page_transition_types.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace kumo {
namespace {
constexpr char kServiceKey[] = "kumo-native-agent-service";
constexpr char kObserverKey[] = "kumo-native-agent-tab-observer";
constexpr size_t kMaxMessage = 1024 * 1024;
int TabID(content::WebContents* tab) { return sessions::SessionTabHelper::IdForTab(tab).id(); }
bool HTTP(const GURL& url) { return url.is_valid() && url.SchemeIsHTTPOrHTTPS() && !url.has_username() && !url.has_password(); }
std::string PublicURL(const GURL& url) { GURL::Replacements clean; clean.ClearQuery(); clean.ClearRef(); return url.ReplaceComponents(clean).spec().substr(0, 8192); }
base::DictValue Failure(std::string_view error) { return base::DictValue().Set("ok", false).Set("error", std::string(error)); }

bool ValidCommand(std::string_view action, const base::DictValue& p) {
  if (action.starts_with("missions.")) return missions::ValidRequest(action, p);
  std::set<std::string_view> fields;
  if (action == "tabs.list") {}
  else if (action == "tab.open") fields = {"url"};
  else if (action == "tab.navigate") fields = {"tabId", "url"};
  else if (action == "tab.snapshot" || action == "tab.close") fields = {"tabId"};
  else if (action == "tab.click") fields = {"tabId", "selector"};
  else if (action == "tab.type") fields = {"tabId", "selector", "text"};
  else if (action == "tab.scroll") fields = {"tabId", "x", "y"};
  else return false;
  if (p.size() != fields.size()) return false;
  for (auto field : fields) if (!p.contains(field)) return false;
  if (fields.contains("tabId") && (!p.FindInt("tabId") || *p.FindInt("tabId") < 0)) return false;
  if (fields.contains("url")) { auto* url = p.FindString("url"); if (!url || url->size() > 8192 || !HTTP(GURL(*url))) return false; }
  if (fields.contains("selector")) { auto* selector = p.FindString("selector"); if (!selector || selector->empty() || selector->size() > 512) return false; }
  if (fields.contains("text")) { auto* text = p.FindString("text"); if (!text || text->size() > 20000) return false; }
  for (auto field : {"x", "y"}) if (fields.contains(field)) { const auto n = p.FindDouble(field); if (!n || !std::isfinite(*n) || std::abs(*n) > 100000) return false; }
  return true;
}
class TabObserver final : public content::WebContentsObserver, public base::SupportsUserData::Data {
 public:
  explicit TabObserver(content::WebContents* contents) : content::WebContentsObserver(contents) {}
  void DidStartNavigation(content::NavigationHandle* handle) override {
    if (handle->IsInPrimaryMainFrame() && !handle->IsSameDocument()) Changed(false);
  }
  void DidFinishNavigation(content::NavigationHandle* handle) override {
    if (handle->IsInPrimaryMainFrame() && handle->HasCommitted()) Changed(false, true);
  }
  void WebContentsDestroyed() override { Changed(true, true); }
 private:
  void Changed(bool destroyed, bool committed = false) {
    auto* profile = Profile::FromBrowserContext(web_contents()->GetBrowserContext());
    if (auto* service = static_cast<KumoAgentService*>(profile->GetUserData(kServiceKey))) service->TabChanged(web_contents(), destroyed, committed);
  }
};
}  // namespace

// Bounded nonblocking pipe I/O lives on worker sequences. It owns this child,
// never a PID supplied by the renderer. Browser close terminates the child and
// invalidates every callback; no detached or public broker remains.
class AgentPipe : public base::RefCountedThreadSafe<AgentPipe> {
 public:
  AgentPipe(base::ScopedFD writer, base::Process process) : writer_(std::move(writer)), child_(process.Release()), writes_(base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock(), base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN})) {}
  void Write(std::string body) {
    if (stopped_.load(std::memory_order_acquire)) return;
    const size_t size = body.size();
    if (queued_bytes_.fetch_add(size) + size > 4 * kMaxMessage) {
      queued_bytes_.fetch_sub(size); Stop(); return;
    }
    writes_->PostTask(FROM_HERE, base::BindOnce([](scoped_refptr<AgentPipe> self, std::string data) {
      base::ScopedFD writer;
      { // Only duplicate under the lock; no write or poll holds the UI lock.
        base::AutoLock guard(self->lock_);
        if (self->writer_.is_valid() && !self->stopped_.load())
          writer.reset(fcntl(self->writer_.get(), F_DUPFD_CLOEXEC, 0));
      }
      if (writer.is_valid() && !internal::WriteAgentFrame(writer.get(), data, self->stopped_)) self->Stop();
      else if (!writer.is_valid() && !self->stopped_.load()) self->Stop();
      self->queued_bytes_.fetch_sub(data.size());
    }, base::WrapRefCounted(this), std::move(body)));
  }
  void Stop() {
    stopped_.store(true, std::memory_order_release);
    { base::AutoLock guard(lock_); writer_.reset(); }
    const pid_t child = child_.Take();
    if (child > 0) {
      // Stop never waits on the UI sequence. The one owner finishes even during
      // browser shutdown; neither pipe EOF nor concurrent Stop can reap twice.
      base::ThreadPool::PostTask(FROM_HERE,
          {base::MayBlock(), base::TaskShutdownBehavior::BLOCK_SHUTDOWN},
          base::BindOnce([](pid_t owned_child) {
            internal::ReapOwnedAgentChild(owned_child);
          }, child));
    }
  }
 private:
  friend class base::RefCountedThreadSafe<AgentPipe>;
  ~AgentPipe() { Stop(); }
  base::Lock lock_;
  std::atomic_bool stopped_{false};
  std::atomic_size_t queued_bytes_{0};
  base::ScopedFD writer_;
  internal::OwnedAgentChild child_;
  scoped_refptr<base::SequencedTaskRunner> writes_;
};

KumoAgentService* KumoAgentService::Get(Profile* profile) {
  if (!profile || profile->IsOffTheRecord()) return nullptr;
  auto* value = static_cast<KumoAgentService*>(profile->GetUserData(kServiceKey));
  if (!value) { auto service = std::make_unique<KumoAgentService>(profile); value = service.get(); profile->SetUserData(kServiceKey, std::move(service)); value->Start(); }
  return value;
}
void KumoAgentService::AttachToWebContents(content::WebContents* contents) {
  if (!contents || Profile::FromBrowserContext(contents->GetBrowserContext())->IsOffTheRecord()) return;
  if (!contents->GetUserData(kObserverKey)) contents->SetUserData(kObserverKey, std::make_unique<TabObserver>(contents));
  Get(Profile::FromBrowserContext(contents->GetBrowserContext()));
}
KumoAgentService::KumoAgentService(Profile* profile) : profile_(profile) {
  const auto hash = crypto::hash::Sha256("Kumo native agent profile v1:" + profile->GetPath().value());
  runtime_id_ = base::ToLowerASCII(base::HexEncode(hash)).substr(0, 32);
}
KumoAgentService::~KumoAgentService() { weak_factory_.InvalidateWeakPtrs(); if (pipe_) pipe_->Stop(); }
std::string KumoAgentService::GetRuntimeId() const { return runtime_id_; }

void KumoAgentService::Start() {
  const base::FilePath contents = GetContentsPath();
  auto ui = base::SequencedTaskRunner::GetCurrentDefault(); auto weak = weak_factory_.GetWeakPtr();
  base::ThreadPool::PostTask(FROM_HERE, {base::MayBlock(), base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN}, base::BindOnce([](base::FilePath contents, std::string profile, scoped_refptr<base::SequencedTaskRunner> ui, base::WeakPtr<KumoAgentService> weak) {
    const base::FilePath relative("Resources/agent-bridge/bin/node");
    if (!VerifyHelper(contents, relative)) { ui->PostTask(FROM_HERE, base::BindOnce(&KumoAgentService::OnDisconnected, weak)); return; }
    const base::FilePath helper = contents.Append(relative);
    int input[2], output[2];
    if (pipe(input) != 0) { ui->PostTask(FROM_HERE, base::BindOnce(&KumoAgentService::OnDisconnected, weak)); return; }
    base::ScopedFD child_input(input[0]), writer(input[1]);
    if (pipe(output) != 0) { ui->PostTask(FROM_HERE, base::BindOnce(&KumoAgentService::OnDisconnected, weak)); return; }
    base::ScopedFD reader(output[0]), child_output(output[1]);
    const int flags = fcntl(writer.get(), F_GETFL);
    if (flags < 0 || fcntl(writer.get(), F_SETFL, flags | O_NONBLOCK) < 0 || fcntl(writer.get(), F_SETNOSIGPIPE, 1) < 0) { ui->PostTask(FROM_HERE, base::BindOnce(&KumoAgentService::OnDisconnected, weak)); return; }
    base::ScopedFD null(open("/dev/null", O_WRONLY | O_CLOEXEC));
    for (int fd : {input[0], input[1], output[0], output[1]}) fcntl(fd, F_SETFD, FD_CLOEXEC);
    base::LaunchOptions options; options.clear_environment = true;
    // Only native OS identity is consulted; no renderer supplies a home/PATH.
    base::FilePath home = base::GetHomeDir(); if (home.empty()) { ui->PostTask(FROM_HERE, base::BindOnce(&KumoAgentService::OnDisconnected, weak)); return; }
    options.environment["HOME"] = home.value(); options.environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin";
    options.fds_to_remap = {{child_input.get(), STDIN_FILENO}, {child_output.get(), STDOUT_FILENO}, {null.get(), STDERR_FILENO}};
    base::CommandLine command(helper); command.AppendArg("--jitless"); command.AppendArg("--no-expose-wasm"); command.AppendArgPath(contents.Append("Resources/agent-bridge/cli.mjs")); command.AppendArg("browser-channel"); command.AppendArg("--profile"); command.AppendArg(profile);
    base::Process process = base::LaunchProcess(command, options); child_input.reset(); child_output.reset();
    if (!process.IsValid()) { ui->PostTask(FROM_HERE, base::BindOnce(&KumoAgentService::OnDisconnected, weak)); return; }
    auto channel = base::MakeRefCounted<AgentPipe>(std::move(writer), std::move(process));
    ui->PostTask(FROM_HERE, base::BindOnce([](base::WeakPtr<KumoAgentService> service, scoped_refptr<AgentPipe> pipe) { if (service) service->OnPipeReady(pipe); else pipe->Stop(); }, weak, channel));
    base::File file(reader.release());
    while (true) {
      std::array<uint8_t,4> header; if (!file.ReadAtCurrentPosAndCheck(header)) break;
      uint32_t n = uint32_t(header[0]) | (uint32_t(header[1]) << 8) | (uint32_t(header[2]) << 16) | (uint32_t(header[3]) << 24);
      if (!n || n > kMaxMessage) break;
      std::string body(n, '\0'); if (!file.ReadAtCurrentPosAndCheck(base::as_writable_byte_span(body))) break;
      auto value = base::JSONReader::ReadDict(body, base::JSON_PARSE_RFC, 32); if (!value) break;
      ui->PostTask(FROM_HERE, base::BindOnce(&KumoAgentService::OnMessage, weak, std::move(*value)));
    }
    channel->Stop(); ui->PostTask(FROM_HERE, base::BindOnce(&KumoAgentService::OnDisconnected, weak));
  }, contents, runtime_id_, ui, weak));
}
void KumoAgentService::OnPipeReady(scoped_refptr<AgentPipe> pipe) { pipe_ = std::move(pipe); }
void KumoAgentService::OnDisconnected() { mission_grants_.clear(); connected_ = false; enabled_ = false; allow_new_tabs_ = false; grants_.clear(); ++epoch_; error_ = "Browser agent runtime is unavailable. Reinstall Kumo to repair it."; if (pipe_) pipe_->Stop(); pipe_.reset(); }
void KumoAgentService::OnMessage(base::DictValue message) {
  const auto* type = message.FindString("type"); if (!type) return;
  if (*type == "ready") { connected_ = true; error_.clear(); SendState(); }
  else if (*type == "command") RunCommand(message);
}
void KumoAgentService::Send(base::DictValue message) { std::string json; if (pipe_ && base::JSONWriter::Write(message, &json) && json.size() <= kMaxMessage) pipe_->Write(std::move(json)); }
void KumoAgentService::SendState() { base::ListValue missions; for (const auto& id : mission_grants_) missions.Append(id); base::ListValue list; for (const auto& [id, origin] : grants_) list.Append(base::DictValue().Set("tabId", id).Set("origin", origin)); Send(base::DictValue().Set("type", "state").Set("missions", std::move(missions)).Set("enabled", enabled_).Set("allowNewTabs", allow_new_tabs_).Set("grants", std::move(list))); }
base::DictValue KumoAgentService::GetStatus() { base::ListValue list; for (const auto& [id, origin] : grants_) list.Append(base::DictValue().Set("tabId", id).Set("origin", origin)); return base::DictValue().Set("enabled", enabled_).Set("allowNewTabs", allow_new_tabs_).Set("bridgeConnected", connected_).Set("bridgeError", error_).Set("grants", std::move(list)); }
bool KumoAgentService::Eligible(content::WebContents* tab) const { return tab && tab->GetBrowserContext() == profile_ && !profile_->IsOffTheRecord() && HTTP(tab->GetLastCommittedURL()) && tab->GetLastCommittedURL().host() != "chromewebstore.google.com" && !(tab->GetLastCommittedURL().host() == "chrome.google.com" && tab->GetLastCommittedURL().path().starts_with("/webstore")) && tab->GetPrimaryMainFrame() && tab->GetPrimaryMainFrame()->IsRenderFrameLive() && !tab->GetController().GetPendingEntry(); }
content::WebContents* KumoAgentService::FindTab(int id) const { for (auto* browser : GetAllBrowserWindowInterfaces()) if (browser->GetProfile() == profile_) { auto* tabs = browser->GetTabStripModel(); for (int i=0; tabs && i<tabs->count(); ++i) if (TabID(tabs->GetWebContentsAt(i)) == id) return tabs->GetWebContentsAt(i); } return nullptr; }
bool KumoAgentService::Authorized(content::WebContents* tab) const { if (!enabled_ || !Eligible(tab)) return false; auto found = grants_.find(TabID(tab)); return found != grants_.end() && tab->GetPrimaryMainFrame()->GetLastCommittedOrigin().Serialize() == found->second; }
base::ListValue KumoAgentService::GetEligibleTabs() { base::ListValue list; for (auto* browser : GetAllBrowserWindowInterfaces()) if (browser->GetProfile() == profile_) { auto* tabs = browser->GetTabStripModel(); for (int i=0; tabs && i<tabs->count(); ++i) { auto* tab=tabs->GetWebContentsAt(i); if (Eligible(tab)) list.Append(base::DictValue().Set("tabId",TabID(tab)).Set("url",PublicURL(tab->GetLastCommittedURL())).Set("origin",tab->GetPrimaryMainFrame()->GetLastCommittedOrigin().Serialize()).Set("title",base::UTF16ToUTF8(tab->GetTitle()).substr(0, 512))); } } return list; }
void KumoAgentService::SetGrants(const base::ListValue& list, bool allow_new, base::OnceCallback<void(base::DictValue)> callback) {
  Revoke(); std::map<int,std::string> selected;
  if (list.size()>1000 || !connected_) { std::move(callback).Run(Failure("Browser agent runtime is not ready.")); return; }
  for (const auto& row : list) { const auto* grant=row.GetIfDict(); const auto id=grant ? grant->FindInt("tabId") : std::nullopt; const auto* origin=grant ? grant->FindString("origin") : nullptr; auto* tab=id ? FindTab(*id) : nullptr; if (!grant || grant->size()!=2 || !id || !origin || selected.contains(*id) || !Eligible(tab) || tab->GetPrimaryMainFrame()->GetLastCommittedOrigin().Serialize()!=*origin) { std::move(callback).Run(Failure("A selected tab changed. Review the tab list and try again.")); return; } selected.emplace(*id,*origin); }
  grants_=std::move(selected); enabled_=true; allow_new_tabs_=allow_new; ++epoch_; SendState(); std::move(callback).Run(base::DictValue().Set("ok",true));
}
void KumoAgentService::Revoke() { enabled_=false; allow_new_tabs_=false; grants_.clear(); ++epoch_; SendState(); }
base::DictValue KumoAgentService::SetMissionGrants(const base::ListValue& ids) {
  std::set<std::string> available, selected;
  for (const auto& m : missions::List(profile_->GetPrefs())) available.insert(*m.GetDict().FindString("id"));
  if (ids.size()>100 || !connected_) return Failure("The agent bridge is not ready.");
  for (const auto& id : ids) {
    if (!id.is_string() || !available.contains(id.GetString()) || !selected.insert(id.GetString()).second)
      return Failure("Review the selected missions and try again.");
  }
  mission_grants_ = std::move(selected); SendState();
  return base::DictValue().Set("ok",true);
}
void KumoAgentService::RevokeMissions() { mission_grants_.clear(); SendState(); }
base::DictValue KumoAgentService::MissionStatus() {
  base::ListValue ids; for (const auto& id : mission_grants_) ids.Append(id);
  return base::DictValue().Set("grants",std::move(ids)).Set("audit",mission_audit_.Clone())
      .Set("connected",connected_).Set("readOnly",true);
}
void KumoAgentService::TabChanged(content::WebContents* contents, bool destroyed, bool committed) { if (!grants_.contains(TabID(contents))) return; ++epoch_; if (!destroyed && !committed) return; if (destroyed || !HTTP(contents->GetLastCommittedURL()) || contents->GetPrimaryMainFrame()->GetLastCommittedOrigin().Serialize()!=grants_[TabID(contents)]) { grants_.erase(TabID(contents)); SendState(); } }
void KumoAgentService::Reply(std::string_view id, base::Value result) { Send(base::DictValue().Set("type","result").Set("id",std::string(id)).Set("result",std::move(result))); }
void KumoAgentService::Error(std::string_view id, std::string_view error) { Send(base::DictValue().Set("type","result").Set("id",std::string(id)).Set("error",base::DictValue().Set("message",std::string(error)))); }
void KumoAgentService::RunCommand(const base::DictValue& message) {
  const auto* id=message.FindString("id"); const auto* action=message.FindString("action"); const auto* params=message.FindDict("params");
  if (!id || id->empty() || id->size()>100 || !action || !params || !ValidCommand(*action,*params)) { if (id) Error(*id,"Invalid browser command."); return; }
  if (action->starts_with("missions.")) {
    auto result = missions::Read(profile_->GetPrefs(), mission_grants_, *action, *params);
    if (result.FindBool("ok").value_or(false)) {
      if (mission_audit_.size() >= 100) mission_audit_.erase(mission_audit_.begin());
      mission_audit_.Append(base::DictValue().Set("action",*action)
          .Set("missionId",params->FindString("missionId") ? *params->FindString("missionId") : "")
          .Set("at",base::Time::Now().InMillisecondsFSinceUnixEpoch()));
      Reply(*id,base::Value(std::move(result)));
    } else Error(*id,*result.FindString("error"));
    return;
  }
  if (!enabled_) { Error(*id,"Browser control is disabled."); return; }
  if (*action=="tabs.list") { base::ListValue rows; for (const auto& row : GetEligibleTabs()) if (Authorized(FindTab(row.GetDict().FindInt("tabId").value()))) rows.Append(row.Clone()); Reply(*id,base::Value(std::move(rows))); return; }
  if (*action=="tab.open") {
    if (!allow_new_tabs_) { Error(*id,"Opening new tabs is not allowed."); return; }
    BrowserWindowInterface* target=nullptr; for (auto* browser : GetAllBrowserWindowInterfaces()) if (browser->GetProfile()==profile_ && (!target || browser->GetSessionID().id()<target->GetSessionID().id())) target=browser;
    if (!target) { Error(*id,"No ordinary Kumo window is available."); return; }
    auto* opened=target->OpenURL(content::OpenURLParams::CreateBrowserInitiated(GURL(*params->FindString("url")), WindowOpenDisposition::NEW_BACKGROUND_TAB, ui::PAGE_TRANSITION_TYPED), {});
    if (!opened) { Error(*id,"Kumo could not open the tab."); return; }
    // The native new-tab capability grants exactly the requested origin. Any
    // redirect to another origin revokes it before DOM access.
    grants_[TabID(opened)] = url::Origin::Create(GURL(*params->FindString("url"))).Serialize(); ++epoch_; SendState();
    Reply(*id,base::Value(base::DictValue().Set("tabId",TabID(opened)).Set("loading",true))); return;
  }
  const int tab_id=*params->FindInt("tabId"); auto* tab=FindTab(tab_id);
  if (!Authorized(tab)) { Error(*id,"This live tab and origin are not granted."); return; }
  if (*action=="tab.close") { grants_.erase(tab_id); ++epoch_; SendState(); tab->Close(); Reply(*id,base::Value(base::DictValue().Set("closeRequested",tab_id))); return; }
  if (*action=="tab.navigate") { GURL url(*params->FindString("url")); if (url::Origin::Create(url).Serialize()!=grants_[tab_id]) { Error(*id,"Cross-origin navigation requires a new grant."); return; } ++epoch_; tab->GetController().LoadURL(url,content::Referrer(),ui::PAGE_TRANSITION_TYPED,std::string()); Reply(*id,base::Value(base::DictValue().Set("navigating",true))); return; }
  auto* frame=tab->GetPrimaryMainFrame(); const auto document=frame->GetWeakDocumentPtr();
  base::ListValue args; args.Append(*action); args.Append(params->Clone()); args.Append(grants_[tab_id]); std::string json; base::JSONWriter::Write(args,&json);
  const std::string script=std::string(kAgentDOM)+"(..."+json+")";
  frame->ExecuteJavaScriptInIsolatedWorld(base::UTF8ToUTF16(script),base::BindOnce(&KumoAgentService::FinishDOM,weak_factory_.GetWeakPtr(),*id,tab_id,epoch_,document),ISOLATED_WORLD_ID_KUMO_AGENT);
}
void KumoAgentService::FinishDOM(std::string id, int tab_id, uint64_t epoch, content::WeakDocumentPtr document, base::Value value) { auto* tab=FindTab(tab_id); if (epoch!=epoch_ || !Authorized(tab) || !document.AsRenderFrameHostIfValid() || document.AsRenderFrameHostIfValid()!=tab->GetPrimaryMainFrame()) { Error(id,"The document changed or permission was revoked; result discarded."); return; } if (!value.is_dict()) { Error(id,"Page operation returned no result."); return; } if (auto* error=value.GetDict().FindString("error")) { Error(id,*error); return; } Reply(id,std::move(value)); }
}  // namespace kumo
