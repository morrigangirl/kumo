// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/protection/kumo_protection_service.h"

#include <cmath>
#include <deque>
#include <set>
#include <utility>
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/memory/raw_ptr.h"
#include "base/path_service.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/thread_pool.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/sequence_bound.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "base/uuid.h"
#include "chrome/browser/kumo/protection/model_channel.h"
#include "chrome/browser/kumo/actions/kumo_helper_process.h"
#include "chrome/browser/kumo/actions/kumo_preferences.h"
#include "chrome/browser/kumo/store/kumo_legacy_extension.h"
#include "chrome/browser/kumo/protection/protection_policy.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/common/chrome_isolated_world_ids.h"
#include "chrome/grit/browser_resources.h"
#include "components/prefs/pref_service.h"
#include "components/pref_registry/pref_registry_syncable.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/navigation_controller.h"
#include "content/public/browser/navigation_handle.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/storage_partition.h"
#include "content/public/browser/weak_document_ptr.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_contents_observer.h"
#include "content/public/browser/web_contents_user_data.h"
#include "crypto/sha2.h"
#include "extensions/browser/api/storage/settings_namespace.h"
#include "extensions/browser/api/storage/storage_frontend.h"
#include "extensions/browser/api/storage/storage_area_namespace.h"
#include "extensions/common/extension.h"
#include "extensions/common/mojom/manifest.mojom.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/http/http_response_headers.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/simple_url_loader.h"
#include "services/network/public/cpp/simple_url_loader_stream_consumer.h"
#include "services/network/public/mojom/fetch_api.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "ui/base/page_transition_types.h"
#include "ui/base/resource/resource_bundle.h"
#include "url/gurl.h"

namespace kumo {
namespace {
constexpr char kServiceKey[] = "kumo.native-protection";
constexpr char kPhishingPref[] = "kumo.protection.phishing_enabled";
constexpr char kMalwarePref[] = "kumo.protection.malware_enabled";
constexpr char kMigrationPref[] = "kumo.protection.legacy_migrated";
constexpr char kSnapshotPref[] = "kumo.protection.domain_snapshot";
constexpr auto kRefreshInterval = base::Hours(8);
constexpr auto kStaleInterval = base::Hours(48);

bool Eligible(const GURL& url) {
  return url.is_valid() && url.SchemeIsHTTPOrHTTPS() && !url.has_username() &&
         !url.has_password() && url.spec().size() <= 8192 &&
         url.host() != "chromewebstore.google.com" &&
         !(url.host() == "chrome.google.com" &&
           url.path().starts_with("/webstore"));
}
base::FilePath ContentsPath() {
  return GetContentsPath();
}
std::string Hash(std::string_view input) {
  return base::HexEncodeLower(crypto::SHA256HashString(input));
}
base::DictValue Error(std::string_view code) {
  return base::DictValue().Set("ok", false).Set("error", std::string(code));
}
std::optional<bool> UserBoolean(PrefService* prefs, const char* name) {
  const base::Value* value = prefs->GetUserPrefValue(name);
  return value && value->is_bool() ? std::optional(value->GetBool()) : std::nullopt;
}
struct DomainSnapshot {
  std::set<std::string, std::less<>> domains;
  std::string version;
  base::Time modified;
  std::string digest;
};
std::string CanonicalSnapshot(const DomainSnapshot& snapshot) {
  std::string text = snapshot.version + "\n" +
                     base::NumberToString(snapshot.modified.ToTimeT()) + "\n";
  for (const auto& domain : snapshot.domains) text += domain + "\n";
  return text;
}
bool ValidTime(base::Time time) {
  base::Time oldest;
  return base::Time::FromUTCString("01 Jan 2020 00:00 UTC", &oldest) &&
         time >= oldest && time <= base::Time::Now() + base::Minutes(5);
}
bool AddDomain(DomainSnapshot& snapshot, const std::string& value) {
  const GURL url("https://" + value + "/");
  return protection::ValidDomain(value) && url.is_valid() &&
         url.host() == value && snapshot.domains.emplace(value).second &&
         snapshot.domains.size() <= protection::kMaximumDomains;
}
std::optional<DomainSnapshot> ReadBundledDomains(base::FilePath directory) {
  std::string rules_text, metadata_text;
  if (!base::ReadFileToStringWithMaxSize(directory.AppendASCII("rules.json"),
                                       &rules_text, protection::kMaximumFeedBytes) ||
      !base::ReadFileToStringWithMaxSize(directory.AppendASCII("metadata.json"),
                                       &metadata_text, 65536))
    return std::nullopt;
  auto metadata = base::JSONReader::ReadDict(metadata_text, base::JSON_PARSE_RFC, 16);
  auto rules = base::JSONReader::ReadList(rules_text, base::JSON_PARSE_RFC, 32);
  if (!metadata || !rules || rules->empty() || rules->size() > 1000 ||
      metadata->FindInt("schemaVersion") != 1 ||
      metadata->FindString("updateURL") == nullptr ||
      *metadata->FindString("updateURL") != protection::kFeedURL ||
      metadata->FindString("ruleSetID") == nullptr ||
      *metadata->FindString("ruleSetID") != "kumo_malware" ||
      metadata->FindInt("rulesCount") != static_cast<int>(rules->size()))
    return std::nullopt;
  DomainSnapshot result;
  const auto* modified = metadata->FindString("modifiedAt");
  const auto* version = metadata->FindString("version");
  if (!modified || !version || version->empty() || version->size() > 80 ||
      !base::Time::FromUTCString(modified->c_str(), &result.modified) ||
      !ValidTime(result.modified))
    return std::nullopt;
  result.version = *version;
  for (const auto& value : *rules) {
    const auto* rule = value.GetIfDict();
    const auto* action = rule ? rule->FindDict("action") : nullptr;
    const auto* condition = rule ? rule->FindDict("condition") : nullptr;
    const auto* domains = condition ? condition->FindList("requestDomains") : nullptr;
    if (!action || action->FindString("type") == nullptr ||
        *action->FindString("type") != "block" || !domains || domains->empty() ||
        domains->size() > 1000)
      return std::nullopt;
    for (const auto& domain : *domains) {
      if (!domain.is_string() || !AddDomain(result, domain.GetString()))
        return std::nullopt;
    }
  }
  if (metadata->FindInt("domainCount") != static_cast<int>(result.domains.size()))
    return std::nullopt;
  result.digest = Hash(CanonicalSnapshot(result));
  return result;
}
base::DictValue SerializeSnapshot(const DomainSnapshot& snapshot) {
  base::ListValue domains;
  for (const auto& value : snapshot.domains) domains.Append(value);
  return base::DictValue().Set("schemaVersion", 1)
      .Set("version", snapshot.version)
      .Set("modifiedEpoch", snapshot.modified.InSecondsFSinceUnixEpoch())
      .Set("sha256", snapshot.digest).Set("domains", std::move(domains));
}
std::optional<DomainSnapshot> ReadCachedDomains(base::DictValue data) {
  const auto* version = data.FindString("version");
  const auto* digest = data.FindString("sha256");
  const auto* domains = data.FindList("domains");
  const auto modified = data.FindDouble("modifiedEpoch");
  if (data.FindInt("schemaVersion") != 1 || !version || !digest || !domains ||
      domains->empty() || domains->size() > protection::kMaximumDomains ||
      !modified || !std::isfinite(*modified))
    return std::nullopt;
  DomainSnapshot result;
  result.version = *version;
  result.modified = base::Time::FromSecondsSinceUnixEpoch(*modified);
  if (!ValidTime(result.modified)) return std::nullopt;
  for (const auto& domain : *domains) {
    if (!domain.is_string() || !AddDomain(result, domain.GetString()))
      return std::nullopt;
  }
  result.digest = Hash(CanonicalSnapshot(result));
  if (result.digest != *digest) return std::nullopt;
  return result;
}
std::optional<DomainSnapshot> ParseUpdate(std::string text, size_t minimum,
                                         std::string previous_version,
                                         base::Time previous_modified) {
  auto parsed = protection::ParseDomainFeed(text, minimum);
  if (!parsed) return std::nullopt;
  DomainSnapshot result;
  result.version = parsed->version;
  if (!base::Time::FromUTCString(parsed->modified.c_str(), &result.modified) ||
      !ValidTime(result.modified) || result.modified < previous_modified)
    return std::nullopt;
  base::Time::Exploded utc;
  result.modified.UTCExplode(&utc);
  const std::string prefix = base::StringPrintf("%04d.%02d%02d.%02d%02d.",
      utc.year, utc.month, utc.day_of_month, utc.hour, utc.minute);
  if (!result.version.starts_with(prefix)) return std::nullopt;
  uint64_t revision = 0, old_revision = 0;
  if (!base::StringToUint64(result.version.substr(prefix.size()), &revision))
    return std::nullopt;
  if (result.modified == previous_modified && previous_version.starts_with(prefix) &&
      base::StringToUint64(previous_version.substr(prefix.size()), &old_revision) &&
      revision < old_revision)
    return std::nullopt;
  for (const auto& domain : parsed->domains)
    if (!AddDomain(result, domain)) return std::nullopt;
  result.digest = Hash(CanonicalSnapshot(result));
  return result;
}
}  // namespace

struct KumoProtectionService::Impl : network::SimpleURLLoaderStreamConsumer {
  explicit Impl(Profile* value)
      : profile(value),
        cancel(std::make_shared<protection::ModelCancellation>()),
        channel(base::ThreadPool::CreateSequencedTaskRunner(
                    {base::MayBlock(), base::TaskPriority::USER_VISIBLE,
                     base::TaskShutdownBehavior::BLOCK_SHUTDOWN}),
                ContentsPath().AppendASCII("Helpers/KumoPhishing.app/Contents/MacOS/KumoPhishingHost"),
                cancel) {
    const auto directory = ContentsPath().AppendASCII("Resources/KumoProtection/malware");
    auto cached = profile->GetPrefs()->GetDict(kSnapshotPref).Clone();
    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
        base::BindOnce([](base::FilePath path, base::DictValue cache) {
          auto bundled = ReadBundledDomains(path);
          auto saved = ReadCachedDomains(std::move(cache));
          if (saved && (!bundled || saved->modified >= bundled->modified)) return saved;
          return bundled;
        }, directory, std::move(cached)),
        base::BindOnce(&Impl::DomainsLoaded, weak.GetWeakPtr()));
    Migrate();
  }
  ~Impl() override { cancel->Cancel(); }
  raw_ptr<Profile> profile;
  bool migration_complete = false;
  bool migration_attempt_finished = false;
  std::string migration_error;
  bool domains_loaded = false;
  std::optional<DomainSnapshot> snapshot;
  std::vector<base::OnceClosure> domain_waiters;
  std::string domain_error;
  base::RepeatingTimer refresh;
  std::unique_ptr<network::SimpleURLLoader> loader;
  std::string feed_body;
  ResultCallback update_callback;
  bool updating = false;
  uint64_t domain_epoch = 0;
  std::shared_ptr<protection::ModelCancellation> cancel;
  base::SequenceBound<protection::ModelChannel> channel;
  bool model_ready = false;
  bool model_starting = false;
  std::string model_version;
  std::string model_error;
  size_t pending_scans = 0;
  std::set<ProtectionObserver*> observers;
  base::WeakPtrFactory<Impl> weak{this};

  bool PhishingDesired() const { return profile->GetPrefs()->GetBoolean(kPhishingPref); }
  bool MalwareDesired() const { return profile->GetPrefs()->GetBoolean(kMalwarePref); }
  bool PhishingReady() const { return migration_complete && PhishingDesired() && model_ready; }
  void NotifyObservers();
  void FlushWaiters() {
    if (!domains_loaded || !migration_attempt_finished) return;
    auto callbacks = std::move(domain_waiters);
    for (auto& callback : callbacks) std::move(callback).Run();
  }
  void Migrate() {
    if (profile->GetPrefs()->GetBoolean(kMigrationPref)) {
      migration_complete = migration_attempt_finished = true;
      // Get() has not attached this newly constructed service to Profile yet.
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&Impl::RetireLegacy, weak.GetWeakPtr()));
      EnsureModel();
      return;
    }
    auto* frontend = extensions::StorageFrontend::Get(profile);
    if (!frontend || !frontend->IsStorageEnabled(extensions::settings_namespace::LOCAL)) {
      MigrationFailed(); return;
    }
    // This descriptor is never registered, installed, enabled or executed.
    // StorageFrontend needs only its fixed ID for the legacy storage area.
    base::DictValue manifest;
    manifest.Set("name", "Kumo legacy preference migration");
    manifest.Set("version", "1"); manifest.Set("manifest_version", 3);
    base::ListValue permissions; permissions.Append("storage");
    manifest.Set("permissions", std::move(permissions));
    std::u16string error;
    auto descriptor = extensions::Extension::Create(
        base::FilePath(), extensions::mojom::ManifestLocation::kInternal,
        manifest, extensions::Extension::NO_FLAGS,
        protection::kLegacyExtensionId, &error);
    if (!descriptor) { MigrationFailed(); return; }
    frontend->GetValues(std::move(descriptor), extensions::StorageAreaNamespace::kLocal,
        std::vector<std::string>{"phishingProtection", "malwareProtection", "preferences"},
        base::BindOnce(&Impl::LegacyRead, weak.GetWeakPtr()));
  }
  void MigrationFailed() {
    migration_attempt_finished = true;
    migration_error = "Legacy protection preferences could not be read. Review your protection settings.";
    FlushWaiters();
  }
  void LegacyRead(extensions::StorageFrontend::GetResult result) {
    if (!result.status.success || !result.data) { MigrationFailed(); return; }
    if (const auto* value = result.data->Find("preferences")) {
      const auto* preferences = value->GetIfDict();
      if (!preferences || !kumo::preferences::ImportLegacy(profile, *preferences)) {
        MigrationFailed(); return;
      }
    }
    auto* prefs = profile->GetPrefs();
    for (const auto& item : {std::pair{"phishingProtection", kPhishingPref},
                              std::pair{"malwareProtection", kMalwarePref}}) {
      const auto* legacy = result.data->Find(item.first);
      std::optional<bool> old_value;
      if (legacy) {
        const auto* object = legacy->GetIfDict();
        const auto* value = object ? object->Find("enabled") : nullptr;
        if (!object || (value && !value->is_bool())) {
          if (!UserBoolean(prefs, item.second)) { MigrationFailed(); return; }
        } else if (value) old_value = value->GetBool();
      }
      if (!UserBoolean(prefs, item.second) && old_value)
        prefs->SetBoolean(item.second, protection::ResolveEnabled(std::nullopt, old_value));
    }
    prefs->SetBoolean(kMigrationPref, true);
    // Completion gates collection and legacy retirement. The old storage is
    // deliberately retained, so a failed disk write can be retried next launch.
    prefs->CommitPendingWrite(base::BindOnce(&Impl::MigrationCommitted, weak.GetWeakPtr()));
  }
  void MigrationCommitted() {
    migration_error.clear(); migration_complete = migration_attempt_finished = true;
    RetireLegacy();
    FlushWaiters(); EnsureModel(); ScheduleRefresh(); NotifyObservers();
  }
  void RetireLegacy() { RetireLegacyProductExtension(profile); }
  void DomainsLoaded(std::optional<DomainSnapshot> value) {
    snapshot = std::move(value); domains_loaded = true;
    if (!snapshot) domain_error = "The verified domain list is unavailable.";
    FlushWaiters(); ScheduleRefresh();
  }
  void ScheduleRefresh() {
    refresh.Stop();
    if (!migration_complete || !MalwareDesired() || !domains_loaded) return;
    refresh.Start(FROM_HERE, kRefreshInterval, base::BindRepeating(
        [](base::WeakPtr<Impl> self) { if (self) self->StartUpdate(ResultCallback()); },
        weak.GetWeakPtr()));
    if (snapshot && base::Time::Now() - snapshot->modified >= kRefreshInterval && !updating)
      StartUpdate(ResultCallback());
  }
  void EnsureModel() {
    if (!migration_complete || !PhishingDesired() || model_starting || model_ready) return;
    model_starting = true; model_error.clear();
    const auto generation = cancel->generation.load();
    auto request = base::DictValue().Set("id", base::Uuid::GenerateRandomV4().AsLowercaseString()).Set("type", "status");
    channel.AsyncCall(&protection::ModelChannel::Request).WithArgs(std::move(request), generation)
        .Then(base::BindOnce(&Impl::ModelStatus, weak.GetWeakPtr(), generation));
  }
  void ModelStatus(uint64_t generation, base::DictValue response) {
    if (generation != cancel->generation.load()) return;
    model_starting = false;
    const auto* version = response.FindString("modelVersion");
    model_ready = response.FindBool("ok").value_or(false) &&
                  response.FindBool("available").value_or(false) && version &&
                  version->size() == 40 &&
                  version->find_first_not_of("0123456789abcdef") == std::string::npos;
    if (model_ready) model_version = *version;
    else {
      model_error = "The local model is unavailable. Pages may go unchecked.";
      cancel->Cancel(); channel.AsyncCall(&protection::ModelChannel::Stop);
    }
    NotifyObservers();
  }
  bool Classify(std::string text, base::OnceCallback<void(base::DictValue)> callback) {
    if (!PhishingReady() || text.empty() || text.size() > protection::kMaximumSampleBytes ||
        pending_scans >= protection::kMaximumPendingScans) return false;
    ++pending_scans;
    const auto generation = cancel->generation.load();
    auto request = base::DictValue().Set("id", base::Uuid::GenerateRandomV4().AsLowercaseString())
        .Set("type", "classify").Set("text", std::move(text));
    channel.AsyncCall(&protection::ModelChannel::Request).WithArgs(std::move(request), generation)
        .Then(base::BindOnce(&Impl::Classified, weak.GetWeakPtr(), generation, std::move(callback)));
    return true;
  }
  void Classified(uint64_t generation, base::OnceCallback<void(base::DictValue)> callback,
                  base::DictValue response) {
    if (pending_scans) --pending_scans;
    if (generation != cancel->generation.load() || !PhishingDesired()) return;
    if (!response.FindBool("ok").value_or(false)) {
      model_ready = false; model_error = "The local model is unavailable. Pages may go unchecked.";
      cancel->Cancel(); channel.AsyncCall(&protection::ModelChannel::Stop);
    }
    std::move(callback).Run(std::move(response));
  }
  void StartUpdate(ResultCallback callback) {
    if (!migration_complete || !MalwareDesired()) {
      if (callback) std::move(callback).Run(Error("Domain protection is off or not initialized."));
      return;
    }
    if (updating) {
      if (callback) std::move(callback).Run(Error("A list update is already running."));
      return;
    }
    updating = true; update_callback = std::move(callback); feed_body.clear();
    auto request = std::make_unique<network::ResourceRequest>();
    request->url = GURL(protection::kFeedURL);
    request->method = "GET";
    request->credentials_mode = network::mojom::CredentialsMode::kOmit;
    request->load_flags = net::LOAD_DISABLE_CACHE;
    constexpr auto annotation = net::DefineNetworkTrafficAnnotation("kumo_native_domain_feed", R"(
      semantics {
        sender: "Kumo local domain protection"
        description: "Downloads the public fixed threat-domain list. No visited URL, page content or file is sent."
        trigger: "Protection enabled, every eight hours, or the user's Update list button."
        data: "No user data; a fixed HTTPS GET without cookies or credentials."
        destination: OTHER
        destination_other: "raw.githubusercontent.com/hagezi/dns-blocklists"
      }
      policy { cookies_allowed: NO setting: "Kumo Settings domain protection toggle." policy_exception_justification: "Not implemented." }
    )");
    loader = network::SimpleURLLoader::Create(std::move(request), annotation);
    loader->SetTimeoutDuration(base::Seconds(30));
    loader->SetOnRedirectCallback(base::BindRepeating(
        [](base::WeakPtr<Impl> self, const GURL&, const net::RedirectInfo&,
           const network::mojom::URLResponseHead&, std::vector<std::string>*) {
          if (self) self->UpdateFailed("List redirects are not permitted.");
        }, weak.GetWeakPtr()));
    loader->DownloadAsStream(profile->GetDefaultStoragePartition()
        ->GetURLLoaderFactoryForBrowserProcess().get(), this);
  }
  void OnDataReceived(std::string_view bytes, base::OnceClosure resume) override {
    if (bytes.size() > protection::kMaximumFeedBytes - feed_body.size()) {
      UpdateFailed("The list update exceeded its size limit."); return;
    }
    feed_body.append(bytes); std::move(resume).Run();
  }
  void OnRetry(base::OnceClosure retry) override {
    // Retries are deliberately not enabled; reject unexpected retry requests.
    UpdateFailed("The list update could not complete.");
  }
  void OnComplete(bool success) override {
    const bool valid = success && loader && loader->NetError() == net::OK &&
        loader->ResponseInfo() && loader->ResponseInfo()->headers &&
        loader->ResponseInfo()->headers->response_code() == 200;
    loader.reset();
    if (!valid) { UpdateFailed("The list update failed. Existing rules are retained."); return; }
    const auto epoch = domain_epoch;
    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
        base::BindOnce(&ParseUpdate, std::move(feed_body), snapshot ? std::max<size_t>(1, snapshot->domains.size() / 2) : 1,
                       snapshot ? snapshot->version : std::string(), snapshot ? snapshot->modified : base::Time()),
        base::BindOnce(&Impl::UpdateParsed, weak.GetWeakPtr(), epoch));
  }
  void UpdateParsed(uint64_t epoch, std::optional<DomainSnapshot> value) {
    if (epoch != domain_epoch || !MalwareDesired()) {
      UpdateFailed("Protection changed during the list update."); return;
    }
    if (!value) { UpdateFailed("The new list could not be verified. Existing rules are retained."); return; }
    profile->GetPrefs()->SetDict(kSnapshotPref, SerializeSnapshot(*value));
    snapshot = std::move(value); domain_error.clear(); updating = false;
    if (update_callback) std::move(update_callback).Run(base::DictValue().Set("ok", true));
  }
  void UpdateFailed(std::string message) {
    loader.reset(); feed_body.clear(); domain_error = std::move(message); updating = false;
    if (update_callback) std::move(update_callback).Run(Error(domain_error));
  }
};

class ProtectionObserver final : public content::WebContentsObserver,
                                 public content::WebContentsUserData<ProtectionObserver> {
 public:
  ~ProtectionObserver() override {
    if (service_) service_->impl_->observers.erase(this);
  }
  void SettingsChanged() {
    ++generation_; pending_ = false; attempts_ = 0; last_payload_.clear();
    last_sample_ = base::TimeTicks();
    ticket_.clear(); pending_bypass_ = GURL(); bypass_ = content::WeakDocumentPtr();
    auto* frame = web_contents()->GetPrimaryMainFrame();
    if (frame && frame->IsActive() && frame->IsRenderFrameLive() &&
        Eligible(web_contents()->GetLastCommittedURL())) {
      // Disconnect the previous document's collector even when turning off.
      // This reads only our isolated-world state, never website contents.
      frame->ExecuteJavaScriptInIsolatedWorld(
          u"(()=>{const k=Symbol.for('app.kumo.native-phishing-sampler.v1');const s=globalThis[k];if(s){s.observer.disconnect();delete globalThis[k];}})()",
          base::NullCallback(), ISOLATED_WORLD_ID_KUMO_PHISHING);
    }
    timer_.Start(FROM_HERE, base::Seconds(2), this, &ProtectionObserver::Sample);
    Sample();
  }
  base::DictValue WarningDetails() const {
    if (!ValidTicket()) return Error("This warning expired. Leave this site.");
    return base::DictValue().Set("ok", true).Set("origin", ticket_url_.DeprecatedGetOriginAsURL().spec())
        .Set("coverageLimited", coverage_limited_);
  }
  bool ResolveWarning(bool continue_site) {
    if (!ValidTicket()) return false;
    const GURL destination = continue_site ? ticket_url_ : GURL("about:blank");
    ticket_.clear();
    pending_bypass_ = continue_site ? destination : GURL();
    web_contents()->GetController().LoadURL(destination, content::Referrer(),
        ui::PAGE_TRANSITION_AUTO_TOPLEVEL, std::string());
    return true;
  }
 private:
  friend class content::WebContentsUserData<ProtectionObserver>;
  explicit ProtectionObserver(content::WebContents* contents,
                               base::WeakPtr<KumoProtectionService> service)
      : content::WebContentsObserver(contents),
        content::WebContentsUserData<ProtectionObserver>(*contents), service_(service) {
    service_->impl_->observers.insert(this);
    timer_.Start(FROM_HERE, base::Seconds(2), this, &ProtectionObserver::Sample);
  }
  void DidStartNavigation(content::NavigationHandle* handle) override {
    if (handle->IsInPrimaryMainFrame()) { ++generation_; pending_ = false; }
  }
  void DidFinishNavigation(content::NavigationHandle* handle) override {
    if (!handle->IsInPrimaryMainFrame() || !handle->HasCommitted()) return;
    if (!handle->IsSameDocument()) {
      attempts_ = 0; last_payload_.clear(); pending_ = false;
      last_sample_ = base::TimeTicks();
      bypass_ = content::WeakDocumentPtr();
      if (pending_bypass_.is_valid() && handle->GetURL() == pending_bypass_ && !handle->IsErrorPage())
        bypass_ = handle->GetRenderFrameHost()->GetWeakDocumentPtr();
      pending_bypass_ = GURL();
    }
    if (web_contents()->GetLastCommittedURL() != WarningURL()) ticket_.clear();
  }
  void DidStopLoading() override { Sample(); }
  void DOMContentLoaded(content::RenderFrameHost* frame) override {
    if (frame->IsInPrimaryMainFrame()) Sample();
  }
  bool EligibleNow() const {
    if (!service_ || !service_->impl_->PhishingReady() ||
        web_contents()->GetBrowserContext()->IsOffTheRecord() ||
        web_contents()->IsLoading() || attempts_ >= 8 || pending_ ||
        (!last_sample_.is_null() && base::TimeTicks::Now() - last_sample_ < base::Seconds(2)))
      return false;
    auto* frame = web_contents()->GetPrimaryMainFrame();
    return frame && frame->IsActive() && frame->IsRenderFrameLive() &&
           !frame->IsErrorDocument() && Eligible(web_contents()->GetLastCommittedURL()) &&
           bypass_.AsRenderFrameHostIfValid() != frame;
  }
  void Sample() {
    if (!EligibleNow()) return;
    auto* frame = web_contents()->GetPrimaryMainFrame();
    const auto document = frame->GetWeakDocumentPtr();
    const GURL url = web_contents()->GetLastCommittedURL();
    const auto generation = generation_;
    pending_ = true;
    const std::string script = ui::ResourceBundle::GetSharedInstance()
        .LoadDataResourceString(IDR_KUMO_PHISHING_SAMPLER_JS);
    frame->ExecuteJavaScriptInIsolatedWorld(base::UTF8ToUTF16(script),
        base::BindOnce(&ProtectionObserver::Sampled, weak_.GetWeakPtr(),
                       document, url, generation), ISOLATED_WORLD_ID_KUMO_PHISHING);
  }
  bool Current(const content::WeakDocumentPtr& document, const GURL& url,
               uint64_t generation) const {
    auto* frame = document.AsRenderFrameHostIfValid();
    return service_ && service_->impl_->PhishingReady() &&
           generation == generation_ && frame && frame->IsActive() &&
           frame == web_contents()->GetPrimaryMainFrame() &&
           !web_contents()->IsLoading() && web_contents()->GetLastCommittedURL() == url;
  }
  void Sampled(content::WeakDocumentPtr document, GURL url,
               uint64_t generation, base::Value value) {
    if (generation != generation_) return;
    pending_ = false;
    if (!Current(document, url, generation)) return;
    const auto* sample = value.GetIfDict();
    const auto* sampled_url = sample ? sample->FindString("url") : nullptr;
    if (!sample || !sampled_url || GURL(*sampled_url) != url ||
        sample->FindBool("unchanged").value_or(false)) return;
    const auto* text = sample->FindString("text");
    const auto revision = sample->FindInt("revision");
    if (!text || text->empty() || text->size() > protection::kMaximumSampleBytes ||
        !revision || *revision < 0 || *text == last_payload_) return;
    const bool limited = sample->FindBool("coverageLimited").value_or(true) || attempts_ >= 7;
    pending_ = service_->impl_->Classify(*text,
        base::BindOnce(&ProtectionObserver::Classified, weak_.GetWeakPtr(),
                       document, url, generation, *revision, limited));
    if (pending_) { ++attempts_; last_payload_ = *text; last_sample_ = base::TimeTicks::Now(); }
    else {
      // Queue saturation does not consume this document's retry budget.
      document.AsRenderFrameHostIfValid()->ExecuteJavaScriptInIsolatedWorld(
          u"(()=>{const s=globalThis[Symbol.for('app.kumo.native-phishing-sampler.v1')];if(s)s.sampledRevision=-1;})()",
          base::NullCallback(), ISOLATED_WORLD_ID_KUMO_PHISHING);
    }
  }
  void Classified(content::WeakDocumentPtr document, GURL url,
                  uint64_t generation, int revision, bool limited,
                  base::DictValue result) {
    if (generation != generation_) return;
    pending_ = false;
    if (!Current(document, url, generation) || !result.FindBool("ok").value_or(false)) return;
    const auto probability = result.FindDouble("probability");
    const auto windows = result.FindInt("windows");
    const auto tokens = result.FindInt("tokenCount");
    if (!probability || !std::isfinite(*probability) || *probability < 0 || *probability > 1 ||
        !windows || *windows < 1 || *windows > 8 || !tokens || *tokens < 0 || *probability < 0.9)
      return;
    auto* frame = document.AsRenderFrameHostIfValid();
    frame->ExecuteJavaScriptInIsolatedWorld(
        u"(()=>{const s=globalThis[Symbol.for('app.kumo.native-phishing-sampler.v1')];return {url:location.href,revision:s?s.revision:-1};})()",
        base::BindOnce(&ProtectionObserver::Confirm, weak_.GetWeakPtr(), document,
                       url, generation, revision,
                       limited || result.FindBool("coverageLimited").value_or(false) ||
                           result.FindBool("truncated").value_or(false)),
        ISOLATED_WORLD_ID_KUMO_PHISHING);
  }
  void Confirm(content::WeakDocumentPtr document, GURL url, uint64_t generation,
               int revision, bool limited, base::Value result) {
    if (!Current(document, url, generation)) return;
    const auto* value = result.GetIfDict();
    if (!value || value->FindInt("revision") != revision || !value->FindString("url") ||
        GURL(*value->FindString("url")) != url) return;
    ticket_ = base::Uuid::GenerateRandomV4().AsLowercaseString();
    ticket_url_ = url; ticket_expires_ = base::TimeTicks::Now() + base::Minutes(10);
    coverage_limited_ = limited;
    web_contents()->GetController().LoadURL(WarningURL(), content::Referrer(),
        ui::PAGE_TRANSITION_AUTO_TOPLEVEL, std::string());
  }
  GURL WarningURL() const {
    return ticket_.empty() ? GURL() : GURL("chrome://kumo-phishing-warning/?ticket=" + ticket_);
  }
  bool ValidTicket() const {
    return service_ && service_->impl_->PhishingReady() && !ticket_.empty() &&
           base::TimeTicks::Now() < ticket_expires_ &&
           web_contents()->GetLastCommittedURL() == WarningURL() && Eligible(ticket_url_);
  }
  base::WeakPtr<KumoProtectionService> service_;
  base::RepeatingTimer timer_;
  uint64_t generation_ = 0;
  bool pending_ = false;
  int attempts_ = 0;
  std::string last_payload_;
  base::TimeTicks last_sample_;
  std::string ticket_;
  GURL ticket_url_;
  base::TimeTicks ticket_expires_;
  bool coverage_limited_ = false;
  GURL pending_bypass_;
  content::WeakDocumentPtr bypass_;
  base::WeakPtrFactory<ProtectionObserver> weak_{this};
  WEB_CONTENTS_USER_DATA_KEY_DECL();
};
WEB_CONTENTS_USER_DATA_KEY_IMPL(ProtectionObserver);

void KumoProtectionService::Impl::NotifyObservers() {
  for (auto* observer : observers) observer->SettingsChanged();
}
KumoProtectionService* KumoProtectionService::Get(Profile* profile) {
  profile = profile->GetOriginalProfile();
  auto* value = static_cast<KumoProtectionService*>(profile->GetUserData(kServiceKey));
  if (!value) {
    auto service = std::unique_ptr<KumoProtectionService>(new KumoProtectionService(profile));
    value = service.get(); profile->SetUserData(kServiceKey, std::move(service));
  }
  return value;
}
KumoProtectionService::KumoProtectionService(Profile* profile) : impl_(std::make_unique<Impl>(profile)) {}
KumoProtectionService::~KumoProtectionService() = default;
base::WeakPtr<KumoProtectionService> KumoProtectionService::GetWeakPtr() { return weak_factory_.GetWeakPtr(); }
void KumoProtectionService::RegisterProfilePrefs(user_prefs::PrefRegistrySyncable* registry) {
  registry->RegisterBooleanPref(kPhishingPref, true);
  registry->RegisterBooleanPref(kMalwarePref, true);
  registry->RegisterBooleanPref(kMigrationPref, false);
  registry->RegisterDictionaryPref(kSnapshotPref);
}
bool KumoProtectionService::MigrationComplete() const { return impl_->migration_complete; }
bool KumoProtectionService::DomainsReady() const { return impl_->domains_loaded && impl_->migration_attempt_finished; }
bool KumoProtectionService::ShouldBlock(const GURL& url) const {
  return impl_->migration_complete && impl_->MalwareDesired() && impl_->snapshot &&
         (url.SchemeIsHTTPOrHTTPS() || url.SchemeIsWSOrWSS()) &&
         protection::ListedDomain(impl_->snapshot->domains, url.host());
}
void KumoProtectionService::WhenDomainsReady(base::OnceClosure callback) {
  if (DomainsReady()) std::move(callback).Run();
  else impl_->domain_waiters.push_back(std::move(callback));
}
base::DictValue KumoProtectionService::GetStatus() {
  const bool desired = impl_->PhishingDesired();
  const std::string health = !desired ? "off" : !impl_->migration_complete ? "migration-pending" :
      impl_->model_starting ? "starting" : impl_->model_ready ? "ready" : "unavailable";
  base::DictValue phishing;
  phishing.Set("included", true); phishing.Set("enabled", desired);
  phishing.Set("desiredEnabled", desired); phishing.Set("available", impl_->PhishingReady());
  phishing.Set("health", health); phishing.Set("modelVersion", impl_->model_version);
  phishing.Set("error", impl_->model_error); phishing.Set("localOnly", true);
  base::DictValue malware;
  malware.Set("enabled", impl_->MalwareDesired());
  malware.Set("available", impl_->snapshot.has_value() && impl_->migration_complete);
  malware.Set("health", !impl_->MalwareDesired() ? "off" : !DomainsReady() ? "starting" :
      impl_->snapshot && impl_->migration_complete ? "ready" : "unavailable");
  malware.Set("domainCount", impl_->snapshot ? static_cast<int>(impl_->snapshot->domains.size()) : 0);
  malware.Set("version", impl_->snapshot ? impl_->snapshot->version : std::string());
  malware.Set("stale", impl_->snapshot && base::Time::Now() - impl_->snapshot->modified > kStaleInterval);
  malware.Set("lastError", impl_->domain_error); malware.Set("updating", impl_->updating);
  return base::DictValue().Set("phishing", std::move(phishing)).Set("malware", std::move(malware))
      .Set("migrationComplete", impl_->migration_complete).Set("migrationError", impl_->migration_error);
}
void KumoProtectionService::SetPhishingEnabled(bool enabled) {
  impl_->profile->GetPrefs()->SetBoolean(kPhishingPref, enabled);
  impl_->cancel->Cancel(); impl_->model_ready = impl_->model_starting = false;
  impl_->channel.AsyncCall(&protection::ModelChannel::Stop);
  if (!impl_->migration_complete) impl_->Migrate();
  impl_->NotifyObservers();
  if (enabled) impl_->EnsureModel();
}
void KumoProtectionService::SetMalwareEnabled(bool enabled) {
  impl_->profile->GetPrefs()->SetBoolean(kMalwarePref, enabled);
  ++impl_->domain_epoch;
  if (impl_->updating) impl_->UpdateFailed("Protection settings changed.");
  else impl_->domain_error.clear();
  if (!impl_->migration_complete) impl_->Migrate();
  impl_->ScheduleRefresh();
}
void KumoProtectionService::UpdateDomains(ResultCallback callback) { impl_->StartUpdate(std::move(callback)); }
void KumoProtectionService::AttachToWebContents(content::WebContents* contents) {
  if (!contents->GetBrowserContext()->IsOffTheRecord())
    ProtectionObserver::CreateForWebContents(contents, GetWeakPtr());
}
base::DictValue KumoProtectionService::WarningDetails(content::WebContents* contents) {
  auto* observer = ProtectionObserver::FromWebContents(contents);
  return observer ? observer->WarningDetails() : Error("This warning expired. Leave this site.");
}
bool KumoProtectionService::ResolveWarning(content::WebContents* contents, bool continue_site) {
  auto* observer = ProtectionObserver::FromWebContents(contents);
  return observer && observer->ResolveWarning(continue_site);
}
void AttachProtection(content::WebContents* contents) {
  KumoProtectionService::Get(Profile::FromBrowserContext(contents->GetBrowserContext()))->AttachToWebContents(contents);
}
void RegisterProtectionPrefs(user_prefs::PrefRegistrySyncable* registry) {
  KumoProtectionService::RegisterProfilePrefs(registry);
}
}  // namespace kumo
