#include "chrome/browser/kumo/actions/kumo_preferences.h"

#include <optional>
#include <set>
#include <string>
#include <string_view>

#include "base/base64.h"
#include "base/check.h"
#include "base/json/json_reader.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "components/prefs/pref_service.h"
#include "components/pref_registry/pref_registry_syncable.h"
#include "url/gurl.h"

namespace kumo::preferences {
namespace {
constexpr char kPreference[] = "kumo.start_page";
constexpr char kDefaults[] = R"({
"theme":"paper","accent":"#c65b3c","background":"",
"greeting":"A little room to explore.","engine":"duckduckgo",
"engines":[
{"id":"duckduckgo","name":"DuckDuckGo","url":"https://duckduckgo.com/?q={searchTerms}"},
{"id":"kagi","name":"Kagi","url":"https://kagi.com/search?q={searchTerms}"},
{"id":"brave","name":"Brave Search","url":"https://search.brave.com/search?q={searchTerms}"},
{"id":"google","name":"Google","url":"https://www.google.com/search?q={searchTerms}"},
{"id":"bing","name":"Bing","url":"https://www.bing.com/search?q={searchTerms}"}],
"shortcuts":[{"name":"Apple","url":"https://www.apple.com"},
{"name":"Wikipedia","url":"https://www.wikipedia.org"},
{"name":"GitHub","url":"https://github.com"},
{"name":"YouTube","url":"https://www.youtube.com"}]})";

base::DictValue Defaults() {
  auto value = base::JSONReader::ReadDict(kDefaults, base::JSON_PARSE_RFC);
  CHECK(value);
  return std::move(*value);
}
bool WebUrl(const std::string& text) {
  if (text.size() > 8192)
    return false;
  GURL url(text);
  return url.is_valid() && url.SchemeIsHTTPOrHTTPS() && url.has_host() &&
         !url.has_username() && !url.has_password();
}
bool KnownKeys(const base::DictValue& input,
               const std::set<std::string_view>& keys) {
  for (const auto [key, value] : input) {
    if (!keys.contains(key))
      return false;
  }
  return true;
}
bool Wallpaper(const std::string& data) {
  if (data.empty())
    return true;
  if (data.size() > 4000000)
    return false;
  const auto comma = data.find(',');
  if (comma == std::string::npos)
    return false;
  const auto type = data.substr(0, comma);
  if (type != "data:image/png;base64" && type != "data:image/jpeg;base64" &&
      type != "data:image/webp;base64")
    return false;
  std::string bytes;
  if (!base::Base64Decode(std::string_view(data).substr(comma + 1), &bytes) ||
      bytes.size() > 3000000)
    return false;
  if (type == "data:image/png;base64")
    return bytes.starts_with(std::string("\x89PNG\r\n\x1a\n", 8));
  if (type == "data:image/jpeg;base64")
    return bytes.starts_with(std::string("\xff\xd8\xff", 3));
  return bytes.size() >= 12 && bytes.starts_with("RIFF") &&
         bytes.substr(8, 4) == "WEBP";
}
std::optional<base::DictValue> Validate(const base::DictValue& input) {
  if (!KnownKeys(input, {"theme", "accent", "background", "greeting",
                         "engine", "engines", "shortcuts"}))
    return std::nullopt;
  auto output = Defaults();
  for (const auto [key, value] : input)
    output.Set(key, value.Clone());
  const auto* theme = output.FindString("theme");
  const std::set<std::string_view> themes = {
      "paper", "midnight", "forest", "lavender", "sand", "ocean"};
  const auto* accent = output.FindString("accent");
  const auto* background = output.FindString("background");
  const auto* greeting = output.FindString("greeting");
  const auto* selected = output.FindString("engine");
  const auto* engines = output.FindList("engines");
  const auto* shortcuts = output.FindList("shortcuts");
  if (!theme || !themes.contains(*theme) || !accent || accent->size() != 7 ||
      (*accent)[0] != '#' ||
      accent->find_first_not_of("0123456789abcdefABCDEF", 1) != std::string::npos ||
      !background || !Wallpaper(*background) || !greeting ||
      !base::IsStringUTF8(*greeting) ||
      base::UTF8ToUTF16(*greeting).size() > 100 || !selected || !engines ||
      engines->empty() || engines->size() > 50 || !shortcuts ||
      shortcuts->size() > 12)
    return std::nullopt;
  std::set<std::string> ids;
  for (const auto& engine : *engines) {
    if (!engine.is_dict() ||
        !KnownKeys(engine.GetDict(), {"id", "name", "url"}))
      return std::nullopt;
    const auto* id = engine.GetDict().FindString("id");
    const auto* name = engine.GetDict().FindString("name");
    const auto* url = engine.GetDict().FindString("url");
    if (!id || id->empty() || id->size() > 80 || !base::IsStringUTF8(*id) ||
        !ids.insert(*id).second || !name || name->empty() ||
        name->size() > 240 || !base::IsStringUTF8(*name) ||
        base::UTF8ToUTF16(*name).size() > 60 || !url ||
        url->find("{searchTerms}") == std::string::npos)
      return std::nullopt;
    std::string probe = *url;
    base::ReplaceSubstringsAfterOffset(&probe, 0, "{searchTerms}", "test");
    if (!WebUrl(probe))
      return std::nullopt;
  }
  if (!ids.contains(*selected))
    return std::nullopt;
  for (const auto& shortcut : *shortcuts) {
    if (!shortcut.is_dict() ||
        !KnownKeys(shortcut.GetDict(), {"name", "url"}))
      return std::nullopt;
    const auto* name = shortcut.GetDict().FindString("name");
    const auto* url = shortcut.GetDict().FindString("url");
    if (!name || name->empty() || !base::IsStringUTF8(*name) ||
        base::UTF8ToUTF16(*name).size() > 40 || !url || !WebUrl(*url))
      return std::nullopt;
  }
  return output;
}
}  // namespace

void Register(user_prefs::PrefRegistrySyncable* registry) {
  registry->RegisterDictionaryPref(kPreference, Defaults());
}
base::DictValue Get(PrefService* prefs) {
  const auto& stored = prefs->GetDict(kPreference);
  auto validated = Validate(stored);
  return validated ? std::move(*validated) : Defaults();
}
base::DictValue SetPartial(PrefService* prefs, const base::DictValue& input) {
  auto merged = Get(prefs);
  for (const auto [key, value] : input)
    merged.Set(key, value.Clone());
  auto validated = Validate(merged);
  if (!validated)
    return base::DictValue().Set("ok", false).Set(
        "reason", "These preferences are invalid. Your settings were retained.");
  prefs->SetDict(kPreference, std::move(*validated));
  return base::DictValue().Set("ok", true).Set("preferences", Get(prefs));
}
bool ImportLegacy(PrefService* prefs, const base::DictValue& input) {
  if (prefs->GetUserPrefValue(kPreference))
    return true;
  auto validated = Validate(input);
  if (!validated)
    return false;
  prefs->SetDict(kPreference, std::move(*validated));
  return true;
}
}  // namespace kumo::preferences
