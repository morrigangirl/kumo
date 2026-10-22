// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/protection/protection_policy.h"

#include <algorithm>
#include <charconv>
#include <regex>

namespace kumo::protection {
bool ValidDomain(std::string_view domain) {
  if (domain.size() > 253 || domain.find('.') == std::string_view::npos)
    return false;
  size_t start = 0;
  while (start < domain.size()) {
    const size_t end = domain.find('.', start);
    const auto label = domain.substr(start, end == std::string_view::npos
                                               ? domain.size() - start
                                               : end - start);
    const auto alnum = [](char c) {
      return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    };
    if (label.empty() || label.size() > 63 || !alnum(label.front()) ||
        !alnum(label.back()) ||
        !std::all_of(label.begin(), label.end(), [&](char c) {
          return alnum(c) || c == '-';
        }))
      return false;
    if (end == std::string_view::npos) {
      return !std::all_of(label.begin(), label.end(), [](char c) {
        return c >= '0' && c <= '9';
      });
    }
    start = end + 1;
  }
  return false;
}

bool ListedDomain(const std::set<std::string, std::less<>>& domains,
                  std::string_view host) {
  if (!host.empty() && host.back() == '.')
    host.remove_suffix(1);
  while (!host.empty()) {
    if (domains.contains(host))
      return true;
    const size_t dot = host.find('.');
    if (dot == std::string_view::npos)
      return false;
    host.remove_prefix(dot + 1);
  }
  return false;
}

bool ResolveEnabled(std::optional<bool> native_value,
                    std::optional<bool> legacy_value) {
  return native_value.value_or(legacy_value.value_or(true));
}

std::optional<DomainFeed> ParseDomainFeed(std::string_view text,
                                        size_t minimum_count) {
  if (text.empty() || text.size() > kMaximumFeedBytes ||
      !std::all_of(text.begin(), text.end(), [](unsigned char c) {
        return c == '\n' || (c >= 0x20 && c <= 0x7e);
      }))
    return std::nullopt;
  std::map<std::string, std::string> fields;
  std::set<std::string, std::less<>> seen;
  DomainFeed result;
  bool data = false;
  size_t start = 0;
  while (start < text.size()) {
    const size_t end = text.find('\n', start);
    const auto line = text.substr(start, end == std::string_view::npos
                                            ? text.size() - start
                                            : end - start);
    start = end == std::string_view::npos ? text.size() : end + 1;
    if (line.empty())
      continue;
    if (line.front() == '#') {
      if (data)
        return std::nullopt;
      const size_t colon = line.find(": ");
      if (line.starts_with("# ") && colon != std::string_view::npos) {
        std::string name(line.substr(2, colon - 2));
        std::transform(name.begin(), name.end(), name.begin(), [](char c) {
          return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
        });
        if (!fields.emplace(name, line.substr(colon + 2)).second)
          return std::nullopt;
      }
      continue;
    }
    data = true;
    if (!ValidDomain(line) || !seen.emplace(line).second ||
        result.domains.size() >= kMaximumDomains)
      return std::nullopt;
    result.domains.emplace_back(line);
  }
  const auto value = [&](const char* key) -> std::string {
    const auto it = fields.find(key);
    return it == fields.end() ? std::string() : it->second;
  };
  const std::string title = value("title");
  result.version = value("version");
  result.modified = value("last modified");
  const std::string count = value("number of entries");
  size_t parsed_count = 0;
  const auto parsed = std::from_chars(count.data(), count.data() + count.size(), parsed_count);
  if (value("homepage") != "https://github.com/hagezi/dns-blocklists" ||
      value("license") != "https://github.com/hagezi/dns-blocklists/blob/main/LICENSE" ||
      value("syntax") != "Domains (without subdomains)" || value("expires") != "8 hours" ||
      title.find("Threat Intelligence Feeds") == std::string::npos ||
      title.find("mini version") == std::string::npos ||
      !std::regex_match(result.version, std::regex(R"([0-9]{4}\.[0-9]{4}\.[0-9]{4}\.[0-9]{1,15})")) ||
      !std::regex_match(result.modified, std::regex(R"([0-9]{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} [0-9]{2}:[0-9]{2} UTC)")) ||
      parsed.ec != std::errc() || parsed.ptr != count.data() + count.size() ||
      parsed_count != result.domains.size() || parsed_count < minimum_count ||
      parsed_count == 0)
    return std::nullopt;
  return result;
}
}  // namespace kumo::protection
