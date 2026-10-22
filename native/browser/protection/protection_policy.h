// Copyright 2026 Kumo authors. All rights reserved.
#ifndef CHROME_BROWSER_KUMO_PROTECTION_PROTECTION_POLICY_H_
#define CHROME_BROWSER_KUMO_PROTECTION_PROTECTION_POLICY_H_

#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace kumo::protection {
inline constexpr char kLegacyExtensionId[] = "eldkgppmnhligdekahicdcdndcoongio";
inline constexpr char kFeedURL[] = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt";
inline constexpr size_t kMaximumFeedBytes = 16 * 1024 * 1024;
inline constexpr size_t kMaximumDomains = 500000;
inline constexpr size_t kMaximumSampleBytes = 24576;
inline constexpr size_t kMaximumPendingScans = 4;

bool ValidDomain(std::string_view domain);
bool ListedDomain(const std::set<std::string, std::less<>>& domains,
                  std::string_view canonical_host);
// Only actual boolean values are passed to this function. A native user
// setting wins; missing settings use the product default, never a stale health.
bool ResolveEnabled(std::optional<bool> native_value,
                    std::optional<bool> legacy_value);

struct DomainFeed {
  std::vector<std::string> domains;
  std::string version;
  std::string modified;
};
// Parses the exact provider format. Dates/version rollback are additionally
// checked against the browser clock and the previously accepted snapshot.
std::optional<DomainFeed> ParseDomainFeed(std::string_view text,
                                        size_t minimum_count);
}  // namespace kumo::protection
#endif
