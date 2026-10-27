// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/actions/kumo_preferences.h"

#include <string>

#include "base/base64.h"
#include "base/test/task_environment.h"
#include "components/prefs/pref_service.h"
#include "components/sync_preferences/testing_pref_service_syncable.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace kumo::preferences {
namespace {
constexpr char kPreference[] = "kumo.start_page";

class KumoPreferencesTest : public testing::Test {
 protected:
  void SetUp() override {
    Register(prefs_.registry());
  }
  void RejectWithoutMutation(base::DictValue input) {
    const auto before = Get(&prefs_);
    auto result = SetPartial(&prefs_, input);
    EXPECT_EQ(result.FindBool("ok"), false);
    EXPECT_EQ(Get(&prefs_), before);
  }
  base::DictValue Engine(std::string url) {
    return base::DictValue().Set("id", "custom").Set("name", "Custom")
        .Set("url", std::move(url));
  }
  base::test::TaskEnvironment environment_;
  sync_preferences::TestingPrefServiceSyncable prefs_;
};

TEST_F(KumoPreferencesTest, AppliesValidatedPartialSettingsAndKeepsOtherValues) {
  auto before = Get(&prefs_);
  auto result = SetPartial(&prefs_, base::DictValue().Set("theme", "forest")
      .Set("accent", "#12ABcd").Set("greeting", "Welcome"));
  ASSERT_EQ(result.FindBool("ok"), true);
  auto after = Get(&prefs_);
  EXPECT_EQ(*after.FindString("theme"), "forest");
  EXPECT_EQ(*after.FindString("accent"), "#12ABcd");
  EXPECT_EQ(*after.FindString("greeting"), "Welcome");
  EXPECT_EQ(*after.FindList("engines"), *before.FindList("engines"));
}

TEST_F(KumoPreferencesTest, RejectsUnknownFieldsAndInvalidTypesAtomically) {
  RejectWithoutMutation(base::DictValue().Set("theme", "forest").Set("grants", true));
  RejectWithoutMutation(base::DictValue().Set("theme", "unknown"));
  RejectWithoutMutation(base::DictValue().Set("illumination", "strobe"));
  RejectWithoutMutation(base::DictValue().Set("intensity", 101));
  RejectWithoutMutation(base::DictValue().Set("motion", "yes"));
  RejectWithoutMutation(base::DictValue().Set("accent", "#12345z"));
  RejectWithoutMutation(base::DictValue().Set("greeting", true));
  RejectWithoutMutation(base::DictValue().Set("engine", "missing"));
  RejectWithoutMutation(base::DictValue().Set("engines", base::ListValue()));
}

TEST_F(KumoPreferencesTest, RejectsUnsafeAndCredentialBearingSearchUrls) {
  for (const auto* url : {"javascript:alert('{searchTerms}')",
                          "file:///tmp/{searchTerms}",
                          "https://user:secret@example.test/?q={searchTerms}",
                          "https://example.test/?q=no-template"}) {
    SCOPED_TRACE(url);
    base::ListValue engines;
    engines.Append(Engine(url));
    RejectWithoutMutation(base::DictValue().Set("engine", "custom")
        .Set("engines", std::move(engines)));
  }
}

TEST_F(KumoPreferencesTest, AcceptsCustomSearchAndRejectsAmbiguousEngineIds) {
  base::ListValue engines;
  engines.Append(Engine("https://example.test/search?q={searchTerms}"));
  ASSERT_EQ(SetPartial(&prefs_, base::DictValue().Set("engine", "custom")
      .Set("engines", engines.Clone())).FindBool("ok"), true);
  engines.Append(Engine("https://another.test/?q={searchTerms}"));
  RejectWithoutMutation(base::DictValue().Set("engines", std::move(engines)));
  auto unknown = Engine("https://example.test/?q={searchTerms}");
  unknown.Set("command", "/bin/sh");
  base::ListValue injected;
  injected.Append(std::move(unknown));
  RejectWithoutMutation(base::DictValue().Set("engines", std::move(injected)));
}

TEST_F(KumoPreferencesTest, RejectsInvalidUtf8AndOversizedDisplayText) {
  const std::string invalid("\xc3\x28", 2);
  RejectWithoutMutation(base::DictValue().Set("greeting", invalid));
  RejectWithoutMutation(base::DictValue().Set("greeting", std::string(101, 'a')));
  auto bad = Engine("https://example.test/?q={searchTerms}");
  bad.Set("name", invalid);
  base::ListValue engines;
  engines.Append(std::move(bad));
  RejectWithoutMutation(base::DictValue().Set("engine", "custom")
      .Set("engines", std::move(engines)));
}

TEST_F(KumoPreferencesTest, ShortcutsRejectCodeCredentialsAndUnknownFields) {
  for (const auto* url : {"javascript:alert(1)", "data:text/html,hello",
                          "file:///tmp/secret", "https://user@example.test/"}) {
    base::ListValue shortcuts;
    shortcuts.Append(base::DictValue().Set("name", "Site").Set("url", url));
    RejectWithoutMutation(base::DictValue().Set("shortcuts", std::move(shortcuts)));
  }
  base::ListValue shortcuts;
  shortcuts.Append(base::DictValue().Set("name", "Site")
      .Set("url", "https://example.test").Set("nativeCommand", "bad"));
  RejectWithoutMutation(base::DictValue().Set("shortcuts", std::move(shortcuts)));
}

TEST_F(KumoPreferencesTest, WallpaperAcceptsFixedRasterTypesAndRejectsActiveContent) {
  const std::string png = "data:image/png;base64,"
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a3foAAAAASUVORK5CYII=";
  ASSERT_EQ(SetPartial(&prefs_, base::DictValue().Set("background", png))
      .FindBool("ok"), true);
  for (const auto* wallpaper : {"data:image/svg+xml;base64,PHN2Zy8+",
                                "data:text/html;base64,PGgxLz4=",
                                "https://example.test/wallpaper.png",
                                "data:image/png;base64,bm90IGEgcG5n",
                                "data:image/png;base64,%%%%"})
    RejectWithoutMutation(base::DictValue().Set("background", wallpaper));
  RejectWithoutMutation(base::DictValue().Set("background", std::string(4000001, 'a')));
  EXPECT_EQ(SetPartial(&prefs_, base::DictValue().Set("background", ""))
      .FindBool("ok"), true);
}

TEST_F(KumoPreferencesTest, InvalidStoredPreferencesFallBackAndValidUserChoiceWinsMigration) {
  prefs_.SetDict(kPreference, base::DictValue().Set("theme", "bad"));
  EXPECT_EQ(*Get(&prefs_).FindString("theme"), "relay");
  prefs_.ClearPref(kPreference);
  EXPECT_FALSE(ImportLegacy(&prefs_, base::DictValue().Set("grants", true)));
  EXPECT_EQ(prefs_.GetUserPrefValue(kPreference), nullptr);
  ASSERT_TRUE(ImportLegacy(&prefs_, base::DictValue().Set("theme", "forest")));
  EXPECT_EQ(*Get(&prefs_).FindString("theme"), "forest");
  ASSERT_TRUE(ImportLegacy(&prefs_, base::DictValue().Set("theme", "ocean")));
  EXPECT_EQ(*Get(&prefs_).FindString("theme"), "forest");
}
}  // namespace
}  // namespace kumo::preferences
