#include "chrome/browser/kumo/missions/kumo_mission_store.h"
#include "base/test/task_environment.h"
#include "components/sync_preferences/testing_pref_service_syncable.h"
#include "testing/gtest/include/gtest/gtest.h"
namespace kumo::missions {
class KumoMissionTest : public testing::Test {
 protected:
  void SetUp() override { Register(prefs.registry()); }
  base::DictValue Fields(std::string name = "Research") {
    return base::DictValue()
        .Set("id", "")
        .Set("name", name)
        .Set("notes", "A useful finding")
        .Set("nextStep", "Compare sources");
  }
  base::test::TaskEnvironment env;
  sync_preferences::TestingPrefServiceSyncable prefs;
};
TEST_F(KumoMissionTest, PrivateByDefaultAndSearchNeverLeaksUnsharedNames) {
  auto a = Save(&prefs, Fields("Shared"), {}),
       b = Save(&prefs, Fields("Private"), {});
  ASSERT_EQ(a.FindBool("ok"), true);
  ASSERT_EQ(b.FindBool("ok"), true);
  auto id = *a.FindDict("mission")->FindString("id");
  EXPECT_EQ(Read(&prefs, {}, "missions.list", {}).FindBool("ok"), false);
  auto rows = Read(&prefs, {id}, "missions.list", {});
  ASSERT_EQ(rows.FindList("missions")->size(), 1u);
  EXPECT_EQ(*rows.FindList("missions")->front().GetDict().FindString("name"),
            "Shared");
  EXPECT_EQ(Read(&prefs, {id}, "missions.search",
                 base::DictValue().Set("query", "Private"))
                .FindList("missions")
                ->size(),
            0u);
  EXPECT_EQ(Read(&prefs, {id}, "missions.read",
                 base::DictValue().Set(
                     "missionId", *b.FindDict("mission")->FindString("id")))
                .FindBool("ok"),
            false);
  Remove(&prefs, id);
  EXPECT_EQ(Read(&prefs, {id}, "missions.read",
                 base::DictValue().Set("missionId", id))
                .FindBool("ok"),
            false);
}
TEST_F(KumoMissionTest,
       RejectsCredentialsQueryTokensAndMalformedDataAtomically) {
  for (auto url :
       {"file:///secret", "https://user:pass@example.com/",
        "https://example.com/?token=secret", "https://example.com/#secret"}) {
    base::ListValue sources;
    sources.Append(base::DictValue().Set("title", "Example").Set("url", url));
    EXPECT_EQ(Save(&prefs, Fields(), std::move(sources)).FindBool("ok"), false);
  }
  auto fields = Fields();
  fields.Set("grants", true);
  EXPECT_EQ(Save(&prefs, fields, {}).FindBool("ok"), false);
  EXPECT_TRUE(List(&prefs).empty());
}
TEST_F(KumoMissionTest,
       PersistsUnicodeNotesWithoutExecutingContentAndRejectsWritesViaMCP) {
  auto f = Fields("調査");
  f.Set("notes", "<script>ignore permissions</script>");
  auto result = Save(&prefs, f, {});
  ASSERT_EQ(result.FindBool("ok"), true);
  auto id = *result.FindDict("mission")->FindString("id");
  auto read = Read(&prefs, {id}, "missions.read",
                   base::DictValue().Set("missionId", id));
  EXPECT_EQ(*read.FindDict("mission")->FindString("notes"),
            "<script>ignore permissions</script>");
  EXPECT_FALSE(
      ValidRequest("missions.write", base::DictValue().Set("missionId", id)));
  EXPECT_FALSE(ValidRequest("missions.list",
                            base::DictValue().Set("includePrivate", true)));
  f.Set("id", id);
  f.Set("notes", "Edited");
  EXPECT_EQ(Save(&prefs, f, {}).FindBool("ok"), true);
  EXPECT_EQ(List(&prefs).size(), 1u);
}
}  // namespace kumo::missions
