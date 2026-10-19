#!/usr/bin/env python3
"""Offline dispatch regression using pinned Chromium method bodies.

The fixture compiles the actual base dispatch body, the Kumo branch of derived
ExecuteCommand, and the metrics lookup prelude/whole shown method. Lightweight
observer, UMA and native-panel shims expose call ordering and turn NOTREACHED
into a caught exception. This does not test AppKit, an actual fatal process, or
renderer/native-sheet integration; run smoke-native-passwords on the source app.
"""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


def function(text, signature):
    start = text.index(signature)
    opened = text.index('{', start)
    depth, end = 1, opened + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1] /
                    'build/source-155.0.8059.84/recipe/build/src')
parser.add_argument('--prepared-menu', type=Path,
                    help='reviewed candidate menu, before source-tree promotion')
ARGS, REST = parser.parse_known_args()
MENU_REL = 'chrome/browser/renderer_context_menu/render_view_context_menu.cc'
GUARD = '''
#if BUILDFLAG(IS_MAC)
  if (id == kumo::kFillFromApplePasswordsCommand)
    return;
#endif'''


class NativeMetricsFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.menu = (ARGS.prepared_menu or ARGS.source / MENU_REL).read_text()
        cls.base = (ARGS.source / 'components/renderer_context_menu/render_view_context_menu_base.cc').read_text()
        cls.header = (ARGS.source / 'chrome/app/chrome_command_ids.h').read_text()
        cls.notreached = (ARGS.source / 'base/notreached.h').read_text()

    def test_command_has_no_upstream_histogram_id_and_notreached_is_fatal(self):
        self.assertNotRegex(self.header, re.compile(r'^#define\s+\w+\s+57200\b', re.M))
        metrics = function(self.menu, 'int UmaEnumForCommand(')
        self.assertNotIn('kFillFromApplePasswordsCommand', metrics)
        self.assertNotRegex(metrics, r'\b57200\b')
        # Check both streamed and stripped NOTREACHED implementations are fatal.
        self.assertIn('::logging::NotReachedNoreturnError()', self.notreached)
        self.assertIn('base::ImmediateCrash();', self.notreached)

    def test_guard_changes_no_dispatch_or_panel_branch(self):
        used = function(self.menu, 'void RenderViewContextMenu::RecordUsedItem(')
        shown = function(self.menu, 'void RenderViewContextMenu::RecordShownItem(')
        self.assertEqual(used.count(GUARD), 1)
        self.assertEqual(shown.count(GUARD), 1)
        for body in (used, shown):
            self.assertLess(body.index(GUARD), body.index('FindUMAEnumValueForCommand'))
            self.assertEqual(body.count('kumo::kFillFromApplePasswordsCommand'), 1)
        execute = function(self.menu, 'void RenderViewContextMenu::ExecuteCommand(')
        self.assertLess(execute.index('RenderViewContextMenuBase::ExecuteCommand'),
                        execute.index('kumo::FillFromApplePasswords'))
        self.assertLess(execute.index('command_executed_ = true'),
                        execute.index('kumo::FillFromApplePasswords'))

    def test_actual_dispatch_prefix_preserves_observers_and_rejects_other_unknown_ids(self):
        compiler = shutil.which('clang++')
        if not compiler:
            self.skipTest('C++ compiler unavailable')
        base_dispatch = function(self.base, 'void RenderViewContextMenuBase::ExecuteCommand(')
        execute = function(self.menu, 'void RenderViewContextMenu::ExecuteCommand(')
        execute = execute[:execute.index('  // Process extension menu items.')] + '}\n'
        used = function(self.menu, 'void RenderViewContextMenu::RecordUsedItem(')
        used = used[:used.index('  // Log a user action')] + '}\n'
        shown = function(self.menu, 'void RenderViewContextMenu::RecordShownItem(')
        harness = r'''
#include <cassert>
#include <stdexcept>
#include <string>
#include <vector>
#define BUILDFLAG(flag) flag
#define IS_MAC 1
#define ENABLE_PLUGINS 0
struct GURL {};
struct NotReached : std::runtime_error { NotReached() : std::runtime_error("NOTREACHED") {} };
struct Fatal { template <typename T> Fatal& operator<<(const T&) { return *this; } };
Fatal Fail() { throw NotReached(); }
#define NOTREACHED() Fail()
struct Log { template <typename T> Log& operator<<(const T&) { return *this; } };
#define DLOG(level) Log()
int lookups = 0, histograms = 0, panel_calls = 0;
std::vector<std::string> events;
#define UMA_HISTOGRAM_EXACT_LINEAR(name, value, maximum) (++histograms)
enum class UmaEnumIdLookupType { GeneralEnumId };
int FindUMAEnumValueForCommand(int id, UmaEnumIdLookupType) {
  ++lookups;
  return id == 100 ? 3 : -1;
}
struct Frame {};
namespace kumo {
constexpr int kFillFromApplePasswordsCommand = 57200;
void FillFromApplePasswords(Frame*, unsigned long long id, bool password) {
  assert(id == 9 && password);
  ++panel_calls;
  events.push_back("panel");
}
}
struct Observer {
  bool owns = false;
  void CommandWillBeExecuted(int) { events.push_back("observer-notify"); }
  bool IsCommandIdSupported(int) { return owns; }
  void ExecuteCommand(int) { events.push_back("observer-execute"); }
};
struct WebContents { void ExecuteCustomContextMenuCommand(unsigned, const GURL&) {} };
struct FieldId { unsigned long long value() const { return 9; } };
struct Params { GURL link_followed; FieldId field_renderer_id; };
struct RenderViewContextMenuBase {
  bool command_executed_ = false;
  std::vector<Observer> observers_;
  Params params_;
  WebContents contents;
  WebContents* source_web_contents_ = &contents;
  static constexpr int content_context_custom_first = 90000;
  virtual void RecordUsedItem(int) = 0;
  static bool IsContentCustomCommandId(int) { return false; }
  void ExecuteCommand(int id, int event_flags);
};
struct RenderViewContextMenu : RenderViewContextMenuBase {
  Frame frame;
  Frame* GetRenderFrameHost() { return &frame; }
  bool IsPasswordField() const { return true; }
  void RecordUsedItem(int id) override;
  void RecordShownItem(int id, bool is_submenu);
  void ExecuteCommand(int id, int event_flags);
};
BASE_DISPATCH
DERIVED_DISPATCH
USED_METRICS
SHOWN_METRICS
void Reset() { lookups = histograms = panel_calls = 0; events.clear(); }
int main() {
  RenderViewContextMenu menu;
  menu.observers_.push_back(Observer{});
  Reset();
  menu.RecordShownItem(kumo::kFillFromApplePasswordsCommand, false);
  menu.ExecuteCommand(kumo::kFillFromApplePasswordsCommand, 0);
  assert(lookups == 0 && histograms == 0 && panel_calls == 1);
  assert((events == std::vector<std::string>{"observer-notify", "panel"}));
  assert(menu.command_executed_);
  Reset();
  menu.RecordShownItem(100, false);
  menu.ExecuteCommand(100, 0);
  assert(lookups == 2 && histograms == 2 && panel_calls == 0);
  assert((events == std::vector<std::string>{"observer-notify"}));
  Reset();
  bool fatal = false;
  try { menu.ExecuteCommand(57201, 0); } catch (const NotReached&) { fatal = true; }
  assert(fatal && lookups == 1 && histograms == 0 && events.empty() && panel_calls == 0);
  Reset();
  menu.observers_[0].owns = true;
  menu.ExecuteCommand(kumo::kFillFromApplePasswordsCommand, 0);
  assert(lookups == 0 && histograms == 0 && panel_calls == 0);
  assert((events == std::vector<std::string>{"observer-notify", "observer-execute"}));
  Reset();
  menu.RecordShownItem(100, true);
  assert(lookups == 0 && histograms == 0);
}
'''
        harness = harness.replace('BASE_DISPATCH', base_dispatch).replace('DERIVED_DISPATCH', execute)
        harness = harness.replace('USED_METRICS', used).replace('SHOWN_METRICS', shown)
        with tempfile.TemporaryDirectory(prefix='kumo-native-metrics-') as folder:
            folder = Path(folder)
            source, executable = folder / 'probe.cc', folder / 'probe'
            source.write_text(harness)
            subprocess.run([compiler, '-std=c++20', '-Wall', '-Wextra', '-Wno-unused-parameter',
                            str(source), '-o', str(executable)], check=True, capture_output=True)
            subprocess.run([str(executable)], check=True, capture_output=True)
            # Removing just the guard reproduces the deterministic NOTREACHED
            # branch before observer notification/native-panel construction.
            baseline = harness.replace(GUARD, '')
            start = baseline.index('int main() {')
            baseline = baseline[:start] + r'''
int main() {
  RenderViewContextMenu menu;
  menu.observers_.push_back(Observer{});
  bool fatal = false;
  try { menu.ExecuteCommand(kumo::kFillFromApplePasswordsCommand, 0); }
  catch (const NotReached&) { fatal = true; }
  assert(fatal && lookups == 1 && histograms == 0 && events.empty() && panel_calls == 0);
}
'''
            source.write_text(baseline)
            subprocess.run([compiler, '-std=c++20', str(source), '-o', str(executable)],
                           check=True, capture_output=True)
            subprocess.run([str(executable)], check=True, capture_output=True)


if __name__ == '__main__':
    unittest.main(argv=[__file__, *REST])
