#!/usr/bin/env python3
"""Add Kumo's native Apple AutoFill context-menu path to pinned Chromium source.

This is a source overlay, not binary injection. Every anchor must match once;
upstream drift stops preparation for review rather than silently skipping it.
"""
import argparse
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
MARKER = "// KUMO_NATIVE_AUTOFILL"

def once(text, before, after):
    if text.count(before) != 1:
        raise RuntimeError(f"Native AutoFill source anchor drifted: {before[:100]!r}")
    return text.replace(before, after, 1)

def apply(source):
    source = Path(source)
    folder = source / 'chrome/browser/renderer_context_menu'
    menu_path = folder / 'render_view_context_menu.cc'
    build_path = folder / 'BUILD.gn'
    commands = (source / 'chrome/app/chrome_command_ids.h').read_text()
    if re.search(r'^#define\s+\w+\s+57200\b', commands, re.M):
        raise RuntimeError('Kumo AutoFill command ID collides with upstream. Review required.')
    menu = menu_path.read_text()
    gn = build_path.read_text()
    if MARKER in menu or MARKER in gn:
        raise RuntimeError('Native AutoFill overlay already applied; prepare a clean source tree.')
    menu = once(menu, '#include "build/build_config.h"', '#include "build/build_config.h"\n\n#if BUILDFLAG(IS_MAC)\n#include "chrome/browser/renderer_context_menu/kumo_password_context.h"\n#endif\n' + MARKER)
    menu = once(menu, 'void RenderViewContextMenu::AppendOtherEditableItems() {', '''void RenderViewContextMenu::AppendOtherEditableItems() {
#if BUILDFLAG(IS_MAC)
  if (params_.field_renderer_id.value() != 0 &&
      kumo::CanFillFromApplePasswords(GetRenderFrameHost(),
                                     params_.field_renderer_id.value())) {
    menu_model_.AddItem(kumo::kFillFromApplePasswordsCommand,
                       u"Fill with Apple Passwords…");
    menu_model_.AddSeparator(ui::NORMAL_SEPARATOR);
  }
#endif''')
    menu = once(menu, 'bool RenderViewContextMenu::IsCommandIdEnabled(int id) const {', '''bool RenderViewContextMenu::IsCommandIdEnabled(int id) const {
#if BUILDFLAG(IS_MAC)
  if (id == kumo::kFillFromApplePasswordsCommand) {
    return params_.field_renderer_id.value() != 0 &&
           kumo::CanFillFromApplePasswords(GetRenderFrameHost(),
                                          params_.field_renderer_id.value());
  }
#endif''')
    menu = once(menu, '  command_executed_ = true;\n\n  // Process extension menu items.', '''  command_executed_ = true;

#if BUILDFLAG(IS_MAC)
  if (id == kumo::kFillFromApplePasswordsCommand) {
    if (params_.field_renderer_id.value() != 0) {
      kumo::FillFromApplePasswords(GetRenderFrameHost(),
                                  params_.field_renderer_id.value(),
                                  IsPasswordField());
    }
    return;
  }
#endif

  // Process extension menu items.''')
    # Browser-owned Kumo commands are not members of Chromium's persisted UMA
    # enum. Exclude only this command before either lookup; the base ExecuteCommand
    # still notifies observers and owns its usual command-executed lifecycle.
    for signature in ('void RenderViewContextMenu::RecordUsedItem(int id) {',
                      'void RenderViewContextMenu::RecordShownItem(int id, bool is_submenu) {'):
        menu = once(menu, signature, signature + """
#if BUILDFLAG(IS_MAC)
  if (id == kumo::kFillFromApplePasswordsCommand)
    return;
#endif""")
    gn = once(gn, 'source_set("impl") {', '''source_set("impl") {
  # KUMO_NATIVE_AUTOFILL
  if (is_mac) {
    sources = [ "kumo_password_panel.mm", "kumo_password_panel.h",
                "kumo_password_context.mm", "kumo_password_context.h" ]
    frameworks = [ "AppKit.framework" ]
  }''')
    # Keep sources additive; this target originally initializes the list later.
    gn = once(gn, '  sources = [ "context_menu_content_type_factory.cc" ]', '  sources += [ "context_menu_content_type_factory.cc" ]')
    # GN needs a sources list even on other platforms before += below.
    gn = once(gn, 'source_set("impl") {\n  # KUMO_NATIVE_AUTOFILL', 'source_set("impl") {\n  sources = []\n  # KUMO_NATIVE_AUTOFILL')
    gn = once(gn, '  if (!is_android) {\n    public += [\n      "accessibility_labels_menu_observer.h",', '  if (is_mac) {\n    deps += [ "//components/autofill/core/common" ]\n  }\n\n  if (!is_android) {\n    public += [\n      "accessibility_labels_menu_observer.h",')
    # Write only after all anchors and command ID checks passed.
    for name in ('kumo_password_panel.h', 'kumo_password_panel.mm', 'kumo_password_context.h', 'kumo_password_context.mm'):
        shutil.copyfile(ROOT / 'native/chromium' / name, folder / name)
    menu_path.write_text(menu)
    build_path.write_text(gn)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    apply(args.source.resolve())
