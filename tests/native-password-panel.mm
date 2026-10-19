#import <AppKit/AppKit.h>

#include "../native/chromium/kumo_password_panel.h"

#include <algorithm>
#include <cstdio>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int assertions = 0;
int exit_status = 1;

void Expect(bool condition, const char* description) {
  ++assertions;
  if (!condition)
    throw std::runtime_error(description);
}

// Pump only this test process's AppKit queue. No Apple Passwords picker, keychain
// operation, browser, clipboard, or user's application is accessed by this test.
bool PumpUntil(const std::function<bool()>& predicate, NSTimeInterval timeout = 4.0) {
  const NSTimeInterval deadline = NSDate.timeIntervalSinceReferenceDate + timeout;
  while (!predicate() && NSDate.timeIntervalSinceReferenceDate < deadline) {
    @autoreleasepool {
      NSEvent* event = [NSApp nextEventMatchingMask:NSEventMaskAny
                                        untilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]
                                           inMode:NSDefaultRunLoopMode
                                          dequeue:YES];
      if (event)
        [NSApp sendEvent:event];
      [NSApp updateWindows];
    }
  }
  return predicate();
}

struct Result {
  int calls = 0;
  bool accepted = false;
  std::u16string value;
};

kumo::PasswordPanelCallback Capture(const std::shared_ptr<Result>& result) {
  return [result](bool accepted, std::u16string value) {
    ++result->calls;
    result->accepted = accepted;
    result->value = std::move(value);
  };
}

NSWindow* MakeParent(bool visible = true) {
  NSWindow* window = [[NSWindow alloc]
      initWithContentRect:NSMakeRect(20, 20, 900, 650)
                styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
                  backing:NSBackingStoreBuffered
                    defer:NO];
  window.title = @"Kumo synthetic native panel tests";
  window.releasedWhenClosed = NO;
  window.restorable = NO;
  window.animationBehavior = NSWindowAnimationBehaviorNone;
  if (visible) {
    // A visible AppKit window is required by the production API; keep this
    // dedicated synthetic test window beyond the desktop's visible bounds.
    [window setFrameOrigin:NSMakePoint(NSMaxX(NSScreen.mainScreen.frame) + 100, 20)];
    [window orderFront:nil];
    Expect(window.visible, "synthetic parent window must be visible to AppKit");
  }
  return window;
}

NSTextField* FindCredentialField(NSView* view) {
  if ([view isKindOfClass:NSTextField.class]) {
    NSTextField* field = (NSTextField*)view;
    if (field.editable &&
        ([field.contentType isEqualToString:NSTextContentTypePassword] ||
         [field.contentType isEqualToString:NSTextContentTypeUsername])) {
      return field;
    }
  }
  for (NSView* child in view.subviews) {
    if (NSTextField* field = FindCredentialField(child))
      return field;
  }
  return nil;
}

NSButton* FindButton(NSView* view, NSString* title) {
  if ([view isKindOfClass:NSButton.class] &&
      [((NSButton*)view).title isEqualToString:title]) {
    return (NSButton*)view;
  }
  for (NSView* child in view.subviews) {
    if (NSButton* button = FindButton(child, title))
      return button;
  }
  return nil;
}

NSTextView* FindOrigin(NSView* view) {
  if ([view isKindOfClass:NSTextView.class] && !((NSTextView*)view).editable)
    return (NSTextView*)view;
  for (NSView* child in view.subviews) {
    if (NSTextView* origin = FindOrigin(child))
      return origin;
  }
  return nil;
}

NSWindow* Show(NSWindow* parent, bool is_password, const std::shared_ptr<Result>& result) {
  kumo::ShowKumoPasswordPanel(parent, "https://example.invalid:8443", is_password, Capture(result));
  Expect(PumpUntil([&] { return parent.attachedSheet != nil; }), "native sheet must attach");
  Expect(result->calls == 0, "opening the native sheet must not return a credential");
  return parent.attachedSheet;
}

void ExpectCancellation(const std::shared_ptr<Result>& result) {
  Expect(PumpUntil([&] { return result->calls != 0; }), "cancellation completion must arrive");
  Expect(result->calls == 1, "cancellation callback must arrive exactly once");
  Expect(!result->accepted && result->value.empty(), "cancellation must contain no selected value");
}

void WaitForNoSheet(NSWindow* parent) {
  Expect(PumpUntil([&] { return parent.attachedSheet == nil; }), "sheet must detach after completion");
}

void RunTests() {
  NSWindow* parent = MakeParent();
  {
    auto result = std::make_shared<Result>();
    kumo::ShowKumoPasswordPanel(nil, "https://example.invalid", true, Capture(result));
    ExpectCancellation(result);
  }
  {
    NSWindow* hidden = MakeParent(false);
    auto result = std::make_shared<Result>();
    kumo::ShowKumoPasswordPanel(hidden, "https://example.invalid", true, Capture(result));
    ExpectCancellation(result);
    Expect(hidden.attachedSheet == nil, "hidden parent must not receive a sheet");
    [hidden close];
  }
  const std::vector<std::string> invalid_origins = {
      "", "file:///tmp/test", "https://example.invalid/path", "https://example.invalid/",
      "https://example.invalid?query", "https://example.invalid#fragment",
      "https://user:secret@example.invalid", "https://exa\nmple.invalid",
      "https://éxample.invalid"};
  for (const auto& invalid : invalid_origins) {
    auto result = std::make_shared<Result>();
    kumo::ShowKumoPasswordPanel(parent, invalid, true, Capture(result));
    ExpectCancellation(result);
    Expect(parent.attachedSheet == nil, "invalid origin must not attach a sheet");
  }
  {
    auto original = std::make_shared<Result>();
    NSWindow* sheet = Show(parent, false, original);
    NSTextField* field = FindCredentialField(sheet.contentView);
    Expect(field != nil && ![field isKindOfClass:NSSecureTextField.class],
           "username request must use a standard native text field");
    Expect([field.contentType isEqualToString:NSTextContentTypeUsername],
           "username request must preserve native username semantics");
    NSTextView* origin = FindOrigin(sheet.contentView);
    Expect(origin != nil && [origin.string isEqualToString:@"https://example.invalid:8443"] &&
               !origin.editable,
           "destination origin must be exact and read-only");
    auto duplicate = std::make_shared<Result>();
    kumo::ShowKumoPasswordPanel(parent, "https://other.invalid", true, Capture(duplicate));
    ExpectCancellation(duplicate);
    Expect(parent.attachedSheet == sheet && original->calls == 0,
           "a duplicate request must leave the original sheet untouched");
    field.stringValue = @"synthetic username, never a real credential";
    kumo::CancelKumoPasswordPanel(parent);
    kumo::CancelKumoPasswordPanel(parent);
    ExpectCancellation(original);
    WaitForNoSheet(parent);
    Expect(field.stringValue.length == 0, "cancel must clear the native field before delivery");
    kumo::CancelKumoPasswordPanel(parent);
    Expect(original->calls == 1, "repeated cancellation must not repeat completion");
  }
  {
    auto result = std::make_shared<Result>();
    NSWindow* sheet = Show(parent, true, result);
    NSTextField* field = FindCredentialField(sheet.contentView);
    Expect([field isKindOfClass:NSSecureTextField.class],
           "password request must use a native secure text field");
    Expect([field.contentType isEqualToString:NSTextContentTypePassword],
           "password request must preserve native password semantics");
    const std::u16string dummy = u"Synthetic only: café / 雲 / 🔐 / 𝄞";
    [sheet makeFirstResponder:nil];
    field.stringValue = [[NSString alloc] initWithCharacters:
        reinterpret_cast<const unichar*>(dummy.data()) length:dummy.size()];
    NSButton* fill = FindButton(sheet.contentView, @"Fill");
    Expect(fill != nil, "native sheet must expose an explicit Fill control");
    [fill performClick:nil];
    Expect(PumpUntil([&] { return result->calls != 0; }), "Fill completion must arrive");
    Expect(result->accepted && result->value == dummy,
           "Fill must preserve exactly the selected synthetic UTF-16 value");
    Expect(result->calls == 1, "Fill callback must arrive exactly once");
    Expect(field.stringValue.length == 0, "Fill must clear the native field before delivery");
    WaitForNoSheet(parent);
    kumo::CancelKumoPasswordPanel(parent);
    Expect(result->calls == 1, "later cancellation must not repeat Fill completion");
    std::fill(result->value.begin(), result->value.end(), u'\0');
    result->value.clear();
  }
  {
    auto result = std::make_shared<Result>();
    NSWindow* sheet = Show(parent, false, result);
    [FindButton(sheet.contentView, @"Fill") performClick:nil];
    Expect(PumpUntil([&] { return result->calls != 0; }), "empty Fill completion must arrive");
    Expect(result->calls == 1 && result->accepted && result->value.empty(),
           "explicit empty acceptance must remain distinguishable from Cancel");
    WaitForNoSheet(parent);
  }
  {
    auto result = std::make_shared<Result>();
    NSWindow* sheet = Show(parent, true, result);
    NSTextField* field = FindCredentialField(sheet.contentView);
    [sheet makeFirstResponder:nil];
    field.stringValue = @"synthetic Cancel-button test";
    // This host does not offer an active title-bar close action for a sheet;
    // exercise the actual Cancel control instead of assuming performClose works.
    NSButton* cancel = FindButton(sheet.contentView, @"Cancel");
    Expect(cancel != nil, "native sheet must expose an explicit Cancel control");
    [cancel performClick:nil];
    ExpectCancellation(result);
    WaitForNoSheet(parent);
    Expect(field.stringValue.length == 0, "Cancel button must clear the field");
  }
  {
    NSPanel* unrelated = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, 200, 100)
                                                  styleMask:NSWindowStyleMaskTitled
                                                    backing:NSBackingStoreBuffered
                                                      defer:NO];
    auto finished = std::make_shared<bool>(false);
    [parent beginSheet:unrelated completionHandler:^(NSModalResponse /* response */) {
      *finished = true;
    }];
    Expect(PumpUntil([&] { return parent.attachedSheet == unrelated; }),
           "unrelated synthetic sheet must attach");
    kumo::CancelKumoPasswordPanel(parent);
    Expect(parent.attachedSheet == unrelated && !*finished,
           "Kumo cancellation must leave unrelated sheets untouched");
    [parent endSheet:unrelated returnCode:NSModalResponseCancel];
    Expect(PumpUntil([&] { return *finished; }), "unrelated sheet must complete normally");
    WaitForNoSheet(parent);
  }
  {
    auto result = std::make_shared<Result>();
    NSWindow* sheet = Show(parent, true, result);
    NSTextField* field = FindCredentialField(sheet.contentView);
    [sheet makeFirstResponder:nil];
    field.stringValue = @"synthetic parent-close test";
    [parent close];
    ExpectCancellation(result);
    Expect(field.stringValue.length == 0, "parent close must clear the pending field");
  }
}

}  // namespace

@interface KumoNativePanelTestRunner : NSObject <NSApplicationDelegate>
@end

@implementation KumoNativePanelTestRunner
- (void)applicationDidFinishLaunching:(NSNotification*)notification {
  (void)notification;
  [self performSelector:@selector(runTests) withObject:nil afterDelay:0];
}
- (void)runTests {
  @autoreleasepool {
    @try {
      try {
        RunTests();
        exit_status = 0;
      } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL at assertion %d: %s\n", assertions, error.what());
      }
    } @catch (NSException* /* error */) {
      std::fprintf(stderr, "FAIL: unexpected native panel exception\n");
    }
    if (exit_status == 0)
      std::printf("PASS: native password panel (%d assertions; synthetic values only)\n", assertions);
  }
  [NSApp stop:nil];
  [NSApp postEvent:[NSEvent otherEventWithType:NSEventTypeApplicationDefined
                                    location:NSZeroPoint
                               modifierFlags:0
                                   timestamp:0
                                windowNumber:0
                                     context:nil
                                     subtype:0
                                       data1:0
                                       data2:0]
              atStart:NO];
}
@end

int main() {
  @autoreleasepool {
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    KumoNativePanelTestRunner* runner = [[KumoNativePanelTestRunner alloc] init];
    NSApp.delegate = runner;
    [NSApp run];
  }
  return exit_status;
}
