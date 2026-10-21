#import <AppKit/AppKit.h>

#include "../native/chromium/kumo_pairing_panel.h"

#include <cstdio>
#include <atomic>
#include <functional>
#include <memory>
#include <stdexcept>
#include <unistd.h>

namespace {
int assertions = 0;
int exit_status = 1;

void Expect(bool condition, const char* message) {
  ++assertions;
  if (!condition)
    throw std::runtime_error(message);
}

// Only this process's synthetic AppKit windows are used. Every component call
// injects geometry; no Apple helper, CGWindowList query, vault, or clipboard.
void Pump(double seconds = 0.3) {
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:seconds];
  while (deadline.timeIntervalSinceNow > 0) {
    @autoreleasepool {
      NSEvent* event = [NSApp nextEventMatchingMask:NSEventMaskAny
          untilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]
          inMode:NSDefaultRunLoopMode dequeue:YES];
      if (event)
        [NSApp sendEvent:event];
      [NSApp updateWindows];
    }
  }
}

NSWindow* Parent() {
  NSWindow* window = [[NSWindow alloc] initWithContentRect:NSMakeRect(10000, 10000, 800, 600)
      styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
      backing:NSBackingStoreBuffered defer:NO];
  window.title = @"Synthetic pairing component test";
  window.releasedWhenClosed = NO;
  window.restorable = NO;
  [window orderFront:nil];
  Expect(window.visible, "synthetic parent must be visible to AppKit");
  return window;
}

NSPanel* Panel() {
  for (NSWindow* window in NSApp.windows) {
    if ([window isKindOfClass:NSPanel.class] && window.delegate &&
        [window.title isEqualToString:@"Connect Apple Passwords"])
      return (NSPanel*)window;
  }
  return nil;
}

NSSecureTextField* Field(NSView* view) {
  if ([view isKindOfClass:NSSecureTextField.class])
    return (NSSecureTextField*)view;
  for (NSView* child in view.subviews) {
    if (NSSecureTextField* field = Field(child))
      return field;
  }
  return nil;
}

NSButton* Button(NSView* view, NSString* title) {
  if ([view isKindOfClass:NSButton.class] && [((NSButton*)view).title isEqualToString:title])
    return (NSButton*)view;
  for (NSView* child in view.subviews) {
    if (NSButton* button = Button(child, title))
      return button;
  }
  return nil;
}

struct Result {
  int calls = 0;
  bool accepted = false;
  std::string code;
};

kumo::PairingCodeCallback Capture(const std::shared_ptr<Result>& result) {
  return [result](bool accepted, std::string code) {
    ++result->calls;
    result->accepted = accepted;
    result->code = std::move(code);
  };
}

kumo::PairingGeometry Available() {
  // Read display geometry only, never other applications' windows. AppKit may
  // constrain synthetic panels to real displays, so injected coordinates must
  // describe an actual visible display for successful-placement scenarios.
  NSRect screen = NSScreen.screens.firstObject.visibleFrame;
  return {{{screen.origin.x, screen.origin.y, screen.size.width, screen.size.height}},
          {{screen.origin.x + screen.size.width / 3,
            screen.origin.y + screen.size.height / 3, 320, 180}}};
}

void CheckActualFrame(NSPanel* panel, const kumo::PairingGeometry& geometry) {
  NSRect frame = panel.frame;
  bool contained = false;
  for (const auto& screen : geometry.visible_screens) {
    contained |= frame.origin.x >= screen.x && frame.origin.y >= screen.y &&
        NSMaxX(frame) <= screen.x + screen.width &&
        NSMaxY(frame) <= screen.y + screen.height;
  }
  Expect(panel.visible && contained, "actual AppKit frame must be inside injected visible screen");
  for (const auto& helper : geometry.helper_windows) {
    Expect(NSMaxX(frame) + 12 <= helper.x || helper.x + helper.width + 12 <= frame.origin.x ||
               NSMaxY(frame) + 12 <= helper.y || helper.y + helper.height + 12 <= frame.origin.y,
           "actual AppKit frame must retain gap from every helper window");
  }
}

void SetCode(NSPanel* panel, NSString* value) {
  NSSecureTextField* field = Field(panel.contentView);
  [panel makeFirstResponder:nil];
  field.stringValue = value;
  [[NSNotificationCenter defaultCenter] postNotificationName:NSControlTextDidChangeNotification
      object:field];
}

void Cancelled(const std::shared_ptr<Result>& result) {
  Expect(result->calls == 1 && !result->accepted && result->code.empty(),
         "cancel callback must be exactly once and contain no code");
}

void Run() {
  using kumo::PairingPanelState;
  NSWindow* parent = Parent();
  {
    auto result = std::make_shared<Result>();
    int reads = 0;
    auto provider = [&] { ++reads; return Available(); };
    Expect(kumo::ShowKumoPairingPanel(nil, 123, Capture(result), provider) ==
               PairingPanelState::kInvalidRequest, "null parent must fail");
    Cancelled(result);
    Expect(reads == 0, "invalid request must not invoke any bounds provider");
    for (pid_t pid : {pid_t(0), pid_t(-1), getpid()}) {
      auto invalid = std::make_shared<Result>();
      Expect(kumo::ShowKumoPairingPanel(parent, pid, Capture(invalid), provider) ==
                 PairingPanelState::kInvalidRequest, "invalid helper identity must fail");
      Cancelled(invalid);
    }
    Expect(reads == 0, "invalid helper IDs must not inspect windows");
  }
  {
    auto result = std::make_shared<Result>();
    auto returned = std::make_shared<std::atomic<int>>(-1);
    auto reads = std::make_shared<std::atomic<int>>(0);
    auto on_main = std::make_shared<bool>(false);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
      auto state = kumo::ShowKumoPairingPanel(parent, 123,
          [result, on_main](bool accepted, std::string code) {
            *on_main = NSThread.isMainThread;
            Capture(result)(accepted, std::move(code));
          }, [reads] { ++*reads; return kumo::PairingGeometry{}; });
      returned->store(static_cast<int>(state));
    });
    Pump();
    Expect(returned->load() == static_cast<int>(PairingPanelState::kInvalidRequest),
           "off-main Show must reject without opening a panel");
    Cancelled(result);
    Expect(*on_main && reads->load() == 0,
           "off-main misuse must complete on main without consulting bounds");
  }
  {
    auto geometry = std::make_shared<kumo::PairingGeometry>();
    auto reads = std::make_shared<int>(0);
    auto result = std::make_shared<Result>();
    std::vector<PairingPanelState> states;
    auto provider = [geometry, reads] { ++*reads; return *geometry; };
    Expect(kumo::ShowKumoPairingPanel(parent, 123, Capture(result), provider,
               [&](auto state) { states.push_back(state); }) ==
               PairingPanelState::kHelperUnavailable,
           "entry must start hidden without helper bounds");
    NSPanel* panel = Panel();
    Expect(panel && !panel.visible && result->calls == 0,
           "unavailable bounds must not reveal entry or complete request");
    *geometry = Available();
    Expect(kumo::RefreshKumoPairingPanel(parent) == PairingPanelState::kVisible,
           "valid bounds must reveal safely positioned entry");
    Expect(panel.visible && !panel.floatingPanel && !panel.hidesOnDeactivate &&
               panel.level == NSNormalWindowLevel && !parent.attachedSheet,
           "entry must be an ordinary non-modal panel surviving deactivation");
    CheckActualFrame(panel, *geometry);
    Expect(Field(panel.contentView) && Field(panel.contentView).editable,
           "code entry must be a native secure text field");
    SetCode(panel, @"012345");
    Expect(Button(panel.contentView, @"Connect").enabled,
           "six ASCII digits must enable explicit Connect");
    [panel resignKeyWindow];
    Pump();
    Expect(result->calls == 0 && panel.visible,
           "loss of focus must not dismiss code entry");
    NSRect old = panel.frame;
    geometry->helper_windows = {{old.origin.x, old.origin.y, old.size.width, old.size.height}};
    kumo::RefreshKumoPairingPanel(parent);
    CheckActualFrame(panel, *geometry);
    Expect(!NSEqualRects(old, panel.frame), "helper movement must reposition only Kumo entry");
    Expect(geometry->helper_windows[0].x == old.origin.x,
           "component must not mutate helper geometry");
    geometry->helper_windows = geometry->visible_screens;
    Expect(kumo::RefreshKumoPairingPanel(parent) == PairingPanelState::kNoRoom,
           "full helper coverage must report no room");
    Expect(!panel.visible && Field(panel.contentView).stringValue.length == 0,
           "no room must hide entry and clear previously typed digits");
    geometry->helper_windows = {{0, 0, -1, 10}};
    Expect(kumo::RefreshKumoPairingPanel(parent) == PairingPanelState::kInvalidGeometry,
           "invalid bounds must be reported distinctly");
    *geometry = Available();
    kumo::RefreshKumoPairingPanel(parent);
    auto duplicate = std::make_shared<Result>();
    Expect(kumo::ShowKumoPairingPanel(parent, 123, Capture(duplicate), provider) ==
               PairingPanelState::kAlreadyOpen, "duplicate request must fail without replacing entry");
    Cancelled(duplicate);
    Expect(Panel() == panel && result->calls == 0, "original request must survive duplicate");
    kumo::CancelKumoPairingPanel(parent);
    Cancelled(result);
    int after_cancel = *reads;
    Pump(0.6);
    Expect(*reads == after_cancel, "completion must invalidate timer and stop bounds lookup");
    [[NSNotificationCenter defaultCenter]
        postNotificationName:NSApplicationDidChangeScreenParametersNotification object:nil];
    Expect(*reads == after_cancel, "completion must remove screen observer");
    Expect(states.size() >= 5, "caller must receive placement availability transitions");
    kumo::CancelKumoPairingPanel(parent);
    Cancelled(result);
  }
  {
    auto result = std::make_shared<Result>();
    auto offscreen = [] {
      return kumo::PairingGeometry{{{10000, 10000, 1200, 800}},
                                  {{10400, 10300, 400, 200}}};
    };
    Expect(kumo::ShowKumoPairingPanel(parent, 123, Capture(result), offscreen) ==
               PairingPanelState::kNoRoom,
           "AppKit clamping outside injected screens must not be reported safe");
    Expect(!Panel().visible && result->calls == 0,
           "unsafe actual frame must hide entry without accepting anything");
    kumo::CancelKumoPairingPanel(parent);
    Cancelled(result);
  }
  {
    auto result = std::make_shared<Result>();
    NSRect screen = NSScreen.screens.firstObject.visibleFrame;
    kumo::PairingGeometry narrow{
      {{screen.origin.x, screen.origin.y, 320, 480}},
      {{screen.origin.x, screen.origin.y + 280, 320, 200}}};
    Expect(kumo::ShowKumoPairingPanel(parent, 123, Capture(result), [narrow] { return narrow; }) ==
               PairingPanelState::kVisible, "small injected visible area must fit a compact panel");
    NSPanel* panel = Panel();
    CheckActualFrame(panel, narrow);
    Expect(panel.frame.size.width == 300, "actual AppKit panel must use compact width");
    kumo::CancelKumoPairingPanel(parent);
    Cancelled(result);
  }
  {
    auto result = std::make_shared<Result>();
    kumo::ShowKumoPairingPanel(parent, 123, Capture(result), Available);
    NSPanel* panel = Panel();
    for (NSString* invalid in @[@"", @"12345", @"1234567", @"１２３４５６", @"12 456"] ) {
      SetCode(panel, invalid);
      Expect(!Button(panel.contentView, @"Connect").enabled,
             "invalid code must not enable Connect");
      [Button(panel.contentView, @"Connect") performClick:nil];
      Expect(result->calls == 0, "invalid code must not be accepted");
    }
    // Programmatic field assignments can bypass edit validation; accept must
    // independently validate rather than trust the button's enabled state.
    SetCode(panel, @"123456");
    Field(panel.contentView).stringValue = @"12x456";
    [Button(panel.contentView, @"Connect") performClick:nil];
    Expect(result->calls == 0, "accept must reject an invalid value after button enablement");
    SetCode(panel, @"012345");
    [Button(panel.contentView, @"Connect") performClick:nil];
    Expect(result->calls == 1 && result->accepted && result->code == "012345",
           "explicit Connect must deliver six validated digits once");
    Expect(Field(panel.contentView).stringValue.length == 0 && !panel.visible &&
               kumo::RefreshKumoPairingPanel(parent) == PairingPanelState::kClosed,
           "acceptance must clear text and remove active controller");
    result->code.assign(result->code.size(), '\0');
    result->code.clear();
    kumo::CancelKumoPairingPanel(parent);
    Expect(result->calls == 1, "late cancel must not repeat acceptance");
  }
  {
    auto result = std::make_shared<Result>();
    NSSecureTextField* retained_field = nil;
    kumo::ShowKumoPairingPanel(parent, 123,
        [&, result](bool accepted, std::string code) {
          Expect(retained_field.stringValue.length == 0 &&
                     kumo::RefreshKumoPairingPanel(parent) == PairingPanelState::kClosed,
                 "text and active association must be cleared before callback");
          Capture(result)(accepted, std::move(code));
        }, Available);
    retained_field = Field(Panel().contentView);
    SetCode(Panel(), @"654321");
    [Panel() performClose:nil];
    Cancelled(result);
  }
  {
    auto result = std::make_shared<Result>();
    const auto state = kumo::ShowKumoPairingPanel(parent, 123, Capture(result), Available,
        [&](auto) { kumo::CancelKumoPairingPanel(parent); });
    Expect(state == PairingPanelState::kClosed,
           "reentrant state cancellation must finish safely before Show returns");
    Cancelled(result);
    Expect(Panel() == nil, "reentrant cancellation must leave no live panel delegate");
  }
  {
    auto first = std::make_shared<Result>();
    auto second = std::make_shared<Result>();
    bool reopened = false;
    auto state = kumo::ShowKumoPairingPanel(parent, 123, Capture(first), Available,
        [&](auto) {
          if (!reopened) {
            reopened = true;
            kumo::CancelKumoPairingPanel(parent);
            kumo::ShowKumoPairingPanel(parent, 123, Capture(second), Available);
          }
        });
    Expect(state == PairingPanelState::kClosed,
           "reentrant replacement must finish the original Show safely");
    Cancelled(first);
    Expect(Panel().visible && second->calls == 0,
           "reentrant state replacement must leave the new request active");
    kumo::CancelKumoPairingPanel(parent);
    Cancelled(second);
  }
  {
    auto first = std::make_shared<Result>();
    auto second = std::make_shared<Result>();
    auto state = kumo::ShowKumoPairingPanel(parent, 123, Capture(first), [&] {
      kumo::CancelKumoPairingPanel(parent);
      kumo::ShowKumoPairingPanel(parent, 123, Capture(second), Available);
      return Available();
    });
    Expect(state == PairingPanelState::kClosed,
           "reentrant provider replacement must finish original request safely");
    Cancelled(first);
    Expect(Panel().visible && second->calls == 0,
           "reentrant provider replacement must leave new request active");
    kumo::CancelKumoPairingPanel(parent);
    Cancelled(second);
  }
  {
    auto result = std::make_shared<Result>();
    kumo::ShowKumoPairingPanel(parent, 123, Capture(result), Available);
    NSPanel* panel = Panel();
    SetCode(panel, @"123456");
    [parent close];
    Cancelled(result);
    Expect(!panel.visible && Field(panel.contentView).stringValue.length == 0,
           "parent close must dismiss and clear entry");
  }
}
}  // namespace

@interface KumoPairingTestRunner : NSObject <NSApplicationDelegate>
@end
@implementation KumoPairingTestRunner
- (void)applicationDidFinishLaunching:(NSNotification*)notification {
  (void)notification;
  [self performSelector:@selector(runTests) withObject:nil afterDelay:0];
}
- (void)runTests {
  @autoreleasepool {
    @try {
      try {
        Run();
        exit_status = 0;
      } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL at check %d: %s\n", assertions, error.what());
      }
    } @catch (NSException*) {
      std::fprintf(stderr, "FAIL: unexpected synthetic pairing panel exception\n");
    }
    if (exit_status == 0)
      std::printf("PASS: %d synthetic pairing panel checks\n", assertions);
  }
  [NSApp stop:nil];
  [NSApp postEvent:[NSEvent otherEventWithType:NSEventTypeApplicationDefined
      location:NSZeroPoint modifierFlags:0 timestamp:0 windowNumber:0 context:nil
      subtype:0 data1:0 data2:0] atStart:NO];
}
@end

int main() {
  @autoreleasepool {
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    KumoPairingTestRunner* runner = [[KumoPairingTestRunner alloc] init];
    NSApp.delegate = runner;
    [NSApp run];
  }
  return exit_status;
}
