#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <objc/runtime.h>

#include "kumo_pairing_panel.h"

#include <array>
#include <utility>
#include <unistd.h>

namespace {

char kPairingControllerKey;

kumo::PairingGeometry ReadHelperBounds(pid_t helper_pid) {
  kumo::PairingGeometry geometry;
  // Quartz's desktop origin is top-left; AppKit's is bottom-left on the display
  // containing the menu bar. Keep negative secondary-screen coordinates intact.
  NSScreen* primary = NSScreen.screens.firstObject;
  if (!primary)
    return geometry;
  const double desktop_top = NSMaxY(primary.frame);
  for (NSScreen* screen in NSScreen.screens) {
    NSRect frame = screen.visibleFrame;
    geometry.visible_screens.push_back({frame.origin.x, frame.origin.y,
                                       frame.size.width, frame.size.height});
  }
  CFArrayRef raw = CGWindowListCopyWindowInfo(
      kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements,
      kCGNullWindowID);
  NSArray* windows = CFBridgingRelease(raw);
  std::vector<kumo::PairingWindowBounds> helper_bounds;
  for (NSDictionary* window in windows) {
    // Do not request, inspect, or record names, titles, pixels, accessibility
    // data, or any other application's bounds. The PID is supplied by caller.
    NSNumber* owner = window[(__bridge NSString*)kCGWindowOwnerPID];
    if (![owner isKindOfClass:NSNumber.class] || owner.intValue != helper_pid)
      continue;
    NSDictionary* bounds = window[(__bridge NSString*)kCGWindowBounds];
    CGRect rect;
    if (![bounds isKindOfClass:NSDictionary.class] ||
        !CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)bounds, &rect)) {
      // An unreadable helper window prevents claiming safe placement.
      geometry.helper_windows.clear();
      return geometry;
    }
    helper_bounds.push_back({helper_pid, {rect.origin.x, rect.origin.y,
                                         rect.size.width, rect.size.height}});
  }
  return kumo::PairingGeometryFromBounds(geometry.visible_screens, helper_bounds,
                                        helper_pid, desktop_top);
}

bool ValidCode(NSString* value) {
  if (value.length != 6)
    return false;
  std::array<char16_t, 6> characters;
  [value getCharacters:reinterpret_cast<unichar*>(characters.data())
                 range:NSMakeRange(0, characters.size())];
  return kumo::IsSixDigitPairingCode(characters.data(), characters.size());
}

bool SafeActualFrame(NSRect frame, const kumo::PairingGeometry& geometry) {
  return frame.size.width >= 300 && frame.size.height >= 194 &&
      kumo::IsPairingFrameSafe({frame.origin.x, frame.origin.y,
                                frame.size.width, frame.size.height}, geometry);
}

kumo::PairingPanelState StateFor(kumo::PairingPlacementStatus status) {
  switch (status) {
    case kumo::PairingPlacementStatus::kPlaced:
      return kumo::PairingPanelState::kVisible;
    case kumo::PairingPlacementStatus::kUnavailable:
      return kumo::PairingPanelState::kHelperUnavailable;
    case kumo::PairingPlacementStatus::kInvalid:
      return kumo::PairingPanelState::kInvalidGeometry;
    case kumo::PairingPlacementStatus::kNoRoom:
      return kumo::PairingPanelState::kNoRoom;
  }
}

}  // namespace

@interface KumoPairingPanelController : NSObject <NSWindowDelegate, NSTextFieldDelegate> {
 @private
  __weak NSWindow* _parent;
  NSPanel* _panel;
  NSSecureTextField* _code;
  NSButton* _unlock;
  NSTimer* _timer;
  id _closeObserver;
  id _screenObserver;
  kumo::PairingCodeCallback _callback;
  kumo::PairingGeometryProvider _geometryProvider;
  kumo::PairingPanelStateCallback _stateCallback;
  kumo::PairingPanelState _state;
  BOOL _hasState;
  BOOL _completed;
  BOOL _adjusting;
}
- (instancetype)initWithParent:(NSWindow*)parent
                     callback:(kumo::PairingCodeCallback)callback
             geometryProvider:(kumo::PairingGeometryProvider)provider
                stateCallback:(kumo::PairingPanelStateCallback)stateCallback;
- (kumo::PairingPanelState)begin;
- (kumo::PairingPanelState)refresh;
- (void)cancel:(id)sender;
@end

@implementation KumoPairingPanelController

- (instancetype)initWithParent:(NSWindow*)parent
                     callback:(kumo::PairingCodeCallback)callback
             geometryProvider:(kumo::PairingGeometryProvider)provider
                stateCallback:(kumo::PairingPanelStateCallback)stateCallback {
  self = [super init];
  if (!self)
    return nil;
  _parent = parent;
  _callback = std::move(callback);
  _geometryProvider = std::move(provider);
  _stateCallback = std::move(stateCallback);
  _panel = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, 360, 188)
      styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
      backing:NSBackingStoreBuffered defer:NO];
  _panel.title = @"Connect Apple Passwords";
  _panel.delegate = self;
  _panel.level = NSNormalWindowLevel;
  _panel.floatingPanel = NO;
  _panel.hidesOnDeactivate = NO;
  _panel.becomesKeyOnlyIfNeeded = NO;
  _panel.restorable = NO;
  _panel.releasedWhenClosed = NO;
  _panel.animationBehavior = NSWindowAnimationBehaviorNone;
  NSView* view = _panel.contentView;

  NSTextField* guidance = [NSTextField wrappingLabelWithString:
      @"Enter the six-digit code shown by Apple. Keep Apple’s code window open."];
  _code = [[NSSecureTextField alloc] initWithFrame:NSZeroRect];
  _code.usesSingleLineMode = YES;
  _code.font = [NSFont monospacedDigitSystemFontOfSize:21 weight:NSFontWeightMedium];
  _code.placeholderString = @"6-digit code";
  _code.accessibilityLabel = @"Apple Passwords pairing code";
  _code.accessibilityHelp = @"Enter six digits from Apple’s separate code window.";
  _code.delegate = self;
  _code.allowsEditingTextAttributes = NO;
  NSButton* cancel = [NSButton buttonWithTitle:@"Cancel" target:self action:@selector(cancel:)];
  cancel.keyEquivalent = @"\e";
  _unlock = [NSButton buttonWithTitle:@"Connect" target:self action:@selector(accept:)];
  _unlock.keyEquivalent = @"\r";
  _unlock.enabled = NO;
  for (NSView* item in @[guidance, _code, cancel, _unlock]) {
    item.translatesAutoresizingMaskIntoConstraints = NO;
    [view addSubview:item];
  }
  [NSLayoutConstraint activateConstraints:@[
    [guidance.leadingAnchor constraintEqualToAnchor:view.leadingAnchor constant:18],
    [guidance.trailingAnchor constraintEqualToAnchor:view.trailingAnchor constant:-18],
    [guidance.topAnchor constraintEqualToAnchor:view.topAnchor constant:16],
    [_code.leadingAnchor constraintEqualToAnchor:guidance.leadingAnchor],
    [_code.trailingAnchor constraintEqualToAnchor:guidance.trailingAnchor],
    [_code.topAnchor constraintEqualToAnchor:guidance.bottomAnchor constant:12],
    [_code.heightAnchor constraintEqualToConstant:32],
    [_unlock.trailingAnchor constraintEqualToAnchor:guidance.trailingAnchor],
    [_unlock.bottomAnchor constraintEqualToAnchor:view.bottomAnchor constant:-12],
    [cancel.trailingAnchor constraintEqualToAnchor:_unlock.leadingAnchor constant:-8],
    [cancel.centerYAnchor constraintEqualToAnchor:_unlock.centerYAnchor],
    [cancel.topAnchor constraintGreaterThanOrEqualToAnchor:_code.bottomAnchor constant:10],
  ]];
  _panel.initialFirstResponder = _code;
  return self;
}

- (kumo::PairingPanelState)begin {
  __weak KumoPairingPanelController* weakSelf = self;
  _closeObserver = [[NSNotificationCenter defaultCenter]
      addObserverForName:NSWindowWillCloseNotification object:_parent
      queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification*) {
        [weakSelf cancel:nil];
      }];
  _screenObserver = [[NSNotificationCenter defaultCenter]
      addObserverForName:NSApplicationDidChangeScreenParametersNotification object:nil
      queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification*) {
        KumoPairingPanelController* controller = weakSelf;
        [controller refresh];
      }];
  _timer = [NSTimer timerWithTimeInterval:0.25 repeats:YES block:^(NSTimer*) {
    KumoPairingPanelController* controller = weakSelf;
    [controller refresh];
  }];
  [[NSRunLoop mainRunLoop] addTimer:_timer forMode:NSRunLoopCommonModes];
  return [self refresh];
}

- (void)clearCode {
  NSText* editor = _code.currentEditor;
  editor.string = @"";
  _code.stringValue = @"";
  _unlock.enabled = NO;
  // AppKit controls release their strings. This does not promise memory zeroing.
}

- (kumo::PairingPanelState)refresh {
  __attribute__((objc_precise_lifetime)) KumoPairingPanelController* keepAlive = self;
  (void)keepAlive;
  if (_completed)
    return kumo::PairingPanelState::kClosed;
  if (_adjusting)
    return _state;
  _adjusting = YES;
  std::optional<kumo::PairingRect> current;
  if (_panel.visible) {
    NSRect frame = _panel.frame;
    current = {{frame.origin.x, frame.origin.y, frame.size.width, frame.size.height}};
  }
  auto provider = _geometryProvider;
  const auto geometry = provider();
  if (_completed) {
    _adjusting = NO;
    return kumo::PairingPanelState::kClosed;
  }
  const auto placement = kumo::PlacePairingPanel(geometry, current);
  auto state = StateFor(placement.status);
  if (placement.frame) {
    const auto& frame = *placement.frame;
    [_panel setFrame:NSMakeRect(frame.x, frame.y, frame.width, frame.height) display:NO];
    // AppKit can constrain a requested frame. Check the actual frame before
    // revealing entry, rather than assuming the geometry solver's coordinates
    // were applied unchanged.
    NSRect actual = _panel.frame;
    if (SafeActualFrame(actual, geometry)) {
      if (!_panel.visible)
        [_panel orderFront:nil];
      actual = _panel.frame;
    }
    if (!SafeActualFrame(actual, geometry)) {
      [self clearCode];
      [_panel orderOut:nil];
      state = kumo::PairingPanelState::kNoRoom;
    }
  } else {
    [self clearCode];
    [_panel orderOut:nil];
  }
  const bool changed = !_hasState || _state != state;
  _state = state;
  _hasState = YES;
  _adjusting = NO;
  // Copy to survive a reentrant caller cancellation clearing the stored block.
  auto stateCallback = _stateCallback;
  if (changed && stateCallback)
    stateCallback(state);
  return _completed ? kumo::PairingPanelState::kClosed : state;
}

- (void)controlTextDidChange:(NSNotification*)notification {
  if (notification.object != _code || _completed)
    return;
  NSString* value = _code.stringValue;
  bool partialValid = value.length <= 6;
  for (NSUInteger i = 0; partialValid && i < value.length; ++i) {
    unichar c = [value characterAtIndex:i];
    partialValid = c >= '0' && c <= '9';
  }
  if (!partialValid)
    [self clearCode];
  _unlock.enabled = partialValid && ValidCode(_code.stringValue);
}

- (void)accept:(id)sender {
  (void)sender;
  if (_completed || [self refresh] != kumo::PairingPanelState::kVisible ||
      !ValidCode(_code.stringValue)) {
    return;
  }
  // Copy only six validated ASCII digits and never send them to a pasteboard,
  // log, user defaults, restoration state, or another process in this component.
  std::string code(6, '\0');
  for (NSUInteger i = 0; i < 6; ++i)
    code[i] = static_cast<char>([_code.stringValue characterAtIndex:i]);
  [self complete:YES code:std::move(code)];
}

- (void)cancel:(id)sender {
  (void)sender;
  [self complete:NO code:{}];
}

- (BOOL)windowShouldClose:(NSWindow*)sender {
  (void)sender;
  [self cancel:nil];
  return NO;
}

- (void)windowDidMove:(NSNotification*)notification {
  (void)notification;
  if (!_adjusting)
    [self refresh];
}

- (void)complete:(BOOL)accepted code:(std::string)code {
  if (_completed)
    return;
  __attribute__((objc_precise_lifetime)) KumoPairingPanelController* keepAlive = self;
  (void)keepAlive;
  _completed = YES;
  [self clearCode];
  [_panel orderOut:nil];
  _panel.delegate = nil;
  [_timer invalidate];
  _timer = nil;
  for (id observer in @[_closeObserver ?: NSNull.null, _screenObserver ?: NSNull.null]) {
    if (observer != NSNull.null)
      [[NSNotificationCenter defaultCenter] removeObserver:observer];
  }
  _closeObserver = nil;
  _screenObserver = nil;
  _geometryProvider = {};
  _stateCallback = {};
  NSWindow* parent = _parent;
  _parent = nil;
  objc_setAssociatedObject(parent, &kPairingControllerKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  auto callback = std::move(_callback);
  _callback = {};
  if (callback)
    callback(accepted, std::move(code));
}

- (void)dealloc {
  [_timer invalidate];
  if (_closeObserver)
    [[NSNotificationCenter defaultCenter] removeObserver:_closeObserver];
  if (_screenObserver)
    [[NSNotificationCenter defaultCenter] removeObserver:_screenObserver];
}

@end

namespace kumo {

PairingPanelState ShowKumoPairingPanel(NSWindow* parent,
                                      pid_t helper_pid,
                                      PairingCodeCallback callback,
                                      PairingGeometryProvider provider,
                                      PairingPanelStateCallback state_callback) {
  if (!NSThread.isMainThread) {
    // Reject misuse without touching AppKit off-main. Completion still follows
    // the component's main-thread lifecycle contract.
    dispatch_async(dispatch_get_main_queue(), ^{
      if (callback)
        callback(false, {});
    });
    return PairingPanelState::kInvalidRequest;
  }
  if (!parent || !parent.visible || helper_pid <= 0 || helper_pid == getpid()) {
    if (callback)
      callback(false, {});
    return PairingPanelState::kInvalidRequest;
  }
  if (objc_getAssociatedObject(parent, &kPairingControllerKey)) {
    if (callback)
      callback(false, {});
    return PairingPanelState::kAlreadyOpen;
  }
  if (!provider)
    provider = [helper_pid] { return ReadHelperBounds(helper_pid); };
  KumoPairingPanelController* controller = [[KumoPairingPanelController alloc]
      initWithParent:parent callback:std::move(callback)
      geometryProvider:std::move(provider) stateCallback:std::move(state_callback)];
  objc_setAssociatedObject(parent, &kPairingControllerKey, controller,
                           OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  return [controller begin];
}

PairingPanelState RefreshKumoPairingPanel(NSWindow* parent) {
  if (!NSThread.isMainThread)
    return PairingPanelState::kInvalidRequest;
  KumoPairingPanelController* controller = objc_getAssociatedObject(parent, &kPairingControllerKey);
  return controller ? [controller refresh] : PairingPanelState::kClosed;
}

void CancelKumoPairingPanel(NSWindow* parent) {
  if (!NSThread.isMainThread) {
    dispatch_async(dispatch_get_main_queue(), ^{ CancelKumoPairingPanel(parent); });
    return;
  }
  KumoPairingPanelController* controller = objc_getAssociatedObject(parent, &kPairingControllerKey);
  [controller cancel:nil];
}

}  // namespace kumo
