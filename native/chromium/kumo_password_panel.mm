#import <AppKit/AppKit.h>

#include "kumo_password_panel.h"

#include <utility>

namespace {

// A browser's canonical serialized origin is ASCII, contains no userinfo, and
// contains no path, query, fragment, whitespace, or control characters.
NSString* ValidatedOriginLabel(const std::string& origin) {
  if (origin.empty() || origin.size() > 4096)
    return nil;
  for (unsigned char character : origin) {
    if (character <= 0x20 || character >= 0x7f)
      return nil;
  }
  NSString* label = [[NSString alloc] initWithBytes:origin.data()
                                          length:origin.size()
                                        encoding:NSUTF8StringEncoding];
  NSURLComponents* components = [NSURLComponents componentsWithString:label];
  if (!components || components.host.length == 0 ||
      !([components.scheme isEqualToString:@"https"] ||
        [components.scheme isEqualToString:@"http"]) ||
      components.user != nil || components.password != nil ||
      components.query != nil || components.fragment != nil ||
      components.path.length != 0) {
    return nil;
  }
  return label;
}

std::u16string CopyUTF16(NSString* string) {
  static_assert(sizeof(char16_t) == sizeof(unichar));
  std::u16string result(string.length, u'\0');
  if (!result.empty()) {
    [string getCharacters:reinterpret_cast<unichar*>(result.data())
                    range:NSMakeRange(0, string.length)];
  }
  return result;
}

}  // namespace

@interface KumoPasswordPanelController : NSObject <NSWindowDelegate> {
 @private
  NSPanel* _panel;
  NSTextField* _credentialField;
  __weak NSWindow* _parent;
  id _parentCloseObserver;
  kumo::PasswordPanelCallback _callback;
  BOOL _completed;
  BOOL _ending;
}
- (instancetype)initWithOrigin:(NSString*)origin
                   isPassword:(BOOL)isPassword
                     callback:(kumo::PasswordPanelCallback)callback;
- (void)beginForParent:(NSWindow*)parent;
- (void)cancel:(id)sender;
@end

@implementation KumoPasswordPanelController

- (instancetype)initWithOrigin:(NSString*)origin
                   isPassword:(BOOL)isPassword
                     callback:(kumo::PasswordPanelCallback)callback {
  self = [super init];
  if (!self)
    return nil;
  _callback = std::move(callback);
  _panel = [[NSPanel alloc]
      initWithContentRect:NSMakeRect(0, 0, 650, 300)
                styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
                  backing:NSBackingStoreBuffered
                    defer:NO];
  _panel.title = isPassword ? @"Choose a password in Apple Passwords"
                            : @"Choose an account in Apple Passwords";
  _panel.restorable = NO;
  _panel.releasedWhenClosed = NO;
  _panel.delegate = self;
  NSView* view = _panel.contentView;

  NSTextField* destination = [NSTextField labelWithString:@"Destination site"];
  destination.font = [NSFont boldSystemFontOfSize:13];
  destination.frame = NSMakeRect(24, 260, 602, 22);
  [view addSubview:destination];

  NSScrollView* originScroller = [[NSScrollView alloc] initWithFrame:NSMakeRect(24, 208, 602, 48)];
  originScroller.borderType = NSBezelBorder;
  originScroller.hasVerticalScroller = YES;
  NSTextView* originView = [[NSTextView alloc] initWithFrame:originScroller.bounds];
  originView.editable = NO;
  originView.selectable = YES;
  originView.richText = NO;
  originView.font = [NSFont monospacedSystemFontOfSize:13 weight:NSFontWeightRegular];
  originView.string = origin;
  originView.verticallyResizable = YES;
  originView.horizontallyResizable = NO;
  originView.textContainer.widthTracksTextView = YES;
  originScroller.documentView = originView;
  [view addSubview:originScroller];

  NSString* guidance = isPassword
      ? @"Right-click the field below → AutoFill → Passwords. In Apple’s chooser, "
         "select the website or app entry and saved account. "
         "Click Fill once the password appears here."
      : @"Right-click the field below → AutoFill → Passwords. In Apple’s chooser, "
         "select the website or app entry and saved account. "
         "Click Fill once the username appears here.";
  NSTextField* instructions = [NSTextField wrappingLabelWithString:guidance];
  instructions.frame = NSMakeRect(24, 145, 602, 50);
  [view addSubview:instructions];

  if (isPassword) {
    _credentialField = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(24, 98, 602, 30)];
    _credentialField.contentType = NSTextContentTypePassword;
    _credentialField.placeholderString = @"Password selected with AutoFill → Passwords";
    _credentialField.accessibilityLabel = @"Password";
  } else {
    _credentialField = [[NSTextField alloc] initWithFrame:NSMakeRect(24, 98, 602, 30)];
    _credentialField.contentType = NSTextContentTypeUsername;
    _credentialField.placeholderString = @"Username selected with AutoFill → Passwords";
    _credentialField.accessibilityLabel = @"Username";
  }
  _credentialField.accessibilityHelp = @"Use this field’s AutoFill → Passwords menu. "
      "In Apple’s chooser, select the website or app entry and saved account, "
      "then click Fill once the selected value appears here.";
  _credentialField.usesSingleLineMode = YES;
  [view addSubview:_credentialField];
  _panel.initialFirstResponder = _credentialField;

  NSButton* cancel = [NSButton buttonWithTitle:@"Cancel" target:self action:@selector(cancel:)];
  cancel.frame = NSMakeRect(422, 27, 98, 32);
  cancel.keyEquivalent = @"\e";
  [view addSubview:cancel];
  NSButton* fill = [NSButton buttonWithTitle:@"Fill" target:self action:@selector(fill:)];
  fill.frame = NSMakeRect(528, 27, 98, 32);
  fill.keyEquivalent = @"\r";
  [view addSubview:fill];
  return self;
}

- (void)beginForParent:(NSWindow*)parent {
  _parent = parent;
  __weak KumoPasswordPanelController* weakSelf = self;
  _parentCloseObserver = [[NSNotificationCenter defaultCenter]
      addObserverForName:NSWindowWillCloseNotification
                  object:parent
                   queue:NSOperationQueue.mainQueue
              usingBlock:^(NSNotification* /* notification */) {
                [weakSelf cancel:nil];
              }];
  // The sheet completion block retains this controller until dismissal. Its
  // controls, callback, and observer then get cleared before returning a value.
  [parent beginSheet:_panel completionHandler:^(NSModalResponse response) {
    [self completeWithResponse:response];
  }];
}

- (void)fill:(id)sender {
  [self endWithResponse:NSModalResponseOK];
}

- (void)cancel:(id)sender {
  [self endWithResponse:NSModalResponseCancel];
}

- (void)endWithResponse:(NSModalResponse)response {
  if (_completed || _ending)
    return;
  _ending = YES;
  NSWindow* parent = _parent;
  if (parent && parent.attachedSheet == _panel) {
    [parent endSheet:_panel returnCode:response];
  } else {
    [self completeWithResponse:NSModalResponseCancel];
  }
}

- (BOOL)windowShouldClose:(NSWindow*)sender {
  [self cancel:nil];
  return NO;
}

- (void)completeWithResponse:(NSModalResponse)response {
  if (_completed)
    return;
  _completed = YES;
  const bool accepted = response == NSModalResponseOK;
  std::u16string value = accepted ? CopyUTF16(_credentialField.stringValue) : std::u16string();
  NSText* editor = _credentialField.currentEditor;
  editor.string = @"";
  _credentialField.stringValue = @"";
  // AppKit strings are released; this does not claim secure memory zeroing.
  [_panel orderOut:nil];
  _panel.delegate = nil;
  _credentialField = nil;
  _panel = nil;
  if (_parentCloseObserver) {
    [[NSNotificationCenter defaultCenter] removeObserver:_parentCloseObserver];
    _parentCloseObserver = nil;
  }
  _parent = nil;
  auto callback = std::move(_callback);
  _callback = {};
  if (callback)
    callback(accepted, std::move(value));
}

- (void)dealloc {
  if (_parentCloseObserver)
    [[NSNotificationCenter defaultCenter] removeObserver:_parentCloseObserver];
}

@end

namespace kumo {

void ShowKumoPasswordPanel(NSWindow* parent,
                           const std::string& trusted_origin,
                           bool is_password,
                           PasswordPanelCallback callback) {
  NSString* origin = ValidatedOriginLabel(trusted_origin);
  if (![NSThread isMainThread] || !parent || !parent.visible || parent.attachedSheet || !origin) {
    if (callback)
      callback(false, {});
    return;
  }
  KumoPasswordPanelController* controller =
      [[KumoPasswordPanelController alloc] initWithOrigin:origin
                                             isPassword:is_password
                                               callback:std::move(callback)];
  [controller beginForParent:parent];
}

void CancelKumoPasswordPanel(NSWindow* parent) {
  if (![NSThread isMainThread] || !parent)
    return;
  id delegate = parent.attachedSheet.delegate;
  if ([delegate isKindOfClass:KumoPasswordPanelController.class])
    [(KumoPasswordPanelController*)delegate cancel:nil];
}

}  // namespace kumo
