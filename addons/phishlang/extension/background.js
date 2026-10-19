import {createPhishingProtection} from './phishing-background.js';

// This package has its own native host, identity and settings. Agent control and
// Kumo's built-in protection are independent of this optional add-on.
const protection = createPhishingProtection(chrome, {
  nativeHost: 'com.kumo.phishlang',
  settingsPath: 'settings.html',
  leaveURL: 'about:blank',
  nativeUnavailableMessage: 'The local companion is unavailable. Run install.command from the PhishLang add-on package, then enable protection again.',
});
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (typeof message?.type !== 'string' || !message.type.startsWith('phishing.')) return false;
  protection.handleMessage(message, sender).then(reply, error => reply({error: error.message}));
  return true;
});
chrome.runtime.onSuspend?.addListener(() => protection.shutdown());
