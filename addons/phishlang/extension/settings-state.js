// A model score is a signal, never a declaration that a website is safe.
export function phishingView(status, hasPermission) {
  if (status?.ok !== true || status.included !== true) return {
    label: 'Unavailable', tone: 'unavailable',
    description: 'The extension could not initialize. Reload it in Kumo’s Extensions page and try again.',
    enableDisabled: true, disableDisabled: hasPermission !== true,
  };
  if (status.enabled !== true) return {
    label: 'Off', tone: 'off',
    description: status.health === 'unavailable'
      ? 'The local companion could not be reached. Run install.command from the PhishLang add-on package, then try again.'
      : 'Pages are not being analyzed. Enable local warnings when you are ready.',
    enableDisabled: false, disableDisabled: hasPermission !== true,
  };
  if (status.health !== 'ready' || hasPermission !== true) return {
    label: 'Unavailable', tone: 'unavailable',
    description: 'Protection is enabled, but pages may go unchecked. Turn it off and enable it again to retry the local companion.',
    enableDisabled: true, disableDisabled: false,
  };
  return {
    label: 'Enabled', tone: 'ready',
    description: 'Enabled. The local model is connected. Warnings are experimental and can miss phishing or flag legitimate sites.',
    enableDisabled: true, disableDisabled: false,
  };
}

export function pageResultText(result, enabled) {
  if (!enabled) return 'No page analysis while protection is off.';
  return {
    suspicious: 'A phishing warning was raised for this page.',
    partial: 'Only part of this page could be analyzed.',
    'no-signal': 'No phishing signal in the checked content. This does not establish that the page is safe.',
    unavailable: 'This page could not be checked.',
  }[result?.status] || 'No result for the current page. Private tabs, embedded frames and restricted pages are not checked.';
}
