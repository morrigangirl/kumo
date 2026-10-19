// Both the sealed package and background runtime must include the classifier
// before settings can offer website access for it.
export function phishingControlState(buildInfo, status) {
  if (buildInfo?.phishingProtection?.included === false) return {
    included: false, enableDisabled: true, disableDisabled: true,
    description: 'Not included in this release. Known-malware-domain blocking and download antivirus are configured separately above.',
  };
  if (buildInfo?.phishingProtection?.included !== true || status?.included !== true) return {
    included: false, enableDisabled: true, disableDisabled: true,
    description: 'Local phishing analysis is unavailable in this build.',
  };
  const enabled = status.enabled === true;
  return {
    included: true, enableDisabled: enabled, disableDisabled: !enabled,
    description: enabled
      ? status.health === 'ready' ? 'Enabled. Page analysis stays on this Mac.' : 'Enabled, but the local model is unavailable. Pages may go unchecked. Relaunch Kumo or turn protection off and on.'
      : 'Off. Enable local page analysis to receive phishing warnings.',
  };
}
