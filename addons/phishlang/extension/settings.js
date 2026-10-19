import {phishingView, pageResultText} from './settings-state.js';

export const WEBSITE_ORIGINS = ['http://*/*', 'https://*/*'];

export function installSettings(api, document) {
  const element = id => document.getElementById(id);
  const enable = element('enablePhishing'), disable = element('disablePhishing');
  const error = element('settingsError');
  let busy = false;
  async function request(type, extra = {}) {
    const result = await api.runtime.sendMessage({type, ...extra});
    if (result?.error || result?.ok !== true) throw new Error(result?.error || 'The extension is unavailable. Reload it in Kumo’s Extensions page.');
    return result;
  }
  function render(status, permission) {
    const view = phishingView(status, permission);
    element('protectionStatus').textContent = view.label;
    element('protectionStatus').dataset.tone = view.tone;
    element('phishingStatus').textContent = view.description;
    element('pageResult').textContent = pageResultText(status?.currentTab, status?.enabled === true);
    element('modelVersion').textContent = typeof status?.modelVersion === 'string' ? status.modelVersion.slice(0, 12) : 'Not loaded';
    element('websiteAccess').textContent = permission ? 'Allowed for HTTP and HTTPS pages' : 'Not granted';
    enable.disabled = busy || view.enableDisabled;
    disable.disabled = busy || view.disableDisabled;
  }
  async function refresh() {
    try {
      const tabs = await api.tabs.query({active: true, currentWindow: true});
      const tabId = tabs[0]?.id;
      const [status, permission] = await Promise.all([
        request('phishing.status', Number.isSafeInteger(tabId) ? {tabId} : {}),
        api.permissions.contains({origins: WEBSITE_ORIGINS}),
      ]);
      render(status, permission);
    } catch (failure) {
      const permission = await api.permissions.contains({origins: WEBSITE_ORIGINS}).catch(() => false);
      render(null, permission);
      error.textContent = failure.message;
    }
  }
  enable.onclick = async () => {
    if (busy) return;
    busy = true; enable.disabled = true; disable.disabled = true; error.textContent = '';
    try {
      // Request optional page access directly in this click's user gesture.
      if (!await api.permissions.request({origins: WEBSITE_ORIGINS})) throw new Error('Website access was not granted. Protection remains off.');
      await request('phishing.enable');
    } catch (failure) { error.textContent = failure.message; }
    finally { busy = false; await refresh(); }
  };
  disable.onclick = async () => {
    if (busy) return;
    busy = true; enable.disabled = true; disable.disabled = true; error.textContent = '';
    try {
      try { await request('phishing.disable'); }
      finally { await api.permissions.remove({origins: WEBSITE_ORIGINS}); }
    } catch (failure) { error.textContent = failure.message; }
    finally { busy = false; await refresh(); }
  };
  return {ready: refresh(), refresh};
}

if (typeof chrome !== 'undefined' && typeof document !== 'undefined') {
  const settings = installSettings(chrome, document);
  setInterval(() => { if (document.visibilityState === 'visible') void settings.refresh(); }, 2500);
}
