import {DEFAULTS} from './shared.js';
const preferences = (await chrome.storage.local.get('preferences')).preferences || DEFAULTS;
document.documentElement.dataset.theme = preferences.theme;
async function refresh() { const state = await chrome.runtime.sendMessage({type: 'agent.status'}); document.getElementById('status').textContent = state.enabled ? `Enabled for ${state.grants.length} tab(s). Revocation takes effect immediately.` : 'Off. No tabs are shared with agents.'; }
document.getElementById('manage').onclick = () => { chrome.tabs.create({url: chrome.runtime.getURL('newtab.html#agents')}); window.close(); };
document.getElementById('revoke').onclick = async () => { await chrome.runtime.sendMessage({type: 'agent.disable'}); await refresh(); };
refresh();
