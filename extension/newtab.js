import {DEFAULTS, THEMES, searchURL, validateSettings, validateEngine, webURL, chromeTheme} from './shared.js';
import {engineSecurityStatus} from './security.js';
import {phishingControlState} from './phishing-status.js';
const $ = id => document.getElementById(id);
let settings = validateSettings((await chrome.storage.local.get('preferences')).preferences || DEFAULTS);
let buildInfo = {};
try {
  const packaged = await (await fetch(chrome.runtime.getURL('build-info.json'))).json();
  if (packaged && typeof packaged === 'object' && !Array.isArray(packaged)) buildInfo = packaged;
} catch {}
const securityStatus = engineSecurityStatus(buildInfo);
for (const card of document.querySelectorAll('[data-engine-status]')) {
  card.dataset.engineStatus = securityStatus.kind;
  card.querySelector('[data-engine-status-title]').textContent = securityStatus.title;
  card.querySelector('[data-engine-status-versions]').textContent = securityStatus.versions;
}
const appUpdates = buildInfo.appUpdates;
const appUpdatesIncluded = appUpdates?.included === true && appUpdates.provider === 'github-releases' && appUpdates.repository === 'morrigangirl/kumo';
const appUpdateVersion = appUpdatesIncluded ? `Kumo ${appUpdates.version || 'unavailable'} · Build ${appUpdates.build || 'unavailable'}` : 'App version and build are unavailable.';
const appUpdateStatus = appUpdatesIncluded && appUpdates.ready === true
  ? 'Release channel: GitHub Releases. The native updater verifies signed updates before installation.'
  : 'Local development build. Release updates require Developer ID signing, notarization and a configured update verification key.';
$('appVersion').textContent = appUpdatesIncluded ? String(appUpdates.version || 'Developer preview') : 'Developer preview';
for (const card of document.querySelectorAll('[data-app-updates]')) {
  card.querySelector('[data-app-update-version]').textContent = appUpdateVersion;
  card.querySelector('[data-app-update-status]').textContent = appUpdateStatus;
  card.querySelector('[data-app-check-updates]').disabled = !appUpdatesIncluded;
}
if (buildInfo.engineVersion) {
  $('engineDescription').textContent = `A native macOS browser using Chromium ${buildInfo.engineVersion} with the ungoogled-chromium patch set, a Swift launcher, and local customization. ${buildInfo.sourceCompiledLocally ? 'This engine was compiled locally with Kumo’s native source integration.' : 'This preview packages a verified upstream binary; the repository includes a separate source-build path.'}`;
}
const toast = (message, target = 'settingsToast') => { $(target).textContent = message; };
async function save() { settings = validateSettings(settings); await chrome.storage.local.set({preferences: settings}); render(); }
function makeOption(value, label) { const option = document.createElement('option'); option.value = value; option.textContent = label; return option; }
function render() {
  document.documentElement.dataset.theme = settings.theme;
  document.documentElement.style.setProperty('--accent', settings.accent);
  document.body.style.backgroundImage = settings.background ? `linear-gradient(var(--bg), transparent), url("${settings.background}")` : '';
  $('date').textContent = new Intl.DateTimeFormat(undefined, {weekday: 'long', month: 'long', day: 'numeric'}).format(new Date()).toUpperCase();
  const greeting = settings.greeting === DEFAULTS.greeting ? 'A little room\nto explore.' : settings.greeting;
  $('greeting').textContent = greeting;
  $('greetingInput').value = settings.greeting;
  $('accent').value = settings.accent;
  for (const id of ['searchEngine', 'defaultEngine']) {
    $(id).replaceChildren(...settings.engines.map(e => makeOption(e.id, e.name)));
    $(id).value = settings.engine;
  }
  $('shortcuts').replaceChildren(...settings.shortcuts.map(shortcut => {
    const link = document.createElement('a'); link.className = 'shortcut'; link.href = shortcut.url;
    const icon = document.createElement('span'); icon.className = 'shortcut-icon'; icon.textContent = shortcut.name[0]?.toUpperCase() || '↗';
    const name = document.createElement('span'); name.textContent = shortcut.name;
    link.append(icon, name); return link;
  }));
  const colors = {paper: '#eeeae3', midnight: '#23252c', forest: '#234333', lavender: '#ddd3eb', sand: '#e8d3b4', ocean: '#1f4359'};
  $('themes').replaceChildren(...THEMES.map(theme => {
    const button = document.createElement('button'); button.className = 'theme'; button.setAttribute('aria-pressed', String(settings.theme === theme));
    const preview = document.createElement('span'); preview.className = 'theme-preview'; preview.style.background = colors[theme]; preview.append(document.createElement('i'), document.createElement('i'));
    const label = document.createElement('span'); label.textContent = theme[0].toUpperCase() + theme.slice(1); button.append(preview, label);
    button.onclick = () => { settings.theme = theme; save(); }; return button;
  }));
  renderList('engineList', settings.engines, engine => { settings.engines = settings.engines.filter(e => e.id !== engine.id); save(); }, e => e.url, settings.engines.length === 1);
  renderList('shortcutList', settings.shortcuts, shortcut => { settings.shortcuts = settings.shortcuts.filter(s => s !== shortcut); save(); }, s => s.url);
}
function renderList(id, items, remove, describe, disableRemove = false) {
  $(id).replaceChildren(...items.map(item => {
    const row = document.createElement('div'); row.className = 'list-item';
    const label = document.createElement('span'); label.textContent = item.name;
    const detail = document.createElement('small'); detail.textContent = describe(item); label.append(detail);
    const button = document.createElement('button'); button.textContent = 'Remove'; button.disabled = disableRemove; button.onclick = () => remove(item);
    row.append(label, button); return row;
  }));
}
function panel(name) {
  for (const el of document.querySelectorAll('.panel')) el.hidden = el.id !== `panel-${name}`;
  for (const el of document.querySelectorAll('[data-panel]')) el.classList.toggle('selected', el.dataset.panel === name);
  toast('');
  if (name === 'privacy') { void refreshPhishingStatus(); void refreshMalwareStatus(); void refreshDownloadProtectionStatus(); }
}
async function refreshDownloadProtectionStatus() {
  if (!$('download-protection-status')) return;
  if (buildInfo.malwareProtection?.downloadAntivirusIncluded !== true) {
    $('download-protection-state').textContent = 'Source build required';
    $('download-protection-status').textContent = 'This package does not include the native download-completion gate. Build the current Kumo source target to enable download antivirus.';
    return;
  }
  try {
    const status = await chrome.runtime.sendMessage({type: 'downloadProtection.status'});
    if (!status || status.error || status.id !== 'settings-status') throw new Error('Status unavailable.');
    $('download-protection-state').textContent = status.available ? 'Ready' : status.installed ? 'Definitions need attention' : 'Setup required';
    $('download-protection-status').textContent = status.available ? 'Local download scanning is ready. Normal downloads wait for a scan before completion and automatic opening.' : status.installed ? 'The scanner is installed, but its definitions are unavailable or outdated. Downloads will be blocked until scanning is ready. Run the definitions update command.' : 'Install the signed local scanner and download its definitions. Downloads will be blocked while scanning is unavailable.';
    if (status.installed) $('download-protection-status').textContent += status.automaticUpdates ? ' Automatic definition updates are configured for every eight hours.' : ' Automatic definition updates are off; run scanner setup to enable them.';
  } catch {
    $('download-protection-state').textContent = 'Unavailable';
    $('download-protection-status').textContent = 'Download protection status is unavailable. Relaunch Kumo and check again.';
  }
}
if ($('download-protection-refresh')) $('download-protection-refresh').onclick = refreshDownloadProtectionStatus;
for (const [id, name] of [['download-protection-setup', 'downloadScannerSetupCommand'], ['download-protection-update', 'downloadScannerUpdateCommand']]) {
  if (!$(id)) continue;
  $(id).onclick = async () => {
    const command = buildInfo[name];
    if (!command) { toast('Package Kumo to include the scanner setup tools.'); return; }
    try { await navigator.clipboard.writeText(command); toast('Command copied. Run it in Terminal; the official installer may ask for administrator approval.'); }
    catch { toast(command); }
  };
}
async function refreshMalwareStatus() {
  const description = $('malware-status');
  if (!description) return;
  try {
    const status = await chrome.runtime.sendMessage({type: 'malware.status'});
    if (!status || status.ok !== true) throw new Error('Protection status is unavailable.');
    $('malware-state').textContent = !status.available ? 'Unavailable' : !status.enabled ? 'Off' : status.stale ? 'List outdated' : 'On';
    const date = status.modifiedAt && Number.isFinite(Date.parse(status.modifiedAt)) ? new Date(status.modifiedAt).toLocaleString() : 'unavailable';
    description.textContent = !status.available ? 'The malware list could not be loaded. Sites are not protected by this layer.' : !status.enabled ? 'Known-malware-domain blocking is off.' : `${Number(status.domainCount || 0).toLocaleString()} listed domains and their subdomains are blocked before connections. List updated ${date}.${status.stale ? ' The list is outdated; existing rules remain active. Update it now.' : ''}`;
    if (status.lastError) description.textContent += ' The last list update failed. Existing rules are retained; try updating again.';
    $('malware-enable').disabled = !status.available || status.enabled;
    $('malware-disable').disabled = !status.enabled;
    $('malware-update').disabled = !status.available || !status.enabled;
  } catch {
    $('malware-state').textContent = 'Unavailable';
    description.textContent = 'Protection status is unavailable. Relaunch Kumo and check again.';
  }
}
for (const [id, action] of [['malware-enable', 'enable'], ['malware-disable', 'disable'], ['malware-update', 'update']]) {
  if (!$(id)) continue;
  $(id).onclick = async () => {
    $(id).disabled = true;
    try {
      const result = await chrome.runtime.sendMessage({type: `malware.${action}`});
      if (result.error) throw new Error(result.error);
      toast(action === 'update' ? 'Malware list checked.' : action === 'enable' ? 'Known-malware-domain blocking enabled.' : 'Known-malware-domain blocking turned off.');
    } catch (error) { toast(error.message); }
    finally { await refreshMalwareStatus(); }
  };
}
async function refreshPhishingStatus() {
  let status;
  try { status = await chrome.runtime.sendMessage({type: 'phishing.status'}); } catch {}
  const description = document.getElementById('phishingStatus');
  if (!description) return;
  const state = phishingControlState(buildInfo, status);
  description.textContent = state.description;
  document.getElementById('enablePhishing').disabled = state.enableDisabled;
  document.getElementById('disablePhishing').disabled = state.disableDisabled;
  for (const details of document.querySelectorAll('[data-phishing-details]')) details.hidden = !state.included;
}
function showSettings(name = 'appearance') { panel(name); if (!$('settingsDialog').open) $('settingsDialog').showModal(); }
function nativePage(url) { return chrome.tabs.create({url}); }
function downloadJSON(data, name) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'}); const href = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = href; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(href), 30000);
}
$('searchForm').onsubmit = event => { event.preventDefault(); try { const url = searchURL($('search').value, settings); if (url) location.href = url; } catch (error) { $('search').setCustomValidity(error.message); $('search').reportValidity(); } };
$('search').oninput = () => $('search').setCustomValidity('');
for (const id of ['searchEngine', 'defaultEngine']) $(id).onchange = event => { settings.engine = event.target.value; save(); };
for (const id of ['openSettings', 'customize', 'themesCard']) $(id).onclick = () => showSettings();
for (const button of document.querySelectorAll('[data-panel]')) button.onclick = () => panel(button.dataset.panel);
for (const button of document.querySelectorAll('[data-close]')) button.onclick = () => $(button.dataset.close).close();
for (const button of document.querySelectorAll('[data-native]')) button.onclick = () => nativePage(button.dataset.native);
for (const button of document.querySelectorAll('[data-app-releases]')) button.onclick = () => nativePage('https://github.com/morrigangirl/kumo/releases');
for (const button of document.querySelectorAll('[data-app-check-updates]')) button.onclick = async () => {
  const command = 'open -n -b app.kumo.browser --args --kumo-check-for-updates';
  try { await navigator.clipboard.writeText(command); toast('Command copied. Run it in Terminal to open Kumo’s native updater.'); }
  catch { toast(command); }
};
$('nativeSearch').onclick = () => nativePage('chrome://settings/searchEngines');
if (document.getElementById('enablePhishing')) {
  document.getElementById('enablePhishing').onclick = async () => {
    try {
      if (buildInfo.phishingProtection?.included !== true) throw new Error('The experimental phishing model is not included in this build.');
      // Request from the actual gesture, before an await. These website permissions
      // enable analysis; they do not create any agent tab grants.
      const permission = chrome.permissions.request({origins: ['http://*/*', 'https://*/*']});
      if (!await permission) throw new Error('Website access was not granted.');
      const result = await chrome.runtime.sendMessage({type: 'phishing.enable'});
      if (result.error) throw new Error(result.error);
      await refreshPhishingStatus(); toast('Local phishing warnings enabled.');
    } catch (error) { toast(error.message); }
  };
  document.getElementById('disablePhishing').onclick = async () => {
    const result = await chrome.runtime.sendMessage({type: 'phishing.disable'});
    if (result.error) { toast(result.error); return; }
    await refreshPhishingStatus(); toast('Local phishing warnings turned off.');
  };
}
$('browseThemes').onclick = () => nativePage('https://chromewebstore.google.com/category/themes');
$('accent').oninput = () => { settings.accent = $('accent').value; document.documentElement.style.setProperty('--accent', settings.accent); };
$('accent').onchange = save;
$('greetingInput').onchange = () => { settings.greeting = $('greetingInput').value; save(); };
$('wallpaper').onchange = async event => {
  const file = event.target.files[0]; if (!file) return;
  if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type) || file.size > 2000000) { toast('Choose PNG, JPEG, or WebP under 2 MB.'); return; }
  const reader = new FileReader(); reader.onload = async () => { settings.background = reader.result; await save(); toast('Background saved on this Mac.'); }; reader.readAsDataURL(file);
};
$('clearWallpaper').onclick = () => { settings.background = ''; save(); };
$('exportSettings').onclick = () => downloadJSON(settings, 'kumo-preferences.json');
$('exportTheme').onclick = () => { downloadJSON(chromeTheme(settings), 'manifest.json'); toast('Save manifest.json in its own folder, then load the folder at chrome://extensions.'); };
$('importSettings').onchange = async event => {
  try { const file = event.target.files[0]; if (!file || file.size > 5000000) throw new Error('Choose a preferences JSON file under 5 MB.'); settings = validateSettings(JSON.parse(await file.text())); await save(); toast('Preferences imported.'); } catch (error) { toast(error.message); }
};
$('engineForm').onsubmit = async event => {
  event.preventDefault(); try { if (settings.engines.length >= 50) throw new Error('You can keep up to 50 search engines.'); const engine = validateEngine({name: $('engineName').value, url: $('engineURL').value}); settings.engines.push(engine); settings.engine = engine.id; await save(); event.target.reset(); toast('Search engine added.'); } catch (error) { toast(error.message); }
};
$('shortcutForm').onsubmit = async event => {
  event.preventDefault(); try { if (settings.shortcuts.length >= 12) throw new Error('You can keep up to 12 shortcuts.'); settings.shortcuts.push({name: $('shortcutName').value.trim(), url: webURL($('shortcutURL').value).href}); await save(); event.target.reset(); } catch (error) { toast(error.message); }
};
async function agentStatus() {
  const state = await chrome.runtime.sendMessage({type: 'agent.status'});
  $('agentDot').classList.toggle('on', !!state.enabled); $('agentLabel').textContent = state.enabled ? `${state.grants.length} tabs` : 'off';
  $('bridgeStatus').textContent = state.bridgeError ? `Bridge unavailable: ${state.bridgeError}` : state.enabled ? `Agent access enabled for ${state.grants.length} tab${state.grants.length === 1 ? '' : 's'}.` : 'Agent access is off.';
  return state;
}
async function showAgents() {
  const state = await agentStatus(); $('allowNewTabs').checked = !!state.allowNewTabs;
  const tabs = (await chrome.tabs.query({})).filter(t => !t.incognito && /^https?:\/\//.test(t.url || ''));
  $('tabChoices').replaceChildren(...tabs.map(tab => {
    const label = document.createElement('label'); label.className = 'checkbox tab-choice';
    const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.value = tab.id; checkbox.dataset.origin = new URL(tab.url).origin;
    checkbox.checked = state.grants.some(g => g.tabId === tab.id && g.origin === checkbox.dataset.origin);
    const text = document.createElement('span'); text.textContent = tab.title || tab.url;
    const origin = document.createElement('small'); origin.textContent = new URL(tab.url).origin; text.append(origin); label.append(checkbox, text); return label;
  }));
  if (!tabs.length) $('tabChoices').textContent = 'Open a website in another tab, then return here to grant access.';
  if (!$('agentsDialog').open) $('agentsDialog').showModal();
}
$('openAgents').onclick = showAgents;
$('grantAgents').onclick = async () => {
  try {
    const selected = [...document.querySelectorAll('#tabChoices input:checked')];
    const allowNewTabs = $('allowNewTabs').checked;
    const grants = selected.map(c => ({tabId: Number(c.value), origin: c.dataset.origin}));
    const origins = allowNewTabs ? ['http://*/*', 'https://*/*'] : [...new Set(grants.map(grant => `${grant.origin}/*`))];
    // permissions.request is made directly from this user gesture, before any awaits.
    const permission = origins.length ? chrome.permissions.request({origins}) : Promise.resolve(true);
    if (!await permission) throw new Error('Website access was not granted.');
    const result = await chrome.runtime.sendMessage({type: 'agent.configure', grants, allowNewTabs});
    if (result.error) { await showAgents(); throw new Error(result.error); }
    await agentStatus(); toast('Access enabled. Use your connected Codex or Claude client.', 'agentToast');
  } catch (error) { toast(error.message, 'agentToast'); }
};
$('revokeAgents').onclick = async () => { await chrome.runtime.sendMessage({type: 'agent.disable'}); await agentStatus(); toast('All agent access revoked.', 'agentToast'); };
for (const [id, provider] of [['copyCodex', 'codex'], ['copyClaude', 'claude']]) $(id).onclick = async () => {
  const command = buildInfo[`${provider}SetupCommand`];
  if (!command) { toast('Build Kumo.app to generate the local client setup commands.', 'agentToast'); return; }
  try { await navigator.clipboard.writeText(command); toast(`Setup command copied. Run it in Terminal to configure ${provider === 'codex' ? 'Codex Desktop' : 'Claude Desktop'}.`, 'agentToast'); } catch { toast(command, 'agentToast'); }
};
chrome.storage.onChanged.addListener((changes, area) => { if (area === 'session' && (changes.agentAccess || changes.bridgeError)) agentStatus(); if (area === 'local' && changes.preferences) { settings = validateSettings(changes.preferences.newValue); render(); } });
render(); await agentStatus();
if (location.hash === '#settings') showSettings();
if (location.hash === '#agents') showAgents();
