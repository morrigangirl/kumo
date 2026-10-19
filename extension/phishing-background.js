// Local-only phishing analysis. Agent grants are a separate authorization system.
const HOST = 'com.kumo.phishing';
const KEY = 'phishingProtection';
const WARNINGS = 'phishingWarnings';
const SCRIPT = 'kumo-local-phishing';
const ORIGINS = ['http://*/*', 'https://*/*'];
const WARNING_THRESHOLD = 0.9;
const MAX_TEXT_BYTES = 24576;
const encoder = new TextEncoder();

function website(value) {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || value.length > 8192) return null;
    if (url.hostname === 'chromewebstore.google.com' || url.hostname === 'chrome.google.com' && url.pathname.startsWith('/webstore')) return null;
    return url;
  } catch { return null; }
}

export function createPhishingProtection(api, {timeoutMs = 10000, now = Date.now, randomId = () => crypto.randomUUID(),
  readBuildInfo = async () => {
    const response = await fetch(api.runtime.getURL('build-info.json'));
    if (!response.ok) throw new Error('Packaged feature information is unavailable.');
    return response.json();
  }} = {}) {
  let included = false, enabled = false, epoch = 0, port = null, modelVersion = null, health = 'off';
  let mutations = Promise.resolve();
  let warningMutations = Promise.resolve();
  const pending = new Map(), activeTabs = new Set(), generations = new Map(), results = new Map(), bypasses = new Map(), scanBudgets = new Map();
  const checkEpoch = expected => { if (expected !== epoch) throw new Error('Phishing settings changed.'); };
  const internal = sender => {
    try { const url = new URL(sender.url); return sender.id === api.runtime.id && url.protocol === 'chrome-extension:' && url.host === api.runtime.id && url.pathname === '/newtab.html'; }
    catch { return false; }
  };
  const warningURL = token => api.runtime.getURL(`phishing-warning.html#${token}`);
  function mutateWarnings(transform, expected) {
    const mutation = warningMutations.then(async () => {
      checkEpoch(expected);
      const stored = (await api.storage.session.get(WARNINGS))[WARNINGS] || {};
      checkEpoch(expected);
      const result = transform(stored);
      await api.storage.session.set({[WARNINGS]: result}); checkEpoch(expected);
      return result;
    });
    warningMutations = mutation.catch(() => {});
    return mutation;
  }

  function disconnect() {
    const old = port; port = null;
    for (const {reject, timer} of pending.values()) { clearTimeout(timer); reject(new Error('Local phishing model is unavailable.')); }
    pending.clear();
    try { old?.disconnect(); } catch {}
  }
  function connect() {
    if (port) return port;
    const source = api.runtime.connectNative(HOST); port = source;
    source.onMessage.addListener(message => {
      if (source !== port) return;
      if (!message || typeof message.id !== 'string' || !pending.has(message.id)) return;
      const request = pending.get(message.id); pending.delete(message.id); clearTimeout(request.timer);
      if (message.ok !== true) request.reject(new Error('Local phishing model could not analyze this page.'));
      else request.resolve(message);
    });
    source.onDisconnect.addListener(() => {
      if (source !== port) return;
      health = enabled ? 'unavailable' : 'off'; disconnect();
    });
    return source;
  }
  function nativeRequest(type, text) {
    if (pending.size >= 4) return Promise.reject(new Error('Local phishing analysis is busy.'));
    return new Promise((resolve, reject) => {
      const id = randomId();
      const timer = setTimeout(() => { health = enabled ? 'unavailable' : 'off'; disconnect(); }, timeoutMs);
      timer.unref?.();
      pending.set(id, {resolve, reject, timer});
      try { connect().postMessage(type === 'classify' ? {id, type, text} : {id, type}); }
      catch { disconnect(); reject(new Error('Local phishing model is unavailable. Relaunch Kumo after rebuilding.')); }
    });
  }
  async function unregister() {
    if (!api.scripting.unregisterContentScripts) return;
    const scripts = await api.scripting.getRegisteredContentScripts({ids: [SCRIPT]});
    if (scripts.length) await api.scripting.unregisterContentScripts({ids: [SCRIPT]});
  }
  async function register() {
    if (!api.scripting.registerContentScripts) throw new Error('This browser cannot register phishing protection.');
    const scripts = await api.scripting.getRegisteredContentScripts({ids: [SCRIPT]});
    if (!scripts.length) await api.scripting.registerContentScripts([{
      id: SCRIPT, matches: ORIGINS, excludeMatches: ['*://chromewebstore.google.com/*', '*://chrome.google.com/webstore*'],
      js: ['phishing-content.js'], runAt: 'document_idle', allFrames: false, persistAcrossSessions: true,
    }]);
  }
  function clearSession() {
    results.clear(); bypasses.clear(); scanBudgets.clear(); generations.clear();
  }
  async function stopOpenTabs() {
    if (!api.tabs.query) return;
    const tabs = await api.tabs.query({});
    const eligible = tabs.filter(tab => !tab.incognito && website(tab.url));
    for (let index = 0; index < eligible.length; index += 64) {
      await Promise.allSettled(eligible.slice(index, index + 64)
        .map(tab => api.tabs.sendMessage(tab.id, {type: 'phishing.stop'}, {frameId: 0})));
    }
  }
  async function scanOpenTabs(expected) {
    const tabs = await api.tabs.query({}); checkEpoch(expected);
    for (const tab of tabs.filter(tab => !tab.incognito && !tab.pendingUrl && website(tab.url)).slice(0, 64)) {
      checkEpoch(expected);
      await api.scripting.executeScript({target: {tabId: tab.id}, files: ['phishing-content.js']}).catch(() => {});
    }
  }
  async function initialize() {
    const started = epoch;
    let feature;
    try { feature = (await readBuildInfo())?.phishingProtection; } catch {}
    if (started !== epoch) return;
    included = feature?.included === true;
    if (!included) {
      // Retire scripts and preferences from a model-inclusive installation. An
      // omitted checkpoint must never trigger missing-host retries or page scans.
      health = feature?.included === false ? 'not-included' : 'unavailable';
      await api.storage.local.set({[KEY]: {enabled: false}});
      await unregister();
      await stopOpenTabs();
      await api.storage.session.set({[WARNINGS]: {}});
      return;
    }
    const stored = (await api.storage.local.get(KEY))[KEY];
    if (started !== epoch) return;
    if (stored?.enabled !== true) { await unregister(); return; }
    if (!await api.permissions.contains({origins: ORIGINS})) {
      await api.storage.local.set({[KEY]: {enabled: false}}); await unregister(); return;
    }
    checkEpoch(started);
    enabled = true; health = 'starting';
    await register(); checkEpoch(started);
    try {
      const status = await nativeRequest('status'); checkEpoch(started);
      if (status.available !== true || typeof status.modelVersion !== 'string') throw new Error('Unavailable model');
      modelVersion = status.modelVersion; health = 'ready';
    } catch { if (started === epoch) health = 'unavailable'; }
  }
  const ready = initialize().catch(() => { enabled = false; health = 'unavailable'; });
  mutations = ready;

  function setEnabled(value) {
    if (value && !included) return Promise.reject(new Error('The experimental phishing model is not included in this build.'));
    const expected = ++epoch;
    enabled = false; health = included ? 'off' : health; disconnect(); clearSession();
    const mutation = mutations.then(async () => {
      checkEpoch(expected);
      await api.storage.local.set({[KEY]: {enabled: false}});
      await stopOpenTabs(); checkEpoch(expected);
      await unregister(); checkEpoch(expected);
      await mutateWarnings(() => ({}), expected); checkEpoch(expected);
      if (!value) return {ok: true, enabled: false};
      if (!await api.permissions.contains({origins: ORIGINS})) throw new Error('Allow website access to enable local phishing warnings.');
      checkEpoch(expected);
      const status = await nativeRequest('status'); checkEpoch(expected);
      if (status.available !== true || typeof status.modelVersion !== 'string') throw new Error('Local phishing model is unavailable. Relaunch Kumo after rebuilding.');
      modelVersion = status.modelVersion;
      if (!await api.permissions.contains({origins: ORIGINS})) throw new Error('Website access was revoked.');
      checkEpoch(expected);
      await register(); checkEpoch(expected);
      await api.storage.local.set({[KEY]: {enabled: true}}); checkEpoch(expected);
      enabled = true; health = 'ready';
      void scanOpenTabs(expected).catch(() => {});
      return {ok: true, enabled: true};
    }).catch(async error => {
      if (expected === epoch) { enabled = false; health = 'unavailable'; disconnect(); await unregister().catch(() => {}); }
      throw error;
    });
    mutations = mutation.catch(() => {});
    return mutation;
  }
  async function currentDocument(tabId, documentId, value) {
    const tab = await api.tabs.get(tabId);
    if (tab.id !== tabId || tab.incognito || tab.pendingUrl || tab.url !== value) return false;
    const frame = await api.webNavigation.getFrame({tabId, frameId: 0});
    return frame?.documentId === documentId && !frame.errorOccurred && frame.url === value;
  }
  function trim(map, maximum = 128) { while (map.size > maximum) map.delete(map.keys().next().value); }
  async function scan(message, sender) {
    const expected = epoch, tabId = sender.tab?.id, url = website(message.url);
    if (!enabled) return {ok: true, status: 'off'};
    if (!url || sender.id !== api.runtime.id || sender.frameId !== 0 || sender.tab?.incognito ||
        sender.documentLifecycle !== 'active' || typeof sender.documentId !== 'string' || !sender.documentId ||
        !Number.isSafeInteger(tabId) || tabId < 0 || website(sender.url)?.origin !== url.origin ||
        !Number.isSafeInteger(message.revision) || message.revision < 0 ||
        typeof message.text !== 'string' || encoder.encode(message.text).length > MAX_TEXT_BYTES) throw new Error('Unsupported phishing scan.');
    if (!await api.permissions.contains({origins: [`${url.origin}/*`]})) throw new Error('Website access was revoked.');
    checkEpoch(expected);
    if (!await currentDocument(tabId, sender.documentId, message.url)) return {ok: true, status: 'stale'};
    checkEpoch(expected);
    const bypass = bypasses.get(tabId);
    if (bypass && bypass.expires > now() && bypass.url === message.url && (!bypass.documentId || bypass.documentId === sender.documentId)) {
      bypass.documentId = sender.documentId;
      return {ok: true, status: 'bypassed'};
    }
    bypasses.delete(tabId);
    if (!message.text.trim()) { results.set(tabId, {status: 'partial', coverageLimited: true}); trim(results); return {ok: true, status: 'partial'}; }
    if (activeTabs.has(tabId) || pending.size >= 4) { results.set(tabId, {status: 'partial', coverageLimited: true}); trim(results); return {ok: true, status: 'busy'}; }
    const budgetKey = `${tabId}:${sender.documentId}`;
    const budget = scanBudgets.get(budgetKey) || {count: 0, last: -Infinity};
    if (budget.count >= 8 || now() - budget.last < 1500) { results.set(tabId, {status: 'partial', coverageLimited: true}); trim(results); return {ok: true, status: 'limited'}; }
    budget.count++; budget.last = now(); scanBudgets.set(budgetKey, budget); trim(scanBudgets);
    const generation = generations.get(tabId) || 0; activeTabs.add(tabId);
    try {
      const result = await nativeRequest('classify', message.text); checkEpoch(expected);
      if (generations.get(tabId) !== undefined && generations.get(tabId) !== generation ||
          !await currentDocument(tabId, sender.documentId, message.url)) return {ok: true, status: 'stale'};
      checkEpoch(expected);
      if (!Number.isFinite(result.probability) || result.probability < 0 || result.probability > 1 ||
          !Number.isInteger(result.windows) || result.windows < 1 || result.windows > 8 ||
          !Number.isSafeInteger(result.tokenCount) || result.tokenCount < 0) throw new Error('Invalid model result.');
      const coverageLimited = message.coverageLimited === true || result.coverageLimited === true || result.truncated === true;
      const suspicious = result.probability >= WARNING_THRESHOLD;
      health = 'ready'; results.set(tabId, {status: suspicious ? 'suspicious' : coverageLimited ? 'partial' : 'no-signal', coverageLimited}); trim(results);
      if (!suspicious) return {ok: true, status: coverageLimited ? 'partial' : 'no-signal'};
      const confirmed = await api.tabs.sendMessage(tabId, {type: 'phishing.confirm'}, {documentId: sender.documentId, frameId: 0});
      checkEpoch(expected);
      if (confirmed?.url !== message.url || confirmed.revision !== message.revision || !await currentDocument(tabId, sender.documentId, message.url)) return {ok: true, status: 'stale'};
      const token = randomId();
      await mutateWarnings(stored => {
        const entries = Object.entries(stored).filter(([, entry]) => entry.expires > now()).slice(-31);
        return {...Object.fromEntries(entries), [token]: {tabId, url: message.url, origin: url.origin, expires: now() + 600000, coverageLimited}};
      }, expected);
      // Revalidate after storing the ticket; a same-URL replacement has a new documentId.
      if (!await currentDocument(tabId, sender.documentId, message.url)) return {ok: true, status: 'stale'};
      const finalConfirmation = await api.tabs.sendMessage(tabId, {type: 'phishing.confirm'}, {documentId: sender.documentId, frameId: 0});
      if (finalConfirmation?.url !== message.url || finalConfirmation.revision !== message.revision ||
          !await currentDocument(tabId, sender.documentId, message.url)) return {ok: true, status: 'stale'};
      checkEpoch(expected);
      await api.tabs.update(tabId, {url: warningURL(token)});
      return {ok: true, status: 'warning'};
    } catch (error) {
      if (expected === epoch) { health = 'unavailable'; results.set(tabId, {status: 'unavailable', coverageLimited: true}); trim(results); }
      throw new Error('Local phishing analysis is unavailable for this page.');
    } finally { activeTabs.delete(tabId); }
  }
  async function warningAction(message, sender) {
    const expected = epoch;
    if (!Number.isSafeInteger(sender.tab?.id) || sender.frameId !== 0 || sender.url !== warningURL(message.token) ||
        typeof message.token !== 'string' || message.token.length > 80) throw new Error('Unsupported warning request.');
    const stored = (await api.storage.session.get(WARNINGS))[WARNINGS] || {};
    const entry = stored[message.token];
    if (!entry || entry.tabId !== sender.tab.id || entry.expires <= now() || !website(entry.url)) throw new Error('This warning expired. Return to a new tab.');
    const tab = await api.tabs.get(entry.tabId);
    if (tab.incognito || tab.pendingUrl || tab.url !== warningURL(message.token)) throw new Error('This warning is no longer current.');
    if (message.type === 'phishing.warning') return {ok: true, origin: entry.origin, coverageLimited: entry.coverageLimited};
    if (!enabled) throw new Error('This warning expired. Return to a new tab.');
    checkEpoch(expected);
    const target = message.type === 'phishing.continue' ? entry.url : api.runtime.getURL('newtab.html');
    await mutateWarnings(current => { delete current[message.token]; return current; }, expected);
    checkEpoch(expected);
    const latest = await api.tabs.get(entry.tabId);
    if (latest.incognito || latest.pendingUrl || latest.url !== warningURL(message.token)) throw new Error('This warning is no longer current.');
    checkEpoch(expected);
    if (message.type === 'phishing.continue') { bypasses.set(entry.tabId, {url: entry.url, expires: now() + 30000}); trim(bypasses); }
    await api.tabs.update(entry.tabId, {url: target});
    return {ok: true};
  }
  async function handleMessage(message, sender) {
    await ready;
    if (!message || sender.id !== api.runtime.id) throw new Error('Unsupported phishing request.');
    if (message.type === 'phishing.scan') return scan(message, sender);
    if (['phishing.warning', 'phishing.continue', 'phishing.leave'].includes(message.type)) return warningAction(message, sender);
    if (!internal(sender)) throw new Error('Open Kumo settings to change phishing protection.');
    if (message.type === 'phishing.enable') return setEnabled(true);
    if (message.type === 'phishing.disable') return setEnabled(false);
    if (message.type === 'phishing.status') return {ok: true, included, enabled, health, modelVersion, currentTab: results.get(message.tabId) || null};
    throw new Error('Unsupported phishing request.');
  }
  api.tabs.onUpdated.addListener((tabId, change) => {
    if (change.url || change.status === 'loading') {
      generations.set(tabId, (generations.get(tabId) || 0) + 1); trim(generations);
      results.delete(tabId);
      const bypass = bypasses.get(tabId);
      if (bypass && change.url && change.url !== bypass.url) bypasses.delete(tabId);
    }
  });
  api.tabs.onRemoved.addListener(tabId => { results.delete(tabId); bypasses.delete(tabId); generations.set(tabId, (generations.get(tabId) || 0) + 1); trim(generations); });
  api.permissions.onRemoved?.addListener(permissions => { if (permissions.origins?.length) void setEnabled(false).catch(() => {}); });
  return {ready, handleMessage, shutdown: disconnect};
}
