// Kumo's bounded, local-only PhishLang representation. Runs in an isolated world.
// Deliberately omits field values, editable content, script bodies and handlers.
(() => {
  'use strict';
  const installed = Symbol.for('app.kumo.phishing-content.v1');
  if (globalThis[installed] || window.top !== window) return;
  const pageURL = new URL(location.href);
  if (!['http:', 'https:'].includes(pageURL.protocol) ||
      pageURL.hostname === 'chromewebstore.google.com' ||
      pageURL.hostname === 'chrome.google.com' && /^\/webstore(?:\/|$)/.test(pageURL.pathname)) return;
  Object.defineProperty(globalThis, installed, {value: true, configurable: true});

  const MAX_BYTES = 24 * 1024, MAX_NODES = 12000, MAX_TEXT_NODES = 8000;
  const MAX_PRIORITY = 96, MAX_OTHER = 160, MAX_SCANS = 8, MIN_INTERVAL = 2000;
  const encoder = new TextEncoder();
  const structural = new Set(['title', 'form', 'input']);
  const selected = new Set(['h1', 'h2', 'h3', 'p', 'a', 'ul', 'ol', 'li', 'title', 'footer', 'form', 'script', 'input', 'button', 'iframe', 'meta', 'map', 'area']);
  const privateTags = new Set(['textarea', 'select', 'option', 'style', 'noscript', 'template']);
  const inputTypes = new Set(['button', 'checkbox', 'color', 'date', 'datetime-local', 'email', 'file', 'hidden', 'image', 'month', 'number', 'password', 'radio', 'range', 'reset', 'search', 'submit', 'tel', 'text', 'time', 'url', 'week']);
  const publicPaths = new Set(['login', 'signin', 'sign-in', 'sign-up', 'signup', 'account', 'auth', 'authentication', 'oauth', 'authorize', 'verify', 'verification', 'password', 'reset', 'forgot-password', 'checkout', 'pay', 'payment', 'security', 'help', 'support', 'about', 'contact', 'privacy', 'terms', 'home', 'index', 'index.html']);
  let active = true, retired = false, scans = 0, revision = 0, retryRequested = false;
  let lastSent = -Infinity, lastPayload = '', observedURL = location.href;
  let timer = null, poll = null;

  const tag = element => String(element.localName || '').toLowerCase();
  const attribute = (element, name) => element.getAttribute(name);
  const editable = element => element.isContentEditable ||
    attribute(element, 'contenteditable') !== null && String(attribute(element, 'contenteditable')).toLowerCase() !== 'false';
  const hidden = element => element.hidden || attribute(element, 'aria-hidden') === 'true';
  function visible(element) {
    if (tag(element) === 'title' || tag(element) === 'meta' || tag(element) === 'script') return true;
    if (typeof element.checkVisibility === 'function') return element.checkVisibility({checkOpacity: true, checkVisibilityCSS: true});
    const style = getComputedStyle(element);
    return style.display !== 'none' && style.visibility !== 'hidden' && style.visibility !== 'collapse' && style.opacity !== '0';
  }

  function sanitizedURL(value) {
    if (!value || value.length > 2048) return '<REDACTED_URL>';
    try {
      const url = new URL(value, location.href);
      if (!['http:', 'https:'].includes(url.protocol)) return '<NON_WEB_URL>';
      // URL credentials, query strings and fragments never enter the model.
      const path = url.pathname.split('/').slice(0, 9).map(part => {
        let decoded;
        try { decoded = decodeURIComponent(part); } catch { return '<REDACTED>'; }
        return !decoded || publicPaths.has(decoded.toLowerCase()) ? decoded.toLowerCase() : '<REDACTED>';
      }).join('/');
      return `${url.origin}${path}`.slice(0, 256);
    } catch { return '<INVALID_URL>'; }
  }

  function publicText(value, reasons) {
    if (value.length > 1024) reasons.add('element-text-limit');
    return value.slice(0, 1024).normalize('NFKC')
      .replace(/https?:\/\/[^\s<>"']+/gi, value => sanitizedURL(value))
      .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '<REDACTED_EMAIL>')
      .replace(/\b(?:bearer\s+)?[a-z0-9_+\/=.-]{24,}\b/gi, '<REDACTED_TOKEN>')
      .replace(/\b(?:token|code|secret|password|session|authorization)\s*[:=]\s*[^\s,;]+/gi, '<REDACTED_SECRET>')
      .replace(/\p{N}[\p{N}\s().-]{2,}\p{N}/gu, '<REDACTED_NUMBER>')
      .replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase().slice(0, 256);
  }

  function representation() {
    const reasons = new Set(), priority = [], other = [];
    let textVisited = 0;
    // A cursor traversal bounds work without materializing a huge child list.
    function walk(root, budget, callback) {
      let node = root, count = 0;
      while (node && count < budget) {
        count++;
        const descend = callback(node) !== false;
        if (descend && node.firstChild) { node = node.firstChild; continue; }
        while (node && node !== root && !node.nextSibling) node = node.parentNode;
        if (!node || node === root) { node = null; break; }
        node = node.nextSibling;
      }
      return {count, exhausted: Boolean(node)};
    }
    const discovery = walk(document.documentElement, MAX_NODES, node => {
      if (node.nodeType !== 1) return true;
      const name = tag(node);
      if (privateTags.has(name) || editable(node) || hidden(node)) return false;
      // Closed component roots cannot be inspected; custom elements may hide one.
      if (node.shadowRoot || name.includes('-')) reasons.add('shadow-dom');
      if (name === 'iframe') reasons.add('embedded-frame');
      if (selected.has(name)) {
        const bucket = structural.has(name) ? priority : other;
        const maximum = structural.has(name) ? MAX_PRIORITY : MAX_OTHER;
        if (bucket.length < maximum) bucket.push(node);
        else reasons.add('element-limit');
      }
      return name !== 'script';
    });
    if (discovery.exhausted) reasons.add('node-limit');

    function textOf(element) {
      // Even a paragraph nested inside a form must not disclose form content.
      let ancestor = element;
      for (let depth = 0; ancestor && ancestor.nodeType === 1; depth++, ancestor = ancestor.parentNode) {
        if (depth >= 64) { reasons.add('ancestor-limit'); return ''; }
        if (tag(ancestor) === 'form' || privateTags.has(tag(ancestor)) || editable(ancestor) || hidden(ancestor)) return '';
      }
      let text = '';
      const result = walk(element, Math.max(0, MAX_TEXT_NODES - textVisited), node => {
        if (text.length >= 1024) return false;
        if (node.nodeType === 1) {
          const name = tag(node);
          if (name === 'form' || name === 'script' || name === 'input' || privateTags.has(name) || editable(node) || hidden(node)) return false;
          if (!visible(node)) return false;
        } else if (node.nodeType === 3) text += ` ${String(node.nodeValue || '').slice(0, 1024 - text.length)}`;
        return true;
      });
      textVisited += result.count;
      if (result.exhausted) reasons.add('text-node-limit');
      if (text.length >= 1024) reasons.add('element-text-limit');
      return publicText(text, reasons);
    }

    let text = '', bytes = 0, hasFeatures = false;
    for (const element of [...priority, ...other]) {
      const name = tag(element);
      if (!visible(element)) continue;
      let label = name.toUpperCase(), fields;
      if (name === 'form') fields = {name: 'Form'};
      else if (name === 'input') {
        const candidate = String(attribute(element, 'type') || 'text').toLowerCase();
        const type = inputTypes.has(candidate) ? candidate : 'text';
        label = type === 'checkbox' ? 'CHECKBOX' : 'INPUT';
        fields = type === 'checkbox' ? {label: '<EMPTY>', input: {type: 'checkbox', name: '', text: ''}} : {type, name: '', placeholder: ''};
      } else if (name === 'script') fields = {content: '<EMPTY>'};
      else if (name === 'a') { label = 'LINK'; fields = {text: `${textOf(element) || '<EMPTY>'} link`, href: sanitizedURL(attribute(element, 'href'))}; }
      else if (name === 'button') fields = {text: `${textOf(element) || '<EMPTY>'} button`};
      else if (name === 'footer') { label = 'FOOTER_LINKS'; fields = []; }
      else fields = {text: textOf(element) || '<EMPTY>'};
      const entry = `${text ? ' ' : ''}${label}: ${JSON.stringify(fields)}`;
      const length = encoder.encode(entry).length;
      if (bytes + length > MAX_BYTES) { reasons.add('output-limit'); break; }
      text += entry; bytes += length;
      if (name === 'input' || name === 'form' || name === 'a' && /^https?:/.test(fields.href) ||
          name !== 'script' && typeof fields.text === 'string' && !fields.text.startsWith('<EMPTY>')) hasFeatures = true;
    }
    if (!hasFeatures) reasons.add('no-readable-features');
    if (scans + 1 >= MAX_SCANS) reasons.add('scan-limit');
    return {text, coverageLimited: reasons.size !== 0, coverageReasons: [...reasons].sort()};
  }

  function scan() {
    timer = null;
    if (!active || scans >= MAX_SCANS || document.visibilityState === 'hidden') return;
    const url = location.href;
    const result = url.length > 8192 ? {text: '', coverageLimited: true, coverageReasons: ['document-url-limit']} : representation();
    const payload = JSON.stringify({url, revision, ...result});
    if (payload === lastPayload && !retryRequested) return;
    retryRequested = false;
    lastPayload = payload; lastSent = Date.now();
    const scanNumber = ++scans;
    // The worker binds the result to this document. It never forwards url to the model.
    function response(value) {
      if (value?.status === 'off' || value?.status === 'disabled') { stop(); return; }
      if (value && Object.hasOwn(value, 'error') || ['busy', 'limited', 'unavailable', 'error'].includes(value?.status)) {
        retryRequested = true;
        schedule(MIN_INTERVAL);
      }
      if (scanNumber === MAX_SCANS) stop();
    }
    try {
      Promise.resolve(chrome.runtime.sendMessage({type: 'phishing.scan', url, revision, ...result})).then(response)
        .catch(() => response({status: 'error'}));
    } catch { response({status: 'error'}); /* Extension disabled or unavailable. */ }
  }

  function schedule(delay = 300) {
    if (!active || retired || scans >= MAX_SCANS || timer !== null) return;
    timer = setTimeout(scan, Math.max(delay, MIN_INTERVAL - (Date.now() - lastSent)));
  }
  const observer = new MutationObserver(() => { revision++; schedule(); });
  const messageListener = (message, sender, reply) => {
    if (!['phishing.confirm', 'phishing.stop'].includes(message?.type) || sender.id !== chrome.runtime.id || sender.tab ||
        sender.url !== chrome.runtime.getURL('background.js')) return;
    if (message.type === 'phishing.stop') {
      retired = true;
      stop();
      delete globalThis[installed];
      chrome.runtime.onMessage.removeListener(messageListener);
      for (const [name, listener] of Object.entries(eventListeners)) removeEventListener(name, listener);
      reply({stopped: true});
      return;
    }
    // Only the trusted worker can bind its pending result to this live document.
    reply({url: location.href, revision});
  };
  chrome.runtime.onMessage.addListener(messageListener);
  function checkURL() {
    if (location.href !== observedURL) { observedURL = location.href; revision++; schedule(0); }
  }
  function start() {
    if (retired) return;
    active = true;
    if (scans >= MAX_SCANS) return;
    observer.observe(document.documentElement, {subtree: true, childList: true, characterData: true, attributes: true,
      attributeFilter: ['type', 'hidden', 'aria-hidden', 'style', 'href', 'contenteditable', 'autocomplete']});
    if (poll === null) poll = setInterval(() => {
      if (document.visibilityState !== 'hidden') checkURL();
    }, MIN_INTERVAL);
    schedule(0);
  }
  function stop() {
    active = false;
    if (timer !== null) clearTimeout(timer);
    if (poll !== null) clearInterval(poll);
    timer = null; poll = null;
    observer.disconnect();
  }
  const eventListeners = {
    popstate: checkURL,
    hashchange: checkURL,
    visibilitychange: () => { if (document.visibilityState !== 'hidden') { checkURL(); schedule(0); } },
    pagehide: stop,
    pageshow: event => { if (event.persisted) start(); },
  };
  for (const [name, listener] of Object.entries(eventListeners)) addEventListener(name, listener);
  start();
})();
