// Browser-owned isolated-world sampler. No extension API, network, storage,
// credentials, field values or page-provided executable code cross this boundary.
(() => {
  'use strict';
  if (window.top !== window || !['http:', 'https:'].includes(location.protocol)) return null;
  const pageURL = new URL(location.href);
  if (pageURL.username || pageURL.password || pageURL.hostname === 'chromewebstore.google.com' ||
      pageURL.hostname === 'chrome.google.com' && pageURL.pathname.startsWith('/webstore')) return null;
  const key = Symbol.for('app.kumo.native-phishing-sampler.v1');
  let state = globalThis[key];
  if (!state) {
    state = {revision: 0, sampledRevision: -1, url: ''};
    state.observer = new MutationObserver(() => { state.revision++; });
    state.observer.observe(document, {subtree: true, childList: true, characterData: true, attributes: true});
    Object.defineProperty(globalThis, key, {value: state, configurable: true});
  }
  if (state.sampledRevision === state.revision && state.url === location.href)
    return {url: location.href, revision: state.revision, unchanged: true};
  state.sampledRevision = state.revision; state.url = location.href;
  const MAX_BYTES = 24 * 1024, MAX_NODES = 12000, MAX_TEXT_NODES = 8000;
  const MAX_PRIORITY = 96, MAX_OTHER = 160;
  const encoder = new TextEncoder();
  const structural = new Set(['title', 'form', 'input']);
  const selected = new Set(['h1', 'h2', 'h3', 'p', 'a', 'ul', 'ol', 'li', 'title', 'footer', 'form', 'script', 'input', 'button', 'iframe', 'meta', 'map', 'area']);
  const privateTags = new Set(['textarea', 'select', 'option', 'style', 'noscript', 'template']);
  const inputTypes = new Set(['button', 'checkbox', 'color', 'date', 'datetime-local', 'email', 'file', 'hidden', 'image', 'month', 'number', 'password', 'radio', 'range', 'reset', 'search', 'submit', 'tel', 'text', 'time', 'url', 'week']);
  const publicPaths = new Set(['login', 'signin', 'sign-in', 'sign-up', 'signup', 'account', 'auth', 'authentication', 'oauth', 'authorize', 'verify', 'verification', 'password', 'reset', 'forgot-password', 'checkout', 'pay', 'payment', 'security', 'help', 'support', 'about', 'contact', 'privacy', 'terms', 'home', 'index', 'index.html']);


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
    return {text, coverageLimited: reasons.size !== 0, coverageReasons: [...reasons].sort()};
  }

  return {url: location.href, revision: state.revision, ...representation()};
})();
