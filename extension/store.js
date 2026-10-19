(() => {
  if (globalThis.__kumoStoreHelperStarted) return;
  globalThis.__kumoStoreHelperStarted = true;
  let currentButton = null;
  let currentId = null;
  let scheduled = false;

  function detailId() {
    const url = new URL(location.href);
    if (url.origin !== 'https://chromewebstore.google.com' || url.username || url.password) return null;
    return url.pathname.match(/^\/detail\/(?:[^/]+\/)?([a-p]{32})\/?$/)?.[1] ?? null;
  }

  function refresh() {
    const id = detailId();
    if (id && currentId === id && currentButton?.isConnected) return;
    currentButton?.remove();
    currentButton = null;
    currentId = null;
    if (!id || !document.documentElement) return;

    const button = document.createElement('button');
    button.id = 'kumo-store-install';
    button.type = 'button';
    button.textContent = 'Install in Kumo';
    button.title = 'Download this signed extension from the Chrome Web Store. Review Chromium’s installation prompt.';
    Object.assign(button.style, {position: 'fixed', right: '24px', bottom: '24px', zIndex: '2147483647', background: '#1c2723', color: '#fff', padding: '16px 24px', border: '1px solid #fff3', borderRadius: '30px', boxShadow: '0 8px 28px #0003', font: '600 14px system-ui', cursor: 'pointer'});
    button.addEventListener('click', async event => {
      if (!event.isTrusted) return;
      if (detailId() !== id) { refresh(); return; }
      button.disabled = true;
      let message;
      try {
        const result = await chrome.runtime.sendMessage({type: 'store.install', extensionId: id});
        message = result?.error || 'Review the browser install prompt';
      } catch {
        message = 'Could not request installation. Try again.';
      }
      if (currentButton === button && detailId() === id) {
        button.textContent = message;
        button.disabled = false;
      }
    });
    currentId = id;
    currentButton = button;
    document.documentElement.append(button);
  }

  function schedule() {
    if (scheduled) return;
    scheduled = true;
    queueMicrotask(() => { scheduled = false; refresh(); });
  }
  chrome.runtime.onMessage.addListener((message, sender, reply) => {
    if (message?.type !== 'store.confirm' || sender.id !== chrome.runtime.id || sender.tab ||
        sender.url !== chrome.runtime.getURL('background.js')) return;
    // Public URL/ID only. This acknowledgement has no install or grant effect.
    reply({url: location.href, extensionId: detailId()});
  });
  // The Store uses same-document navigation. Observe its DOM and poll the URL
  // without modifying page-world History APIs or running page-world scripts.
  new MutationObserver(schedule).observe(document, {childList: true, subtree: true});
  for (const name of ['popstate', 'hashchange', 'pageshow']) addEventListener(name, schedule);
  setInterval(schedule, 1000);
  refresh();
})();
