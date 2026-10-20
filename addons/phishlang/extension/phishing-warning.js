export function installWarning(api, document, location) {
  const token = location.hash.slice(1);
  const element = id => document.getElementById(id);
  const status = element('warningStatus'), proceed = element('continueSite'), leave = element('leaveSite');
  let actionStarted = false;
  proceed.disabled = true;
  const request = async type => {
    const result = await api.runtime.sendMessage({type, token});
    if (result?.error || result?.ok !== true) throw new Error('Expired warning');
    return result;
  };
  const expired = () => { status.textContent = 'This warning expired. Leave this site to continue browsing.'; proceed.disabled = true; };
  leave.onclick = async () => {
    if (actionStarted) return;
    actionStarted = true;
    leave.disabled = true; proceed.disabled = true;
    try { await request('phishing.leave'); }
    catch { location.replace('about:blank'); }
  };
  proceed.onclick = async () => {
    if (actionStarted || proceed.disabled) return;
    actionStarted = true;
    proceed.disabled = true;
    try { await request('phishing.continue'); }
    catch { actionStarted = false; expired(); }
  };
  const ready = request('phishing.warning').then(result => {
    if (typeof result.origin !== 'string') throw new Error('Expired warning');
    element('warningOrigin').textContent = result.origin;
    element('warningCoverage').textContent = result.coverageLimited
      ? 'Only part of the page could be analyzed. This warning is based on the available content.'
      : 'Analysis happened on this Mac. No page content was sent to an online AI service.';
    if (!actionStarted) proceed.disabled = false;
  }).catch(() => { element('warningOrigin').textContent = 'This warning expired.'; expired(); });
  return {ready};
}

if (typeof chrome !== 'undefined' && typeof document !== 'undefined') installWarning(chrome, document, location);
