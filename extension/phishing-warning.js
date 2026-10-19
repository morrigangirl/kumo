const token = location.hash.slice(1);
const status = document.getElementById('warningStatus');
const continueButton = document.getElementById('continueSite');
const request = type => chrome.runtime.sendMessage({type, token});
document.getElementById('leaveSite').onclick = () => { location.replace(chrome.runtime.getURL('newtab.html')); };
continueButton.onclick = async () => {
  continueButton.disabled = true;
  try {
    const result = await request('phishing.continue');
    if (result.error) throw new Error(result.error);
  } catch { status.textContent = 'This warning expired. Return to a new tab.'; }
};
try {
  const result = await request('phishing.warning');
  if (result.error || !result.origin) throw new Error('Expired');
  document.getElementById('warningOrigin').textContent = result.origin;
  document.getElementById('warningCoverage').textContent = result.coverageLimited ? 'Only part of the page could be analyzed. The warning is based on the available content.' : 'Analysis happened on this Mac. No page content was sent to an online AI service.';
  continueButton.disabled = false;
} catch {
  document.getElementById('warningOrigin').textContent = 'This warning expired.';
  status.textContent = 'Return to a new tab to continue browsing.';
}
