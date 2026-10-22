import {sendWithPromise} from 'chrome://resources/js/cr.js';
const state = document.getElementById('state');
document.getElementById('leave').onclick = () => chrome.send('leaveWarning');
document.getElementById('continue').onclick = () => chrome.send('continueWarning');
try {
  const result = await sendWithPromise('getWarning');
  if (result.ok !== true) throw new Error('This warning expired. Leave this site.');
  document.getElementById('origin').textContent = result.origin;
  document.getElementById('limited').hidden = !result.coverageLimited;
  document.getElementById('continue').disabled = false;
  state.textContent = 'Continue allows only the returned document. Reloading checks the page again.';
} catch {
  state.textContent = 'This warning expired. Leave this site.';
}
