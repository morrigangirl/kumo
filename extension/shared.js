export const DEFAULTS = Object.freeze({
  theme: 'paper', accent: '#c65b3c', background: '', greeting: 'A little room to explore.',
  engine: 'duckduckgo', engines: [
    {id: 'duckduckgo', name: 'DuckDuckGo', url: 'https://duckduckgo.com/?q={searchTerms}'},
    {id: 'kagi', name: 'Kagi', url: 'https://kagi.com/search?q={searchTerms}'},
    {id: 'brave', name: 'Brave Search', url: 'https://search.brave.com/search?q={searchTerms}'},
    {id: 'google', name: 'Google', url: 'https://www.google.com/search?q={searchTerms}'},
    {id: 'bing', name: 'Bing', url: 'https://www.bing.com/search?q={searchTerms}'}
  ],
  shortcuts: [
    {name: 'Apple', url: 'https://www.apple.com'},
    {name: 'Wikipedia', url: 'https://www.wikipedia.org'},
    {name: 'GitHub', url: 'https://github.com'},
    {name: 'YouTube', url: 'https://www.youtube.com'}
  ]
});
export const THEMES = ['paper', 'midnight', 'forest', 'lavender', 'sand', 'ocean'];
export function webURL(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('Use an HTTP or HTTPS address without embedded credentials.');
  return url;
}
export function validateEngine(engine) {
  if (!engine || typeof engine.name !== 'string' || !engine.name.trim() || engine.name.length > 60 || typeof engine.url !== 'string' || !engine.url.includes('{searchTerms}')) throw new Error('A search engine needs a name and URL containing {searchTerms}.');
  webURL(engine.url.replaceAll('{searchTerms}', 'test'));
  return {id: String(engine.id || crypto.randomUUID()).slice(0, 80), name: engine.name.trim(), url: engine.url};
}
export function searchURL(text, settings) {
  const query = text.trim();
  if (!query) return null;
  if (/^https?:\/\//i.test(query)) return webURL(query).href;
  if (!/\s/.test(query) && /^(localhost(?::\d+)?|(?:[\p{L}\d-]+\.)+[\p{L}]{2,})(?::\d+)?(?:[/?#].*)?$/u.test(query)) return webURL(`https://${query}`).href;
  const engine = settings.engines.find(e => e.id === settings.engine) || settings.engines[0];
  if (!engine) throw new Error('Add a search engine in Settings.');
  return validateEngine(engine).url.replaceAll('{searchTerms}', encodeURIComponent(query));
}
export function validateSettings(input) {
  if (!input || typeof input !== 'object') throw new Error('Invalid settings file.');
  const engines = Array.isArray(input.engines) ? input.engines.slice(0, 50).map(validateEngine) : structuredClone(DEFAULTS.engines);
  if (!engines.length) throw new Error('Keep at least one search engine.');
  const shortcuts = Array.isArray(input.shortcuts) ? input.shortcuts.slice(0, 12).map(s => ({name: String(s.name).slice(0, 40), url: webURL(s.url).href})) : structuredClone(DEFAULTS.shortcuts);
  const background = typeof input.background === 'string' && input.background.length < 4000000 && /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(input.background) ? input.background : '';
  return {
    theme: THEMES.includes(input.theme) ? input.theme : DEFAULTS.theme,
    accent: /^#[\da-f]{6}$/i.test(input.accent || '') ? input.accent : DEFAULTS.accent,
    greeting: typeof input.greeting === 'string' ? input.greeting.slice(0, 100) : DEFAULTS.greeting,
    background, engines, shortcuts, engine: engines.some(e => e.id === input.engine) ? input.engine : engines[0].id
  };
}
export function canControl(tab, state) {
  if (!state?.enabled || !tab || tab.incognito) return false;
  let url;
  try { url = webURL(tab.url); } catch { return false; }
  return state.grants.some(g => g.tabId === tab.id && g.origin === url.origin);
}
export function chromeTheme(settings) {
  const rgb = hex => hex.match(/[\da-f]{2}/gi).map(n => parseInt(n, 16));
  const dark = ['midnight', 'forest', 'ocean'].includes(settings.theme);
  const frames = {paper: '#eeeae3', midnight: '#191a20', forest: '#172b25', lavender: '#e7e2f0', sand: '#ede0cc', ocean: '#132b3a'};
  return {manifest_version: 3, version: '1.0', name: `Kumo · ${settings.theme}`, theme: {colors: {
    frame: rgb(frames[settings.theme] || frames.paper), toolbar: rgb(dark ? '#23262b' : '#f8f6f2'),
    tab_text: rgb(dark ? '#ecece8' : '#292823'), bookmark_text: rgb(dark ? '#ecece8' : '#292823'),
    ntp_background: rgb(frames[settings.theme] || frames.paper), ntp_text: rgb(dark ? '#ecece8' : '#292823'),
    button_background: [...rgb(settings.accent), 1]
  }}};
}
