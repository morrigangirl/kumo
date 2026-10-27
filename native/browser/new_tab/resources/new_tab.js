// Copyright 2026 Kumo authors. All rights reserved.
import {sendWithPromise} from 'chrome://resources/js/cr.js';

const defaults = {theme:'relay',accent:'#a78bfa',illumination:'glow',intensity:40,motion:true,greeting:'A little room to explore.',engine:'duckduckgo',engines:[{id:'duckduckgo',url:'https://duckduckgo.com/?q={searchTerms}'}],shortcuts:[{name:'Apple',url:'https://www.apple.com'},{name:'Wikipedia',url:'https://www.wikipedia.org'},{name:'GitHub',url:'https://github.com'},{name:'YouTube',url:'https://www.youtube.com'}]};
let preferences = defaults;
const element = id => document.getElementById(id);
function webURL(value) {
  const url = new URL(value);
  if (!['https:','http:'].includes(url.protocol) || url.username || url.password) throw new Error('Use an HTTP or HTTPS address.');
  return url;
}
function render(value) {
  preferences = {...defaults,...value};
  const themes = ['relay','paper','midnight','forest','lavender','sand','ocean'];
  document.documentElement.dataset['theme'] = themes.includes(preferences.theme) ? preferences.theme : 'relay';
  if (/^#[0-9a-f]{6}$/i.test(preferences.accent)) document.documentElement.style.setProperty('--accent', preferences.accent);
  document.body.dataset.light = ['off','glow','pulse'].includes(preferences.illumination) ? preferences.illumination : 'off';
  document.body.dataset.motion = preferences.motion === false ? 'off' : 'on';
  document.documentElement.style.setProperty('--intensity', String(Math.max(0, Math.min(100, preferences.intensity ?? 40))/100));
  element('greeting').textContent = typeof preferences.greeting === 'string' ? preferences.greeting.slice(0,100) : defaults.greeting;
  if (typeof preferences.background === 'string' && preferences.background.length < 4000000 && /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(preferences.background)) document.body.style.backgroundImage = `url("${preferences.background}")`;
  element('shortcuts').replaceChildren();
  const shortcuts = Array.isArray(preferences.shortcuts) ? preferences.shortcuts.slice(0,12) : defaults.shortcuts;
  for (const shortcut of shortcuts) {
    try {
      const link = document.createElement('a'); link.href = webURL(shortcut.url).href;
      link.textContent = String(shortcut.name).slice(0,40); element('shortcuts').append(link);
    } catch {}
  }
}
element('date').textContent = new Intl.DateTimeFormat(undefined,{weekday:'long',month:'long',day:'numeric'}).format(new Date());
element('search').addEventListener('submit', event => {
  event.preventDefault(); const query = element('query').value.trim(); if (!query) return;
  try {
    let target;
    if (/^https?:\/\//i.test(query)) target = webURL(query).href;
    else if (!/\s/.test(query) && /^(localhost(?::\d+)?|(?:[\p{L}\d-]+\.)+[\p{L}]{2,})(?::\d+)?(?:[/?#].*)?$/u.test(query)) target = webURL('https://'+query).href;
    else {
      const engines = Array.isArray(preferences.engines) ? preferences.engines : defaults.engines;
      const engine = engines.find(e => e.id === preferences.engine) || engines[0];
      if (!engine || typeof engine.url !== 'string' || !engine.url.includes('{searchTerms}')) throw new Error('Choose a search engine in Kumo Settings.');
      target = webURL(engine.url.replaceAll('{searchTerms}',encodeURIComponent(query))).href;
    }
    window.location.assign(target);
  } catch(error) { element('error').textContent = error.message; }
});
render(defaults);
try { render(await sendWithPromise('kumoNewTabPreferences')); }
catch { element('error').textContent = 'Preferences could not be loaded. Open Kumo Settings to check them.'; }
