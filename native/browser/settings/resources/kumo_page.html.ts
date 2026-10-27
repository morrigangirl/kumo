// Copyright 2026 Kumo authors. All rights reserved.
import {html} from 'chrome://resources/lit/v3_0/lit.rollup.js';
import type {SettingsKumoPageElement} from './kumo_page.js';

export function getHtml(this: SettingsKumoPageElement) {
    return html`
      <h1>Kumo</h1><p>Browser preferences and protection, built into Kumo.</p>
      <p class="status" role="status" aria-live="polite">${this.message}</p>
      <section><h2>Updates</h2><p>Kumo ${this.text(this.state['version'])} · Build ${this.text(this.state['build'])}</p>
        <p>${this.text(this.updates()['message'], this.text(this.updates()['reason'], 'Checking installed update configuration…'))}</p>
        <button ?disabled=${this.busy} data-action="updates.check" @click="${this.onActionClick}">Check for updates</button>
        <a href="https://github.com/morrigangirl/kumo/releases" target="_blank" rel="noopener">Release history</a></section>
      <section><h2>Download protection</h2><p>${this.text(this.scanner()['message'], this.text(this.scanner()['reason'], this.text(this.scanner()['status'], 'Checking local scanner…')))}</p>
        <p class="muted">Downloads wait for the local antivirus scan. Installation may ask for macOS administrator approval.</p>
        <button ?disabled=${this.busy} data-action="protection.setup" @click="${this.onActionClick}">Install or repair protection</button>
        <button ?disabled=${this.busy} data-action="definitions.update" @click="${this.onActionClick}">Update definitions</button>
        <button ?disabled=${this.busy} data-action="agents.refresh" @click="${this.onActionClick}">Refresh status</button></section>
      <section><h2>Website protection</h2>
        <p>${this.protection()['migrationComplete'] === true ? 'Website protection preferences are ready.' : this.text(this.protection()['migrationError'], 'Preparing saved protection preferences…')}</p>
        <p>PhishLang: ${this.text(this.phishing()['health'], 'checking')} ${this.text(this.phishing()['error'])}</p>
        <label><input type="checkbox" .checked=${this.phishing()['enabled'] === true} ?disabled=${this.busy || this.protection()['migrationComplete'] !== true}
          @change="${this.onPhishingChange}"> Local PhishLang phishing warnings</label>
        <p class="muted">Page analysis stays on this Mac. The experimental model can miss threats or warn about legitimate pages.</p>
        <label><input type="checkbox" .checked=${this.malware()['enabled'] === true} ?disabled=${this.busy || this.protection()['migrationComplete'] !== true}
          @change="${this.onMalwareChange}"> Block known dangerous domains</label>
        <p>Domain protection: ${this.text(this.malware()['health'], 'checking')} · ${typeof this.malware()['domainCount'] === 'number' ? this.malware()['domainCount'] : 0} domains. ${this.malware()['stale'] === true ? 'The list is due for an update.' : ''} ${this.text(this.malware()['lastError'])}</p>
        <button ?disabled=${this.busy} data-action="malware.update" @click="${this.onActionClick}">Update domain list</button></section>
      <section><h2>Codex and Claude</h2><p>Connect your existing desktop client, then choose which tabs it may control.</p>
        <button ?disabled=${this.busy} data-action="agents.connectCodex" @click="${this.onActionClick}">Connect Codex Desktop</button>
        <button ?disabled=${this.busy} data-action="agents.connectClaude" @click="${this.onActionClick}">Connect Claude Desktop</button>
        <p>Browser connection: ${this.agents()['bridgeConnected'] === true ? 'ready' : 'unavailable'}. ${this.text(this.agents()['bridgeError'])}</p>
        <p>${this.agents()['enabled'] === true ? 'Agent access is enabled for the listed grants.' : 'Agent access is off.'}</p>
        ${['codex','claude'].map(key => html`<p>${key === 'codex' ? 'Codex Desktop' : 'Claude Desktop'}: ${this.client(key)['configured'] === true ? 'configured; reload the desktop client after connecting' : this.text(this.client(key)['status'], 'checking configuration')}.</p>`)}
        <button ?disabled=${this.busy} data-action="agents.refresh" @click="${this.onActionClick}">Refresh connections and tabs</button>
        ${this.tabs().map(t => html`<label><input type="checkbox" .checked=${this.selectedTabs.get(t['tabId'] as number) === t['origin']} ?disabled=${this.busy} data-tab-id=${t['tabId']} data-origin=${this.text(t['origin'])} @change="${this.onTabChange}"> ${this.text(t['title'], 'Tab')} · ${this.text(t['origin'])}</label>`)}
        <label><input id="allowNewTabs" type="checkbox"> Also allow new tabs</label>
        <button ?disabled=${this.busy} @click="${this.onGrantClick}">Allow selected tabs</button>
        <button ?disabled=${this.busy} data-action="agents.revoke" @click="${this.onActionClick}">Revoke live tab access</button>
        <p class="muted">Access ends when the browser closes, a tab changes origin, the browser connection ends, or you revoke it. Your AI account remains in its desktop client.</p></section>
      <section><h2>RELAY appearance</h2>
        <p>Your accent follows the browser palette, tab rail and Mission Memory. <a href="chrome://kumo-missions/">Open Mission Memory</a></p>
        <label>Theme<select id="theme" .value=${this.text(this.preferences()['theme'], 'relay')}>
          ${['relay','paper','midnight','forest','lavender','sand','ocean'].map(t => html`<option value=${t}>${t}</option>`)}</select></label>
        <label>Accent<input id="accent" type="color" .value=${this.text(this.preferences()['accent'], '#a78bfa')}></label>
        <label>Accent preset<select @change="${this.onAccentPresetChange}"><option value="">Custom</option><option value="#a78bfa">Violet</option><option value="#7dd3fc">Ice blue</option><option value="#5eead4">Teal</option><option value="#f9a8d4">Rose</option><option value="#fbbf24">Amber</option></select></label>
        <label>Illumination<select id="illumination" .value=${this.text(this.preferences()['illumination'], 'glow')}><option value="off">Off</option><option value="glow">Subtle glow</option><option value="pulse">Slow pulse</option></select></label>
        <label>Glow intensity<input id="intensity" type="range" min="0" max="100" .value=${String(this.preferences()['intensity'] ?? 40)}></label>
        <label><input id="motion" type="checkbox" .checked=${this.preferences()['motion'] !== false}> Subtle motion (always respects Reduce Motion)</label>
        <label>Greeting<input id="greeting" type="text" maxlength="100" .value=${this.text(this.preferences()['greeting'], 'A little room to explore.')}></label>
        <button ?disabled=${this.busy} @click="${this.onSaveAppearanceClick}">Save appearance</button>
        <button ?disabled=${this.busy} data-action="appearance.applyTheme" @click="${this.onActionClick}">Activate RELAY frame</button>
        <label>Local wallpaper<input type="file" accept="image/png,image/jpeg,image/webp" @change="${this.onWallpaperChange}"></label>
        <button ?disabled=${this.busy || !this.wallpaper} @click="${this.onWallpaperApplyClick}">Apply wallpaper</button>
        <button ?disabled=${this.busy} @click="${this.onWallpaperClearClick}">Clear wallpaper</button>
        <p><a href="chrome://settings/appearance">Browser themes and toolbar appearance</a> · <a href="chrome://settings/searchEngines">Address-bar search engines</a></p></section>
      <section><h2>Start-page search engines</h2>
        <label>Default engine<select .value=${this.text(this.preferences()['engine'])} @change="${this.onEngineChange}">
          ${this.engines().map(e => html`<option value=${this.text(e['id'])}>${this.text(e['name'])}</option>`)}</select></label>
        ${this.engines().map(e => html`<div><label>Engine name<input id=${'engine-name-'+this.text(e['id'])} type="text" maxlength="60" .value=${this.text(e['name'])}></label><label>Search URL<input id=${'engine-url-'+this.text(e['id'])} type="text" .value=${this.text(e['url'])}></label><button ?disabled=${this.busy} data-engine-id=${this.text(e['id'])} @click="${this.onSaveEngineClick}">Save engine</button><button ?disabled=${this.busy} data-engine-id=${this.text(e['id'])} @click="${this.onRemoveEngineClick}">Remove engine</button></div>`)}
        <label>Name<input id="engineName" type="text" maxlength="60"></label><label>Search URL<input id="engineURL" type="text" placeholder="https://example.com/search?q={searchTerms}"></label>
        <button ?disabled=${this.busy} @click="${this.onAddEngineClick}">Add search engine</button></section>
      <section><h2>Start-page shortcuts</h2>
        ${this.shortcuts().map((s, index) => html`<div><label>Shortcut name<input id=${'shortcut-name-'+index} type="text" maxlength="40" .value=${this.text(s['name'])}></label><label>Address<input id=${'shortcut-url-'+index} type="text" .value=${this.text(s['url'])}></label><button ?disabled=${this.busy} data-index=${index} @click="${this.onSaveShortcutClick}">Save shortcut</button><button ?disabled=${this.busy} data-index=${index} @click="${this.onRemoveShortcutClick}">Remove shortcut</button></div>`)}
        <label>Name<input id="shortcutName" type="text" maxlength="40"></label><label>Address<input id="shortcutURL" type="text" placeholder="https://example.com/"></label>
        <button ?disabled=${this.busy} @click="${this.onAddShortcutClick}">Add shortcut</button></section>
      <section><h2>Import and export</h2><p>Transfer appearance, shortcuts and start-page search preferences. Agent grants and account credentials are excluded.</p>
        <button ?disabled=${this.busy} @click="${this.onExportClick}">Export settings</button>
        <label>Settings JSON<input type="file" accept="application/json,.json" @change="${this.onImportChange}"></label>
        <button ?disabled=${this.busy || !this.imported} @click="${this.onImportApplyClick}">Apply imported settings</button></section>
    `;
}
