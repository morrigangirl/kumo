// Copyright 2026 Kumo authors. All rights reserved.
import {CrLitElement} from 'chrome://resources/lit/v3_0/lit.rollup.js';
import {css} from 'chrome://resources/lit/v3_0/lit.rollup.js';
import type {CSSResultGroup} from 'chrome://resources/lit/v3_0/lit.rollup.js';
import type {SearchResult} from '../search_settings.js';
import type {SettingsPlugin} from '../settings_main/settings_plugin.js';
import {KumoBrowserProxy} from './kumo_browser_proxy.js';
import type {KumoParameters, KumoStatus} from './kumo_browser_proxy.js';
import {getHtml} from './kumo_page.html.js';

function object(value: unknown): KumoStatus {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as KumoStatus : {};
}
function text(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

export class SettingsKumoPageElement extends CrLitElement implements SettingsPlugin {
  static get is() { return 'settings-kumo-page'; }
  static override get styles(): CSSResultGroup { return css`
    :host{display:block;max-width:900px;margin:auto;padding:20px;box-sizing:border-box}
    h1{font-size:22px}h2{font-size:17px;margin:0 0 10px}p{line-height:1.5}
    section{padding:22px;margin:0 0 18px;background:var(--cr-card-background-color);border-radius:12px;border:1px solid var(--cr-separator-color)}
    button,input,select,textarea{font:inherit}button{cursor:pointer;border:1px solid var(--cr-separator-color);border-radius:18px;padding:8px 16px;margin:5px 8px 5px 0;background:var(--cr-card-background-color);color:var(--cr-link-color)}
    button:disabled{opacity:.5;cursor:default}label{display:block;margin:12px 0}input[type=text],select,textarea{box-sizing:border-box;width:100%;padding:9px;color:inherit;background:transparent;border:1px solid var(--cr-separator-color);border-radius:5px}
    textarea{min-height:110px}a{color:var(--cr-link-color)}.status{min-height:24px}.muted{color:var(--cr-secondary-text-color)}
  `; }
  override render() { return getHtml.bind(this)(); }
  static override get properties() { return {state: {type: Object}, busy: {type: Boolean}, message: {type: String}, wallpaper: {type: String}, imported: {type: Object}}; }
  protected accessor state: KumoStatus = {};
  protected accessor busy = false;
  protected accessor message = '';
  protected accessor wallpaper = '';
  protected accessor imported: KumoStatus|null = null;
  private readonly proxy = new KumoBrowserProxy();
  protected selectedTabs = new Map<number, string>();
  private poll: number|undefined;
  private refreshing = false;
  private connection = 0;
  private readonly visibilityChanged = () => { this.schedulePoll(); };

  override connectedCallback() {
    super.connectedCallback(); ++this.connection;
    document.addEventListener('visibilitychange', this.visibilityChanged);
    void this.refresh(); this.schedulePoll();
  }
  override disconnectedCallback() {
    ++this.connection;
    document.removeEventListener('visibilitychange', this.visibilityChanged);
    if (this.poll !== undefined) window.clearTimeout(this.poll);
    this.poll = undefined; super.disconnectedCallback();
  }
  private schedulePoll() {
    if (this.poll !== undefined) window.clearTimeout(this.poll);
    this.poll = undefined;
    if (!this.isConnected || document.visibilityState !== 'visible') return;
    this.poll = window.setTimeout(async () => {
      await this.refresh(); this.schedulePoll();
    }, 2500);
  }
  searchContents(query: string): Promise<SearchResult> {
    const match = 'kumo update antivirus clamav phishing malware agent codex claude appearance theme search'.includes(query.toLowerCase());
    return Promise.resolve({canceled: false, matchCount: query === '' || match ? 1 : 0, wasClearSearch: query === ''});
  }
  private async refresh() {
    if (this.refreshing || !this.isConnected || document.visibilityState !== 'visible' || location.pathname !== '/kumo') return;
    const connection = this.connection; this.refreshing = true;
    let timer: number|undefined;
    try {
      const status = await Promise.race([this.proxy.getStatus(), new Promise<KumoStatus>((_resolve,reject) => { timer = window.setTimeout(() => reject(new Error('Status timed out')), 5000); })]);
      if (connection === this.connection && this.isConnected) this.state = status;
    } catch { if (connection === this.connection) this.message = 'Kumo status is unavailable. Open this page again.'; }
    finally { if (timer !== undefined) window.clearTimeout(timer); this.refreshing = false; }
  }
  private async action(name: string, params: KumoParameters = {}): Promise<KumoStatus|undefined> {
    if (this.busy) return undefined;
    this.busy = true; this.message = 'Working…';
    try {
      const reply = await this.proxy.performAction(name, params);
      this.message = text(reply['message'], reply['ok'] === false ? text(reply['error'], 'The operation could not complete.') : 'Done.');
      await this.refresh();
      return reply;
    } catch { this.message = 'The operation did not complete. Check the current status before trying again.'; return undefined; }
    finally { this.busy = false; }
  }
  private field(id: string): string { return (this.shadowRoot.getElementById(id) as HTMLInputElement).value; }
  protected async onSaveAppearanceClick() {
    await this.action('preferences.set', {theme: this.field('theme'), accent: this.field('accent'), greeting: this.field('greeting')});
  }
  protected preferences(): KumoStatus { return object(this.state['preferences']); }
  protected engines(): KumoStatus[] { const v = this.preferences()['engines']; return Array.isArray(v) ? v as KumoStatus[] : []; }
  protected shortcuts(): KumoStatus[] { const v = this.preferences()['shortcuts']; return Array.isArray(v) ? v as KumoStatus[] : []; }
  private webAddress(value: string, template = false): string {
    if (template && !value.includes('{searchTerms}')) throw new Error('Include {searchTerms} in the search URL.');
    const url = new URL(template ? value.replaceAll('{searchTerms}', 'test') : value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('Use an HTTP or HTTPS address without embedded credentials.');
    return value;
  }
  protected onAddEngineClick() {
    try {
      const name = this.field('engineName').trim(), url = this.webAddress(this.field('engineURL').trim(), true);
      if (!name || name.length > 60 || this.engines().length >= 50) throw new Error('Use a name up to 60 characters and at most 50 engines.');
      void this.action('preferences.set', {engines: [...this.engines(), {id: crypto.randomUUID(), name, url}]});
    } catch (e) { this.message = (e as Error).message; }
  }
  private editEngine(id: string) {
    try {
      const name = this.field('engine-name-'+id).trim();
      const url = this.webAddress(this.field('engine-url-'+id).trim(), true);
      if (!name || name.length > 60) throw new Error('Use a name up to 60 characters.');
      void this.action('preferences.set', {engines: this.engines().map(e => e['id'] === id ? {id, name, url} : e)});
    } catch (e) { this.message = (e as Error).message; }
  }
  private editShortcut(index: number) {
    try {
      const name = this.field('shortcut-name-'+index).trim();
      const url = this.webAddress(this.field('shortcut-url-'+index).trim());
      if (!name || name.length > 40) throw new Error('Use a name up to 40 characters.');
      void this.action('preferences.set', {shortcuts: this.shortcuts().map((s,i) => i === index ? {name,url} : s)});
    } catch (e) { this.message = (e as Error).message; }
  }
  private removeEngine(id: unknown) {
    const engines = this.engines().filter(e => e['id'] !== id);
    if (!engines.length) { this.message = 'Keep at least one search engine.'; return; }
    void this.action('preferences.set', {engines, engine: this.preferences()['engine'] === id ? engines[0]['id'] : this.preferences()['engine']});
  }
  protected onAddShortcutClick() {
    try {
      const name = this.field('shortcutName').trim(), url = this.webAddress(this.field('shortcutURL').trim());
      if (!name || name.length > 40 || this.shortcuts().length >= 12) throw new Error('Use a name up to 40 characters and at most 12 shortcuts.');
      void this.action('preferences.set', {shortcuts: [...this.shortcuts(), {name, url}]});
    } catch (e) { this.message = (e as Error).message; }
  }
  protected onWallpaperChange(e: Event) {
    const file = (e.target as HTMLInputElement).files?.[0]; if (!file) return;
    if (!['image/png','image/jpeg','image/webp'].includes(file.type) || file.size > 2900000) { this.message = 'Choose a PNG, JPEG or WebP image smaller than 2.9 MB.'; return; }
    const reader = new FileReader();
    reader.onload = () => { this.wallpaper = typeof reader.result === 'string' && reader.result.length < 4000000 ? reader.result : ''; this.message = this.wallpaper ? 'Wallpaper selected. Choose Apply wallpaper to save it.' : 'The image is too large.'; };
    reader.onerror = () => { this.message = 'The image could not be read.'; };
    reader.readAsDataURL(file);
  }
  protected async onImportChange(e: Event) {
    const file = (e.target as HTMLInputElement).files?.[0]; if (!file) return;
    if (file.size > 4100000) { this.message = 'This settings file is too large.'; return; }
    try {
      const value: unknown = JSON.parse(await file.text());
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
      this.imported = value as KumoStatus; this.message = 'Settings selected. Choose Apply imported settings to validate and save them.';
    } catch { this.imported = null; this.message = 'Choose a valid Kumo settings JSON file.'; }
  }
  protected async onExportClick() {
    const result = await this.action('preferences.export'); if (!result || result['ok'] === false) return;
    const preferences = object(result['preferences']);
    if (!Object.keys(preferences).length) { this.message = 'The browser did not return exportable preferences.'; return; }
    const url = URL.createObjectURL(new Blob([JSON.stringify(preferences, null, 2)+'\n'], {type:'application/json'}));
    const link = document.createElement('a'); link.href = url; link.download = 'kumo-settings.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  protected async onGrantClick() {
    const tabs = Array.isArray(this.state['tabs']) ? this.state['tabs'] as KumoStatus[] : [];
    const grants = tabs.filter(t => typeof t['tabId'] === 'number' && this.selectedTabs.get(t['tabId']) === t['origin']).map(t => ({tabId: t['tabId'], origin: t['origin']}));
    await this.action('agents.grant', {grants, allowNewTabs: (this.shadowRoot.getElementById('allowNewTabs') as HTMLInputElement).checked});
  }

  protected text(value: unknown, fallback = ''): string { return text(value, fallback); }
  protected updates(): KumoStatus { return object(this.state['updates']); }
  protected scanner(): KumoStatus { return object(this.state['downloadProtection']); }
  protected protection(): KumoStatus { return object(this.state['protection']); }
  protected agents(): KumoStatus { return object(this.state['agents']); }
  protected phishing(): KumoStatus { return object(this.protection()['phishing']); }
  protected malware(): KumoStatus { return object(this.protection()['malware']); }
  protected tabs(): KumoStatus[] { const value = this.state['tabs']; return Array.isArray(value) ? value as KumoStatus[] : []; }
  protected client(key: string): KumoStatus { return object(object(this.state['clients'])[key]); }
  protected onActionClick(e: Event) {
    const action = (e.currentTarget as HTMLElement).dataset['action'];
    if (action) void this.action(action);
  }
  protected onPhishingChange(e: Event) { void this.action('phishing.setEnabled', {enabled: (e.target as HTMLInputElement).checked}); }
  protected onMalwareChange(e: Event) { void this.action('malware.setEnabled', {enabled: (e.target as HTMLInputElement).checked}); }
  protected onTabChange(e: Event) {
    const field = e.currentTarget as HTMLInputElement;
    const tabId = Number(field.dataset['tabId']);
    if (!Number.isSafeInteger(tabId) || tabId < 0) return;
    field.checked ? this.selectedTabs.set(tabId, field.dataset['origin'] || '') : this.selectedTabs.delete(tabId);
  }
  protected onWallpaperApplyClick() { void this.action('preferences.set', {background: this.wallpaper}); }
  protected onWallpaperClearClick() { void this.action('preferences.set', {background: ''}); }
  protected onEngineChange(e: Event) { void this.action('preferences.set', {engine: (e.target as HTMLSelectElement).value}); }
  protected onSaveEngineClick(e: Event) { this.editEngine((e.currentTarget as HTMLElement).dataset['engineId'] || ''); }
  protected onRemoveEngineClick(e: Event) { this.removeEngine((e.currentTarget as HTMLElement).dataset['engineId']); }
  protected onSaveShortcutClick(e: Event) { this.editShortcut(Number((e.currentTarget as HTMLElement).dataset['index'])); }
  protected onRemoveShortcutClick(e: Event) {
    const index = Number((e.currentTarget as HTMLElement).dataset['index']);
    void this.action('preferences.set', {shortcuts: this.shortcuts().filter((_s, i) => i !== index)});
  }
  protected onImportApplyClick() { if (this.imported) void this.action('preferences.import', {preferences: this.imported}); }

}

declare global {
  interface HTMLElementTagNameMap {
    'settings-kumo-page': SettingsKumoPageElement;
  }
}

customElements.define(SettingsKumoPageElement.is, SettingsKumoPageElement);
