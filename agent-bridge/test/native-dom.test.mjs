import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
const raw=await readFile(new URL('../../native/browser/agents/kumo_agent_dom.h',import.meta.url),'utf8');
const script=raw.match(/R"KUMO\(([\s\S]*)\)KUMO"/)[1];
const run=(page,action,params={},origin='https://example.com')=>JSON.parse(JSON.stringify(vm.runInNewContext(script+'(...args)',{...page,URL,args:[action,params,origin]})));
function sensitiveFieldPage() {
  const attributeSelector = /^([a-z]+)?(?:\[([\w-]+)(?:(~=|\*=|=)(?:"([^"]*)"|'([^']*)'|([^\]\s]+))(?:\s+(i))?)?\])?$/i;
  const matches = (element, selector) => selector.split(',').some(part => {
    const match = part.trim().match(attributeSelector);
    assert.ok(match, `Unsupported selector in the deterministic DOM fixture: ${part}`);
    const [, tag, attribute, operator, doubleQuoted, singleQuoted, bare, insensitive] = match;
    if (tag && tag.toUpperCase() !== element.tagName) return false;
    if (!attribute) return true;
    let value = element.getAttribute(attribute);
    if (value === null) return false;
    if (!operator) return true;
    let expected = doubleQuoted ?? singleQuoted ?? bare;
    if (insensitive) { value = value.toLowerCase(); expected = expected.toLowerCase(); }
    if (operator === '=') return value === expected;
    if (operator === '*=') return value.includes(expected);
    return value.split(/[\t\n\f\r ]+/).includes(expected);
  });
  class Element {
    constructor(tag, id, autocomplete = '') {
      this.tagName = tag.toUpperCase(); this.id = id; this.name = id;
      this.attributes = {autocomplete}; this.parentElement = null;
      this.style = {display: 'block', visibility: 'visible', opacity: '1'};
      this.childNodes = []; this.placeholder = id; this.disabled = false; this.readOnly = false;
    }
    getAttribute(name) { return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null; }
    getClientRects() { return [{}]; }
    matches(selector) { return matches(this, selector); }
    closest(selector) {
      for (let current = this; current; current = current.parentElement) if (current.matches(selector)) return current;
      return null;
    }
    click() { this.clicks = (this.clicks || 0) + 1; }
    dispatchEvent(event) { (this.events ||= []).push(event.type); }
    append(...children) {
      for (let child of children) {
        if (typeof child === 'string') child = {textContent: child};
        child.parentElement = this; this.childNodes.push(child);
      }
      return this;
    }
    get innerText() { return this.childNodes.map(child => child instanceof Element ? child.innerText : child.textContent).join(''); }
  }
  class Input extends Element {
    constructor(id, autocomplete) { super('input', id, autocomplete); this.type = 'text'; this.attributes.type = 'text'; this._value = 'SYNTHETIC_FIELD_VALUE'; }
    get value() { return this._value; }
    set value(value) { this._value = value; }
  }
  const sensitive = [
    'one-time-code', 'section-login one-time-code', 'section-login\tone-time-code',
    '  SECTION-LOGIN\nONE-TIME-CODE\r ', 'section-login\fone-time-code',
    'one-time-code webauthn', 'NEW-PASSWORD', 'section-login CURRENT-PASSWORD',
    'SECTION-CHECKOUT CC-NUMBER',
  ].map((autocomplete, index) => new Input(`private-${index}`, autocomplete));
  const nested = new Input('private-ancestor', '');
  new Element('div', 'otp-section', 'section-login ONE-TIME-CODE').append(nested);
  sensitive.push(nested);
  const normal = [new Input('public-email', 'section-login email'), new Input('public-similar-token', 'one-time-code-extra')];
  const body = new Element('body', 'body');
  for (const field of [...sensitive, ...normal]) body.append(field.parentElement || field);
  const descendants = root => root.childNodes.flatMap(child => child instanceof Element ? [child, ...descendants(child)] : [child]);
  const document = {
    title: 'Synthetic form', body,
    createTreeWalker(root, what, filter) {
      assert.equal(what, 4);
      const nodes = descendants(root).filter(node => !(node instanceof Element)); let index = 0;
      return {nextNode() { while (index < nodes.length) { const node = nodes[index++]; if (filter.acceptNode(node) === 1) return node; } return null; }};
    },
    querySelectorAll(selector) { assert.ok(['a[href]', 'button,input,textarea,select'].includes(selector)); return descendants(body).filter(element => element instanceof Element && element.matches(selector)); },
    querySelector(selector) { return descendants(body).find(element => element instanceof Element && selector === `#${element.id}`) || null; },
  };
  return {sensitive, normal, Element, body, page: {
    document, location: {origin: 'https://example.com', href: 'https://example.com/'},
    NodeFilter: {SHOW_TEXT: 4, FILTER_ACCEPT: 1, FILTER_REJECT: 2}, getComputedStyle: element => element.style,
    HTMLInputElement: Input, HTMLTextAreaElement: class {}, Event: class {constructor(type) {this.type = type;}},
  }};
}

test('compiled native DOM sampler excludes sensitive tokens and filled values',()=>{
 const f=sensitiveFieldPage(),result=run(f.page,'tab.snapshot');assert.deepEqual(result.controls.map(x=>x.id),f.normal.map(x=>x.id));assert.doesNotMatch(JSON.stringify(result),/private-|SYNTHETIC_FIELD_VALUE/);
 for(const field of f.sensitive)for(const action of ['tab.click','tab.type']){const result=run(f.page,action,{selector:'#'+field.id,text:'secret'});assert.match(result.error,/password, payment, file, or verification-code/);assert.equal(field.value,'SYNTHETIC_FIELD_VALUE');assert.equal(field.clicks||0,0);}
});
test('ordinary field clicks/types work without exposing their values',()=>{
 const f=sensitiveFieldPage();for(const field of f.normal){assert.deepEqual(run(f.page,'tab.click',{selector:'#'+field.id}),{clicked:true});assert.deepEqual(run(f.page,'tab.type',{selector:'#'+field.id,text:'Ordinary'}),{typed:8});assert.equal(field.value,'Ordinary');assert.deepEqual(field.events,['input','change']);}assert.doesNotMatch(JSON.stringify(run(f.page,'tab.snapshot')),/Ordinary|SYNTHETIC_FIELD_VALUE/);
});
test('all snapshot channels exclude editable ancestors and private descendants',()=>{
 const f=sensitiveFieldPage(), {Element}=f;
 const draft=new Element('textarea','draft');draft.placeholder='';draft.append('PRIVATE_DEFAULT_DRAFT');
 const choices=new Element('select','choices');choices.placeholder='';choices.append(new Element('option','choice').append('PRIVATE_OPTION_VALUE'));
 const editable=new Element('div','editable');editable.attributes.contenteditable='true';
 const privateLink=new Element('a','private-link');privateLink.attributes.href='/private';privateLink.href='https://example.com/private';privateLink.append('PRIVATE_EDITABLE_LINK');
 const privateControl=new Element('button','private-control');privateControl.placeholder='';privateControl.append('PRIVATE_EDITABLE_BUTTON');editable.append(privateLink,privateControl);
 const link=new Element('a','public-link');link.attributes.href='/public';link.href='https://example.com/public?token=PRIVATE_URL_TOKEN';
 const linkDraft=new Element('span','link-draft');linkDraft.attributes.contenteditable='true';linkDraft.append('PRIVATE_NESTED_LINK_DRAFT');
 link.append('Public link label',linkDraft);
 const button=new Element('button','public-button');button.placeholder='';
 const buttonDraft=new Element('span','button-draft');buttonDraft.attributes.contenteditable='true';buttonDraft.append('PRIVATE_NESTED_BUTTON_DRAFT');
 const nestedDraft=new Element('textarea','nested-draft');nestedDraft.placeholder='';nestedDraft.append('PRIVATE_NESTED_FORM_VALUE');
 button.append('Public button label',buttonDraft,nestedDraft);
 const hidden=new Element('span','hidden');hidden.attributes.hidden='';hidden.append('PRIVATE_HIDDEN_LABEL');link.append(hidden);
 f.body.append(draft,choices,editable,link,button);
 const result=run(f.page,'tab.snapshot');assert.doesNotMatch(JSON.stringify(result),/PRIVATE_|SYNTHETIC_FIELD_VALUE/);
 assert.deepEqual(result.links,[{text:'Public link label',href:'https://example.com/public'}]);
 assert.equal(result.controls.find(control=>control.id==='draft').label,'');
 assert.equal(result.controls.find(control=>control.id==='choices').label,'');
 assert.equal(result.controls.find(control=>control.id==='public-button').label,'Public button label');
 assert(!result.controls.some(control=>control.id==='private-control'));
 assert.equal(result.controls.find(control=>control.id==='public-email').label,'public-email');
 assert.equal(result.controls.find(control=>control.id==='public-email').name,'public-email');
 assert.match(result.text,/Public link label/);assert.match(result.text,/Public button label/);
});
test('page origin is rechecked before any operation',()=>{
 const f=sensitiveFieldPage();f.page.location.origin='https://other.example';assert.match(run(f.page,'tab.click',{selector:'#'+f.normal[0].id}).error,/changed origin/);assert.equal(f.normal[0].clicks,undefined);
});
test('snapshot URL metadata strips credentials, queries and fragments',()=>{
 const f=sensitiveFieldPage();f.page.location.href='https://example.com/signin?code=PRIVATE#TOKEN';const result=run(f.page,'tab.snapshot');assert.equal(result.url,'https://example.com/signin');assert.doesNotMatch(JSON.stringify(result),/PRIVATE|TOKEN/);
});
test('invalid selectors and unknown DOM operations fail without input mutation',()=>{
 const f=sensitiveFieldPage();f.page.document.querySelector=()=>{throw new Error('bad selector')};assert.match(run(f.page,'tab.click',{selector:'['}).error,/Invalid selector/);
 const g=sensitiveFieldPage();assert.match(run(g.page,'provider-configure',{selector:'#'+g.normal[0].id}).error,/Unknown/);assert.equal(g.normal[0].value,'SYNTHETIC_FIELD_VALUE');
});
