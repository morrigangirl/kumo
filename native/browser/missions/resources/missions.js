import {sendWithPromise} from 'chrome://resources/js/cr.js';
const el = id => document.getElementById(id);
let state = {missions:[],tabs:[],sharing:{grants:[],audit:[]}}, dirty = false, busy = false;
const call = (action, params={}) => sendWithPromise('kumoMissions',action,params);
function message(text) { el('message').textContent=text; }
function fields() { return Object.fromEntries(['id','name','notes','nextStep'].map(id=>[id,el(id).value])); }
function selected(container) { return [...el(container).querySelectorAll('input:checked')].map(input=>input.value); }
function checkbox(container,value,label,checked=false) {
  const row=document.createElement('label'), input=document.createElement('input'); input.type='checkbox'; input.value=value; input.checked=checked;
  row.append(input,document.createTextNode(' '+label)); el(container).append(row);
}
function load(id='') {
  const m=state.missions.find(m=>m.id===id) || {id:'',name:'',notes:'',nextStep:'',sources:[]};
  for (const key of ['id','name','notes','nextStep']) el(key).value=m[key];
  dirty=false; el('delete-confirm').hidden=true; renderSources(m); el('delete').disabled=!m.id; el('restore').disabled=!m.sources.length;
  for (const button of el('missions').children) button.setAttribute('aria-current',String(button.dataset.id===m.id));
}
function renderSources(m) {
  el('sources').replaceChildren();
  for (const [index,s] of m.sources.entries()) {
    const url=new URL(s.url); if (!['https:','http:'].includes(url.protocol) || url.username || url.password) continue;
    const a=document.createElement('a'); a.href=url.href; a.target='_blank'; a.rel='noreferrer noopener'; a.textContent=s.title || url.host; a.title=url.href; a.addEventListener('click',e=>{e.preventDefault();void perform('open',{id:m.id,index},'Source opened.');}); el('sources').append(a);
  }
  if (!m.sources.length) el('sources').textContent='No sources saved yet.';
}
function render() {
  const p=state.preferences || {}; if (/^#[a-f0-9]{6}$/i.test(p.accent)) document.documentElement.style.setProperty('--accent',p.accent);
  document.body.dataset.light=p.illumination || 'glow'; document.body.dataset.motion=p.motion===false?'off':'on'; document.body.style.setProperty('--intensity',String((p.intensity ?? 40)/100));
  el('missions').replaceChildren(); el('tabs').replaceChildren(); el('share-list').replaceChildren(); el('audit').replaceChildren();
  for (const m of state.missions) {
    const b=document.createElement('button'); b.type='button'; b.dataset.id=m.id; b.textContent=m.name;
    const time=document.createElement('small'); time.textContent=new Date(m.updatedAt).toLocaleString(); b.append(time);
    b.addEventListener('click',()=>{if(dirty){message('Save or discard your edits before switching missions.');return;}load(m.id);}); el('missions').append(b);
    checkbox('share-list',m.id,m.name,state.sharing.grants.includes(m.id));
  }
  for (const t of state.tabs) checkbox('tabs',String(t.tabId),t.title+' · '+new URL(t.url).host);
  el('sharing-state').textContent=state.sharing.grants.length ? `${state.sharing.grants.length} shared` : 'Off';
  for (const a of [...state.sharing.audit].reverse()) {
    const li=document.createElement('li'); li.textContent=`${new Date(a.at).toLocaleTimeString()} · ${a.action}${a.missionId ? ' · '+(state.missions.find(m=>m.id===a.missionId)?.name || 'Deleted mission') : ''}`; el('audit').append(li);
  }
}
async function refresh() { state=await call('status'); if(state.ok===false)throw Error(state.error); render(); }
async function perform(action,params={},success='Saved.') {
  if(busy)return; busy=true; document.querySelectorAll('button').forEach(b=>b.disabled=true);
  try {
    const result=await call(action,params); if(result.ok===false)throw Error(result.error);
    const id=result.mission?.id || el('id').value; await refresh();
    if(action==='save'||action==='delete')load(action==='delete'?'':id);
    message(success); return result;
  } catch(error) { message(error.message || 'The operation did not complete.'); }
  finally {busy=false;document.querySelectorAll('button').forEach(b=>b.disabled=false); el('delete').disabled=!el('id').value; el('restore').disabled=!state.missions.find(m=>m.id===el('id').value)?.sources.length;}
}
el('editor').addEventListener('input',()=>dirty=true);
el('editor').addEventListener('submit',e=>{e.preventDefault();void perform('save',{fields:fields(),capture:false,tabIds:[]});});
el('capture').onclick=()=>{if(!el('editor').reportValidity())return;void perform('save',{fields:fields(),capture:true,tabIds:selected('tabs').map(Number)},'Checkpoint saved. Your tabs remain open.');};
el('new').onclick=()=>{if(dirty){message('Save or discard your edits first.');return;}load();el('name').focus();};
el('discard').onclick=()=>load(el('id').value);
el('delete').onclick=()=>el('delete-confirm').hidden=false;
el('cancel-delete').onclick=()=>el('delete-confirm').hidden=true;
el('confirm-delete').onclick=()=>void perform('delete',{id:el('id').value},'Mission deleted.');
el('settings').onclick=()=>void perform('settings',{},'Settings opened.');
el('restore').onclick=()=>void perform('restore',{id:el('id').value},'Saved addresses opened in background tabs.');
el('share').onclick=()=>void perform('share',{ids:selected('share-list')},'Read-only sharing updated for this session.');
el('revoke').onclick=()=>void perform('revoke',{},'Mission sharing is off.');
for(const id of ['refresh','refresh-audit'])el(id).onclick=()=>refresh().catch(e=>message(e.message));
window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
try{await refresh();load(state.missions[0]?.id); }catch{message('Mission Memory is unavailable. Reopen this page in a regular profile.');}
