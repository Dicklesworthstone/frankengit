import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { RebaseClient } from '../../crates/fgit-node/src/smart_http/server/browser/rebase.mjs';
import { mountRebase, collectResolutions, display, chosenFile } from '../../crates/fgit-node/src/smart_http/server/browser/rebase-view.mjs';
import { FILE_BYTES as FILE_LIMIT, RESOLUTION_BYTES as RESOLUTION_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/rebase-data.mjs';
import { utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fixture, token, href, crypto } from './rebase-session-fixtures.mjs';
const dir=new URL('../../crates/fgit-node/src/smart_http/server/browser/',import.meta.url);
const html=readFileSync(new URL('rebase.html',dir),'utf8');
class Element {
  children=[];listeners=new Map();value='';disabled=false;checked=false;files=[];ownText='';hidden=false;
  constructor(tag){this.tagName=tag.toUpperCase();}
  set textContent(value){this.ownText=String(value);this.children=[];}
  get textContent(){return this.ownText+this.children.map(c=>c.textContent??String(c)).join('');}
  addEventListener(kind,fn){this.listeners.set(kind,[...(this.listeners.get(kind)??[]),fn]);}
  replaceChildren(...children){this.children=children;this.ownText='';}
  append(...children){this.children.push(...children);}
  click(){return this.fire('click');}
  async fire(kind='click'){if(kind==='click'&&this.disabled)return;for(const fn of this.listeners.get(kind)??[])await fn({target:this,preventDefault(){}});}
}
function documentFixture(){
 const nodes=new Map([...html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)].map(m=>[m[2],new Element(m[1])]));
 for(const [key,value] of Object.entries({source:'refs/heads/topic',onto:'refs/heads/main',format:'sha1',empty:'stop','max-commits':'32','empty-policy':''}))nodes.get(key).value=value;
 return {nodes,getElementById:id=>nodes.get(id),createElement:tag=>new Element(tag)};
}
async function setup(sequence=null){
 const f=await fixture(),doc=documentFixture(),client=new RebaseClient({href,cryptoImpl:crypto,fetchImpl:f.fetchImpl});
 if(sequence)f.config.sequence=sequence(f);
 const events={callbacks:new Map(),addEventListener(k,fn){this.callbacks.set(k,fn);}};let receipt=null;
 const app=mountRebase(doc,{client,events,saveReceipt:value=>receipt=value}),el=id=>doc.nodes.get(id);
 el('token').value=token;await el('connect').fire();await el('select').fire();
 for(const key of ['upstream','committer','timestamp'])el(key).value=String(f.input[key]);
 return {f,doc,client,app,el,events,receipt:()=>receipt};
}
const file=bytes=>({size:bytes.length,arrayBuffer:async()=>bytes.slice().buffer});
function inputRow(path='61',choice='file',data=file(new Uint8Array())){return {path,choice:{value:choice},mode:{value:'100644'},content:{value:''},file:{files:[data]},endings:{value:'lf'}};}
const retained={resolutionPaths:0,resolutionBytes:0};
test('UI prepares, inspects, stages, and demands a separate rewrite confirmation',async()=>{
 const s=await setup();assert.equal(s.el('token').value,'');await s.el('prepare').fire();assert(s.client.state.candidate);
 assert(s.el('inspection').textContent.includes('Net change'));assert(s.el('inspection').textContent.includes('Rewritten commit 2'));
 await s.el('stage').fire();const count=s.f.calls.length;await s.el('send').fire();assert.equal(s.f.calls.length,count);assert(s.el('status').textContent.includes('Confirm'));
 s.el('confirm-send').checked=true;await s.el('send').fire();assert.equal(s.f.calls.at(-1).endpoint,'source/rebase/apply');assert.equal(s.client.pending,null);
});
test('provisional prefix cannot enable publication and each original conflict has explicit choices',async()=>{
 const s=await setup(f=>[f.stopped(0),f.stopped(1),f.clean]);await s.el('prepare').fire();assert(s.el('stage').disabled);assert.equal(s.app.rows[0].choice.value,'');
 await s.el('resolve').fire();assert(s.el('status').textContent.includes('explicit'));
 let row=s.app.rows[0];row.choice.value='ours';await row.choice.fire('change');await s.el('resolve').fire();assert.equal(s.client.state.report.stopped_commit,s.f.original[1]);
 row=s.app.rows[0];row.choice.value='hex';row.content.value='00 ff 0d 0a';row.mode.value='100755';await row.choice.fire('change');await s.el('resolve').fire();
 assert(s.client.state.candidate);assert.equal(s.client.state.resolutionPaths,2);assert.equal(s.f.calls.filter(c=>c.endpoint==='source/tree').length,2);
});
test('empty stop requires a deliberate new policy without a new branch selection',async()=>{
 const s=await setup(f=>[f.stopped(0,'became_empty'),f.clean]);await s.el('prepare').fire();assert.equal(s.el('empty-stop').hidden,false);assert(s.el('stage').disabled);
 await s.el('continue-empty').fire();assert.equal(s.f.calls.filter(c=>c.endpoint==='source/rebase/prepare').length,1);
 s.el('empty-policy').value='keep';await s.el('continue-empty').fire();assert(s.client.state.candidate);assert.equal(s.el('empty').value,'keep');
});
test('input changes discard recipes and inspection without replacing branch pins',async()=>{
 const s=await setup();await s.el('prepare').fire();const selection=s.client.state.selection;
 s.el('committer').value='Other <other@example.invalid>';await s.el('committer').fire('input');
 assert.equal(s.client.state.candidate,null);assert.equal(s.client.state.report,null);assert.deepEqual(s.client.state.selection,selection);assert(s.el('stage').disabled);
 s.el('onto').value='refs/heads/else';await s.el('onto').fire('change');assert.equal(s.client.state.selection,null);assert(s.el('prepare').disabled);
});
test('disconnect clears recipes and views but preserves outstanding request responsibility',async()=>{
 const s=await setup();await s.el('prepare').fire();await s.el('stage').fire();const key=s.client.pending.key;
 assert(s.el('committer').disabled);await s.el('save-receipt').fire();assert(!s.receipt().includes(token));await s.el('disconnect').fire();
 assert.equal(s.client.pending.key,key);assert.equal(s.el('inspection').textContent,'');assert.equal(s.el('token').value,'');assert(!s.el('save-receipt').disabled);
});
test('unknown publication requires renewed confirmation for each unchanged retry',async()=>{
 const s=await setup();await s.el('prepare').fire();await s.el('stage').fire();s.f.config.lose=true;s.el('confirm-send').checked=true;await s.el('send').fire();
 const call=s.f.calls.at(-1);assert(s.el('status').textContent.includes('Outcome unknown'));assert.equal(s.el('confirm-send').checked,false);
 const count=s.f.calls.length;await s.el('send').fire();assert.equal(s.f.calls.length,count);
 s.f.config.lose=false;s.el('confirm-send').checked=true;await s.el('send').fire();assert.deepEqual(s.f.calls.at(-1).options.body,call.options.body);
});
test('restoring a receipt never rereads tips or sends a rewrite',async()=>{
 const s=await setup();await s.el('prepare').fire();await s.el('stage').fire();const saved=s.client.exportReceipt();const other=await setup();
 const count=other.f.calls.length;other.el('restore-file').files=[file(utf8.encode(saved))];await other.el('restore').fire();
 assert.equal(other.f.calls.length,count);assert(other.client.pending);assert.equal(other.el('confirm-send').checked,false);
});
test('all resolution file sizes are checked before the first file read',async()=>{
 let reads=0;const allowed={size:1,arrayBuffer:async()=>{reads++;return new Uint8Array(1).buffer;}};
 const large={size:FILE_LIMIT+1,arrayBuffer:async()=>{reads++;throw new Error('must not read');}};
 await assert.rejects(collectResolutions([inputRow('61','file',allowed),inputRow('62','file',large)],retained,()=>true));assert.equal(reads,0);
});
test('cumulative retained recipes count against the next file read budget',async()=>{
 let reads=0;const f={size:3,arrayBuffer:async()=>{reads++;return new Uint8Array(3).buffer;}};
 await assert.rejects(collectResolutions([inputRow('61','file',f)],{resolutionPaths:1,resolutionBytes:RESOLUTION_LIMIT-2},()=>true));assert.equal(reads,0);
 await assert.rejects(collectResolutions([inputRow('61','file',f)],{resolutionPaths:128,resolutionBytes:0},()=>true));assert.equal(reads,0);
});
test('text, hex and uploads preserve the intended empty/binary/newline semantics',async()=>{
 const t=inputRow('61','text');t.content.value='a\r\nb';t.endings.value='crlf';const h=inputRow('62','hex');h.content.value='00 ff 0a';
 const empty=inputRow('63','file');const v=await collectResolutions([t,h,empty],retained,()=>true);
 assert.deepEqual(v[0].bytes,utf8.encode('a\r\nb'));assert.deepEqual(v[1].bytes,new Uint8Array([0,255,10]));assert.equal(v[2].bytes.length,0);assert.equal(v[2].choice,'file');
});
test('superseding a file while reading cannot submit previous or truncated bytes',async()=>{
 let release;const row=inputRow('61','file',{size:1,arrayBuffer:()=>new Promise(resolve=>release=resolve)});
 const loading=collectResolutions([row],retained,()=>true);while(!release)await new Promise(r=>setImmediate(r));
 row.file.files=[file(new Uint8Array([7]))];release(new Uint8Array([9]).buffer);await assert.rejects(loading,/changed/);
 await assert.rejects(chosenFile({size:2,arrayBuffer:async()=>new Uint8Array(1).buffer},10),/truncated/);
});
test('disconnect during file reading clears controls and sends no resolution',async()=>{
 const s=await setup(f=>[f.stopped(0)]);await s.el('prepare').fire();const row=s.app.rows[0];row.choice.value='file';let release;
 row.file.files=[{size:1,arrayBuffer:()=>new Promise(resolve=>release=resolve)}];const loading=s.el('resolve').fire();while(!release)await new Promise(r=>setImmediate(r));
 await s.el('disconnect').fire();release(new Uint8Array([1]).buffer);await loading;
 assert.equal(s.f.calls.filter(c=>c.endpoint==='source/rebase/resolve').length,0);assert.equal(s.app.rows.length,0);assert.equal(s.client.connected,false);
});
test('cancelled native inspection cannot resurrect the candidate or enable publication',async()=>{
 const s=await setup();let release;s.f.config.wait=endpoint=>endpoint==='source/rebase/inspect'?new Promise(resolve=>release=resolve):null;
 const read=s.el('prepare').fire();while(!release)await new Promise(r=>setImmediate(r));await s.el('cancel').fire();release();await read;
 assert.equal(s.client.state.candidate,null);assert(s.el('stage').disabled);assert(s.el('status').textContent.includes('cancelled'));
});
test('page exit warns for a stopped read-only recipe as well as a pending rewrite',async()=>{
 const s=await setup(f=>[f.stopped(0)]);await s.el('prepare').fire();let warned=false;
 s.events.callbacks.get('beforeunload')({preventDefault(){warned=true;}});assert(warned);s.events.callbacks.get('pagehide')();assert.equal(s.client.state.report,null);
});
test('escaped previews are bounded and never turn repository bytes into markup',()=>{
 assert(display(new Uint8Array([0,255])).includes('\\x'));assert(display(utf8.encode('\u202e<script>')).includes('\\u{202e}'));
 assert(display(new Uint8Array(8192),32).includes('32 of 8192'));assert(display(new Uint8Array(8192),32).length<300);
 for(const name of ['rebase-view.mjs','rebase.mjs','rebase-data.mjs','rebase-inspection.mjs']){
 const body=readFileSync(new URL(name,dir),'utf8');for(const forbidden of ['innerHTML','localStorage','sessionStorage','document.write','eval('])assert(!body.includes(forbidden));}
 assert(!html.includes('<script>'));assert(!/\bon\w+=/.test(html));
});
test('all transitive browser imports are covered by source-only static routes',()=>{
 const rust=readFileSync(new URL('rebase.rs',dir),'utf8'),seen=new Set();
 function visit(name){if(seen.has(name))return;seen.add(name);const path=new URL(name,dir);assert(existsSync(path),name);
  assert(rust.includes(`b"/ui/rebase/${name}"`),name);for(const match of readFileSync(path,'utf8').matchAll(/from ['"]\.\/([^'"]+)['"]/g))visit(match[1]);}
 visit('rebase-view.mjs');assert(rust.includes('profile.allow_source'));assert(rust.includes('request.target.contains'));assert(rust.includes('include_str!("rebase.html")'));
 const router=readFileSync(new URL('../browser.rs',dir),'utf8');assert(router.includes('mod rebase;'));assert(router.includes('rebase::serve(profile, request, trailing, writer)'));
});

test('published interface controls use the current client limits, not the superseded delivery',()=>{
 assert(html.includes('max="32" value="32"'));assert(html.includes('1 MiB and 64 choices'));
 assert(!html.includes('1–64'));assert(!html.includes('128 choices'));
});
test('oversized recovery files are rejected before their bytes are read',async()=>{
 const s=await setup();let reads=0;const count=s.f.calls.length;
 s.el('restore-file').files=[{size:12*1024*1024+1,arrayBuffer:async()=>{reads++;return new ArrayBuffer(0);}}];
 await s.el('restore').fire();assert.equal(reads,0);assert.equal(s.f.calls.length,count);assert.equal(s.client.pending,null);
});
test('a valid-looking candidate with failed inspection cannot enable the stage control',async()=>{
 const s=await setup();s.f.config.inspect=r=>{r.all_changed_paths=false;};await s.el('prepare').fire();
 assert.equal(s.client.candidate,null);assert(s.el('stage').disabled);assert.equal(s.el('inspection').textContent,'');
 assert.equal(s.f.calls.filter(c=>c.endpoint==='source/rebase/apply').length,0);
});
test('a missing side requires explicit deletion rather than an implicit fallback',async()=>{
 const s=await setup(f=>{const r=f.stopped(0);r.conflicts[0].base=null;return [r];});await s.el('prepare').fire();
 const row=s.app.rows[0],count=s.f.calls.length;row.choice.value='base';await row.choice.fire('change');await s.el('resolve').fire();
 assert.equal(s.f.calls.length,count);assert(s.el('stage').disabled);assert(s.el('status').textContent.includes('absent'));
});
test('an entirely dropped series still requires inspection and an exact rewrite confirmation',async()=>{
 const s=await setup();const f=s.f;
 f.config.prepare=r=>{r.empty='drop';r.candidate_commit=f.onto;r.root_tree=f.trees[0];r.generated_objects=0;r.pack_objects=0;
  r.steps=r.steps.map(step=>({...step,rewritten:f.onto,tree:f.trees[0],kind:'dropped_empty'}));};
 f.config.inspect=r=>{r.candidate_commit=f.onto;r.commits=[];r.commit_count=0;r.bundle.pack_objects=0;r.bundle.closure_objects=0;
  r.net_change=f.diff(f.command.expected_source,f.onto,f.sourceTree,f.trees[0]);};
 s.el('empty').value='drop';await s.el('prepare').fire();assert(s.client.candidate);assert.equal(s.client.candidate.inspection.commit_count,0);
 assert(s.el('inspection').textContent.includes('Net change'));assert.equal(f.calls.at(-1).endpoint,'source/rebase/inspect');
 await s.el('stage').fire();assert.equal(s.client.pending.fields.candidate_commit,f.onto);const n=f.calls.length;
 await s.el('send').fire();assert.equal(f.calls.length,n);
 f.config.apply=r=>{r.candidate_commit=f.onto;};s.el('confirm-send').checked=true;await s.el('send').fire();assert.equal(s.client.pending,null);
});
test('a canonical refusal is displayed as a decision and not retried automatically',async()=>{
 const s=await setup();await s.el('prepare').fire();await s.el('stage').fire();
 s.f.config.apply=r=>{r.outcome='refused';r.refusal_code='TargetMoved';r.decision_record='refusal-record';};
 s.el('confirm-send').checked=true;await s.el('send').fire();assert.equal(s.client.pending,null);
 assert(s.el('status').textContent.includes('Canonical refused'));assert.equal(s.f.calls.filter(c=>c.endpoint==='source/rebase/apply').length,1);
});
