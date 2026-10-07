// HTML-derived DOM contracts with the actual initial client. Native replies are
// explicit protocol doubles; these tests are NOT real browser/fg execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mountInitialEditor, initialHexBytes, displayBytes } from '../../crates/fgit-node/src/smart_http/server/browser/initial-view.mjs';
import { InitialSourceClient } from '../../crates/fgit-node/src/smart_http/server/browser/initial.mjs';
import { FILE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
import { utf8, hex } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fixture, metadata, crypto, token, href } from './initial-fixtures.mjs';
const html=readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/initial.html',import.meta.url),'utf8');
class Element {
 children=[];listeners=new Map();disabled=false;checked=false;files=[];ownText='';value='';
 constructor(tag){this.tagName=tag.toUpperCase();}
 set textContent(value){this.ownText=String(value);this.children=[];}
 get textContent(){return this.ownText+this.children.map(c=>c.textContent??String(c)).join('');}
 append(...children){this.children.push(...children);}
 replaceChildren(...children){this.children=children;this.ownText='';}
 addEventListener(event,fn){this.listeners.set(event,[...(this.listeners.get(event)??[]),fn]);}
 async fire(event='click'){if(event==='click'&&this.disabled)return;for(const fn of this.listeners.get(event)??[])await fn({target:this,preventDefault(){}});}
}
function documentFixture(){
 const nodes=new Map();
 for(const m of html.matchAll(/<(\w+)\b[^>]*\bid="([^"]+)"[^>]*>/g)){
  const e=new Element(m[1]);e.value=/\bvalue="([^"]*)"/.exec(m[0])?.[1]??'';
  if(m[1]==='select')e.value=/<option\b[^>]*\bvalue="([^"]*)"/.exec(html.slice(m.index+m[0].length))?.[1]??'';
  e.disabled=/\sdisabled(?:\s|>)/.test(m[0]);nodes.set(m[2],e);
 }
 return {getElementById:id=>nodes.get(id),createElement:tag=>new Element(tag)};
}
const entry=(path,bytes=new Uint8Array([0,255,13,10]),mode=0o100644)=>({path_hex:hex(utf8.encode(path)),bytes,mode});
function upload(name,bytes=new Uint8Array([0,255]),relative=''){
 const f=new File([bytes],name);if(relative)Object.defineProperty(f,'webkitRelativePath',{value:relative});return f;
}
async function setup(algorithm='sha1',entries=[entry('a.bin')]){
 const f=await fixture(algorithm,entries),doc=documentFixture(),client=new InitialSourceClient({href,cryptoImpl:crypto,fetchImpl:f.fetchImpl});
 const callbacks=new Map(),events={addEventListener:(k,v)=>callbacks.set(k,v)};let saved;
 const app=mountInitialEditor(doc,{client,events,saveReceipt:value=>{saved=value;}}),el=id=>doc.getElementById(id);
 el('token').value=token;await el('connect').fire();el('format').value=algorithm;
 for(const [id,value] of Object.entries(metadata))el(id).value=String(value);
 return {f,client,app,el,callbacks,saved:()=>saved};
}
async function batch(s,files,directory=false){
 const id=directory?'directory-files':'batch-files';s.el(id).files=files;await s.el(id).fire('change');await s.el(directory?'import-directory':'import-files').fire();
}
async function prepare(s){s.el('expected-absent').checked=true;await s.el('expected-absent').fire('input');await s.el('prepare').fire();assert(s.client.candidate,s.el('status').textContent);}
async function queueHex(s,path,value){s.el('path').value=path;s.el('input-kind').value='hex';s.el('file-text').value=value;await s.el('queue').fire();}
for(const algorithm of ['sha1','sha256']){
 test(`${algorithm}: a directory of binary/text/empty files becomes one verified root before explicit publication`,async()=>{
  const entries=[entry('vendor/assets/a.bin'),entry('vendor/empty',new Uint8Array()),entry('vendor/text',utf8.encode('one\r\ntwo'))];
  const s=await setup(algorithm,entries);s.el('import-prefix').value='vendor';
  await batch(s,entries.map(e=>{const p=Buffer.from(e.path_hex,'hex').toString().slice(7);return upload(p.split('/').at(-1),e.bytes,`project/${p}`);}),true);
  assert.deepEqual(s.app.queued,entries);assert.equal(s.f.calls.length,0);assert.match(s.el('status').textContent,/imported atomically/);
  await prepare(s);assert.equal(s.client.candidate.preparation.root_tree,s.f.plan.tree);assert.deepEqual(s.client.candidate.preparation.parents,[]);
  await s.el('stage').fire();assert(s.client.pending);assert(s.el('import-files').disabled);assert(s.el('import-directory').disabled);
  await s.el('send').fire();assert.equal(s.f.calls.length,1);assert.match(s.el('status').textContent,/Confirm/);
  s.el('confirm-send').checked=true;await s.el('send').fire();assert.equal(s.client.pending,null);assert.equal(s.app.queued.length,0);
  assert.deepEqual(s.f.calls.map(c=>c.endpoint),['source/initial/prepare','source/initial/apply']);
 });
 test(`${algorithm}: binary batch publication retains identical request bytes and key across lost reply and receipt restore`,async()=>{
  const entries=[entry('a.bin'),entry('empty',new Uint8Array())],s=await setup(algorithm,entries);
  await batch(s,entries.map(e=>upload(Buffer.from(e.path_hex,'hex').toString(),e.bytes)));await prepare(s);await s.el('stage').fire();
  s.f.config.lose=true;s.el('confirm-send').checked=true;await s.el('send').fire();const original=s.f.calls.at(-1),pending=s.client.pending;
  assert(pending.sent);await s.el('save').fire();assert(s.saved());assert(!s.saved().includes(token));
  const restored=await setup(algorithm,entries);restored.el('receipt').files=[upload('retry.json',utf8.encode(s.saved()))];await restored.el('restore').fire();
  assert.equal(restored.f.calls.length,0);assert.equal(restored.client.pending.key,pending.key);
  await restored.el('recover').fire();assert.equal(restored.f.calls.at(-1).body,undefined);assert(restored.client.pending);
  restored.el('confirm-send').checked=true;await restored.el('send').fire();assert.deepEqual(restored.f.calls.at(-1).body,original.body);
  assert.equal(restored.f.calls.at(-1).headers['idempotency-key'],original.headers['idempotency-key']);assert.equal(restored.client.pending,null);
 });
}
test('all hex byte values and explicit executable mode survive single-file queueing',async()=>{
 const s=await setup();s.el('file-mode').value='100755';await queueHex(s,'all',Array.from({length:256},(_,i)=>i.toString(16).padStart(2,'0')).join(' \n'));
 assert.deepEqual(s.app.queued[0].bytes,Uint8Array.from({length:256},(_,i)=>i));assert.equal(s.app.queued[0].mode,0o100755);assert.equal(s.f.calls.length,0);
});
test('empty hex means empty file, not deletion, and a malformed replacement leaves it intact',async()=>{
 const s=await setup();await queueHex(s,'empty','');assert.equal(s.app.queued.length,1);assert.equal(s.app.queued[0].bytes.length,0);
 await queueHex(s,'empty','0');assert.equal(s.app.queued.length,1);assert.equal(s.app.queued[0].bytes.length,0);assert.match(s.el('status').textContent,/hex/i);
});
for(const value of ['xyz','0xFF','ff:00','0', '00\u00a0ff','ff'.repeat(FILE_LIMIT+1)])
 test(`hex editor refuses malformed or oversized input (${value.length} characters, ${value.slice(0,6)})`,()=>assert.throws(()=>initialHexBytes(value)));
test('previews are bounded and escape control/bidi characters without interpreting HTML',()=>{
 assert.equal(displayBytes(utf8.encode('<script>\u202e\0\r\\')),'<script>\\u{202e}\\u{0}\\u{d}\\\\');
 const binary=displayBytes(new Uint8Array(FILE_LIMIT).fill(255));assert(binary.length<8400);assert.match(binary,/limited to 4096 of 262144/);
 assert.equal(displayBytes(new Uint8Array()),'');
});
for(const [name,uploaded,directory] of [
 ['duplicate',[upload('a'),upload('a')],false],['metadata path',[upload('config',undefined,'p/.git/config')],true],
 ['overlap',[upload('a',undefined,'p/a'),upload('b',undefined,'p/a/b')],true],['mixed roots',[upload('a',undefined,'p/a'),upload('b',undefined,'q/b')],true],
])test(`batch ${name} refuses without changing the existing queue`,async()=>{
 const s=await setup();await queueHex(s,'old','00ff');const before=s.app.queued;await batch(s,uploaded,directory);
 assert.deepEqual(s.app.queued,before);assert.equal(s.f.calls.length,0);assert.equal(s.client.candidate,null);
});
test('an occupied queued destination refuses the batch instead of overwriting it',async()=>{
 const s=await setup();await queueHex(s,'a','0001');const before=s.app.queued;await batch(s,[upload('a'),upload('b')]);
 assert.deepEqual(s.app.queued,before);assert.match(s.el('status').textContent,/replace/);
});
test('FileList count is checked before allocating or enumerating its selected members',async()=>{
 const s=await setup();let members=0;s.el('batch-files').files={length:65,get 0(){members++;throw Error('must not enumerate');}};
 await s.el('import-files').fire();assert.equal(members,0);assert.equal(s.app.queued.length,0);assert.match(s.el('status').textContent,/64-file/);
});
for(const cause of ['late-size','aggregate'])test(`${cause} budget is checked before any File read`,async()=>{
 const s=await setup();let reads=0;const first={name:'a',size:1,arrayBuffer(){reads++;return new ArrayBuffer(1);}};
 const rest=cause==='late-size'?[{name:'b',size:FILE_LIMIT+1,arrayBuffer(){reads++;}}]:Array.from({length:4},(_,i)=>({name:`b${i}`,size:FILE_LIMIT,arrayBuffer(){reads++;}}));
 await batch(s,[first,...rest]);assert.equal(reads,0);assert.equal(s.app.queued.length,0);assert.equal(s.f.calls.length,0);
});
test('a later upload read failure preserves the complete old queue and invalidates an older candidate',async()=>{
 const s=await setup('sha1',[entry('old',new Uint8Array([0,255]))]);await queueHex(s,'old','00ff');await prepare(s);assert(s.client.candidate);
 let reads=0;await batch(s,[{name:'a',size:2,async arrayBuffer(){reads++;return new Uint8Array([0,1]).buffer;}},{name:'b',size:2,async arrayBuffer(){throw Error('read failure');}}]);
 assert.equal(reads,1);assert.deepEqual(s.app.queued,[entry('old',new Uint8Array([0,255]))]);assert.equal(s.client.candidate,null);assert(s.el('stage').disabled);
 assert.equal(s.f.calls.length,1);assert.match(s.el('status').textContent,/read failure/);
});
for(const cause of ['cancel','disconnect','selection','prefix','silent-file-replacement'])test(`${cause} while importing never installs a partial or retargeted queue`,async()=>{
 const s=await setup();await queueHex(s,'old','00ff');let release,second=0;
 const first={name:'a',size:2,arrayBuffer(){return new Promise(r=>release=r);}},other={name:'b',size:2,async arrayBuffer(){second++;return new ArrayBuffer(2);}};
 s.el('batch-files').files=[first,other];const pending=s.el('import-files').fire();assert(release);assert(s.el('import-files').disabled);
 if(cause==='cancel'||cause==='disconnect')await s.el(cause).fire();
 else if(cause==='prefix'){s.el('import-prefix').value='other';await s.el('import-prefix').fire('input');}
 else {s.el('batch-files').files=[first,upload('new')];if(cause==='selection')await s.el('batch-files').fire('change');}
 release(new Uint8Array([0,1]).buffer);await pending;assert.equal(second,0);assert.equal(s.app.queued.length,cause==='disconnect'?0:1);
 assert.equal(s.client.candidate,null);assert.equal(s.f.calls.length,0);
});
test('batch file mode is explicit rather than inferred from browser file names',async()=>{
 const s=await setup();s.el('import-mode').value='100755';await batch(s,[upload('script.sh'),upload('data.bin')]);
 assert(s.app.queued.every(f=>f.mode===0o100755));const before=s.app.queued;s.el('import-mode').value='120000';await batch(s,[upload('other')]);assert.deepEqual(s.app.queued,before);
});
test('browser page-exit cleanup clears all import selections and queued binary bytes',async()=>{
 const s=await setup();await batch(s,[upload('a')]);s.el('batch-files').value='fakepath';s.el('directory-files').value='fakepath';
 const event={preventDefault(){this.prevented=true;}};s.callbacks.get('beforeunload')(event);assert(event.prevented);
 s.callbacks.get('pagehide')();assert.equal(s.app.queued.length,0);assert.equal(s.el('batch-files').value,'');assert.equal(s.el('directory-files').value,'');assert.equal(s.client.connected,false);
});
