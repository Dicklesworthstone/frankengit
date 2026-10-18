// Private root-last request custody, not repository authority. No incomplete
// preparation or torn journal entry is repaired, replaced or treated as absence.
import { constants as F } from 'node:fs';
import { mkdir, open, lstat, realpath, opendir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { performance } from 'node:perf_hooks';
import { readPrivateOperatorFile, readSynchronizedOperatorRecord, saveOperatorRecord }
  from './forge-operator-io.mjs';
import { BOOTSTRAP_LIMITS as L, encode, hash, fail, fields, pin, bounded, canonical, selection,
  createRequest, checkedRequest, outcomeBinding, publication, matchOutcome } from './branch-bootstrap-protocol.mjs';
import { validateOutcomeReply } from '../operator/transaction_outcome.mjs';

export const requestName = i => `request-${String(i+1).padStart(6,'0')}.json`;
const attemptName = i => `attempt-${String(i+1).padStart(6,'0')}`;
export function path(value) {
  if (typeof value!=='string' || !value || resolve(value)!==value || Buffer.byteLength(value)>4096 || /[\0\r\n\uD800-\uDFFF]/u.test(value)) fail('path'); return value;
}
export function lifetime(raw) {
  const timeout=bounded(raw.timeoutMs??300000,1,300000), deadline=performance.now()+timeout;
  if (raw.signal!==undefined && !(raw.signal instanceof AbortSignal)) fail('signal');
  const stop=new AbortController(), signal=raw.signal?AbortSignal.any([raw.signal,stop.signal]):stop.signal;
  const timer=setTimeout(()=>stop.abort(),timeout);
  const check=()=>{signal.throwIfAborted();if(performance.now()>=deadline)fail('timeout');};
  return {signal,check,remaining(){check();return Math.max(1,Math.ceil(deadline-performance.now()));},close(){clearTimeout(timer);stop.abort();}};
}
export async function directory(root, expected=null) {
  path(root);const stat=await lstat(root,{bigint:true});
  if (typeof process.getuid!=='function' || !stat.isDirectory() || stat.uid!==BigInt(process.getuid()) ||
      (stat.mode&0o077n)!==0n || await realpath(root)!==root || expected&&(stat.dev!==expected.dev||stat.ino!==expected.ino)) fail('directory_changed_or_unsafe');
  return stat;
}
async function outsideWorktree(root) {
  for(let p=root;;p=dirname(p)){
    if(p.split('/').includes('.git'))fail('worktree');
    try{await lstat(join(p,'.git'));fail('worktree');}catch(e){if(e.code!=='ENOENT')throw e;}
    if(dirname(p)===p)break;
  }
}
export async function syncDirectory(root) {
  const fd=await open(root,F.O_RDONLY|F.O_DIRECTORY|F.O_NOFOLLOW);
  try{await fd.sync();}finally{await fd.close();}
}
export async function readToken(tokenFile, check) {
  path(tokenFile);await directory(dirname(tokenFile));await outsideWorktree(dirname(tokenFile));
  const bytes=await readPrivateOperatorFile(tokenFile,65,check);
  try{const token=bytes.toString('utf8').replace(/\n$/,'');pin(token);return token;}finally{bytes.fill(0);}
}
export async function inventory(root, maximum, check) {
  const names=[];
  for await(const entry of await opendir(root)){check();if(names.length>=maximum)fail('inventory_limit');names.push(entry.name);}
  return names.sort();
}
async function exactInventory(root, expected, check) {
  const names=await inventory(root,expected.length+1,check);
  if(!isDeepStrictEqual(names,[...expected].sort()))fail('inventory');
}
export async function guard(loaded) {
  await directory(loaded.root,loaded.ids.root);await directory(join(loaded.root,'requests'),loaded.ids.requests);
  await directory(join(loaded.root,'journal'),loaded.ids.journal);
}
export async function loadBootstrap(root, confirm, life, synchronize=false) {
  path(root);pin(confirm);life.check();const rootId=await directory(root);await outsideWorktree(root);
  const reader=synchronize?readSynchronizedOperatorRecord:readPrivateOperatorFile;
  await exactInventory(root,['manifest.json','selection.json','requests','journal'],life.check);
  const bytes=await reader(join(root,'manifest.json'),L.file,life.check);
  if(hash(bytes)!==confirm)fail('plan_pin');
  const m=canonical(bytes);fields(m,['schema','selection_sha256','credential_sha256','requests','request_bytes']);
  if(m.schema!=='frankengit-branch-bootstrap-v1')fail('schema');pin(m.selection_sha256);pin(m.credential_sha256);
  if(!Array.isArray(m.requests))fail('requests');bounded(m.requests.length,1,L.branches);bounded(m.request_bytes,1,L.requestBytes);
  const raw=await reader(join(root,'selection.json'),L.file,life.check);
  if(hash(raw)!==m.selection_sha256)fail('selection_pin');const selected=selection(canonical(raw));
  if(!encode(selected).equals(raw)||m.requests.length!==selected.refs.length)fail('selection_changed');
  const ids={root:rootId,requests:await directory(join(root,'requests')),journal:await directory(join(root,'journal'))};
  const loaded={root,confirm,manifest:m,selection:selected,ids,requests:[]};
  await exactInventory(join(root,'requests'),selected.refs.map((_,i)=>requestName(i)),life.check);
  let total=0;const keys=new Set();
  for(const [i,desc] of m.requests.entries()){
    life.check();await guard(loaded);fields(desc,['sha256','bytes']);pin(desc.sha256);bounded(desc.bytes,1,L.request);
    const data=await reader(join(root,'requests',requestName(i)),L.request,life.check);total+=data.length;
    if(total>L.requestBytes||data.length!==desc.bytes||hash(data)!==desc.sha256)fail('request_commitment');
    const request=checkedRequest(canonical(data)), expected=createRequest(selected,selected.refs[i],m.credential_sha256,request.nonce);
    if(!encode(expected).equals(data)||keys.has(request.key))fail('request_binding');keys.add(request.key);loaded.requests.push(request);
  }
  if(total!==m.request_bytes)fail('request_bytes');await guard(loaded);life.check();return loaded;
}
export async function prepareBootstrap(raw) {
  fields(raw,['workdir','selection','tokenFile','timeoutMs','signal'],['workdir','selection','tokenFile']);
  raw={...raw};
  const root=path(raw.workdir), selected=selection(raw.selection), life=lifetime(raw);let created=false,confirm=null;
  try{
    life.check();await directory(dirname(root));await outsideWorktree(dirname(root));
    try{await lstat(root);fail('exists');}catch(e){if(e.code!=='ENOENT')throw e;}
    const token=await readToken(raw.tokenFile,life.check), fingerprint=hash(Buffer.from(token));
    const requests=selected.refs.map(ref=>{life.check();return encode(createRequest(selected,ref,fingerprint));});
    const total=requests.reduce((n,b)=>n+b.length,0);if(total>L.requestBytes)fail('request_bytes');
    const selectedBytes=encode(selected), m={schema:'frankengit-branch-bootstrap-v1',selection_sha256:hash(selectedBytes),
      credential_sha256:fingerprint,requests:requests.map(b=>({sha256:hash(b),bytes:b.length})),request_bytes:total};
    const bytes=encode(m);if(bytes.length>L.file)fail('manifest_bytes');confirm=hash(bytes);
    await mkdir(root,{mode:0o700});created=true;await syncDirectory(dirname(root));
    const ids={root:await directory(root)};
    for(const name of ['requests','journal']){await mkdir(join(root,name),{mode:0o700});ids[name]=await directory(join(root,name));}
    await syncDirectory(root);const owned={root,ids};
    await saveOperatorRecord(join(root,'selection.json'),selectedBytes,life.check);
    for(const [i,data] of requests.entries()){
      life.check();await guard(owned);await saveOperatorRecord(join(root,'requests',requestName(i)),data,life.check);
    }
    // Re-read each body after all slots exist, before publishing the plan root.
    await exactInventory(root,['selection.json','requests','journal'],life.check);
    await exactInventory(join(root,'requests'),requests.map((_,i)=>requestName(i)),life.check);
    await exactInventory(join(root,'journal'),[],life.check);
    if(!(await readPrivateOperatorFile(join(root,'selection.json'),L.file,life.check)).equals(selectedBytes))fail('selection_changed');
    for(const [i,data] of requests.entries())if(!(await readPrivateOperatorFile(join(root,'requests',requestName(i)),L.request,life.check)).equals(data))fail('request_changed');
    life.check();await guard(owned);await saveOperatorRecord(join(root,'manifest.json'),bytes,life.check);
    return {type:'branch_bootstrap_prepared',workdir:root,plan_sha256:confirm,branches:requests.length,
      namespace:selected.namespace,endpoint:selected.endpoint,scope:selected.scope,network_accessed:false,mutation_submitted:false,complete:false};
  }catch(cause){
    const e=cause instanceof Error?cause:new Error('branch_bootstrap_interrupted');
    e.bootstrap_progress={workdir:root,plan_sha256:confirm,directory_created:created,complete:false};throw e;
  }finally{life.close();}
}
function joinOutcome(before, after, scope) {
  if(!after)return before;
  const next=validateOutcomeReply(after,scope);if(!before)return next;
  try{return validateOutcomeReply(next,scope,before);}
  catch{try{validateOutcomeReply(before,scope,next);return before;}catch{fail('outcome_conflict');}}
}
function observation(raw, request) {
  fields(raw,['outcome','publication','dispatched']);
  if(typeof raw.dispatched!=='boolean')fail('dispatched');
  const outcome=raw.outcome===null?null:validateOutcomeReply(raw.outcome,outcomeBinding(request.scope));
  const pub=raw.publication===null?null:publication(raw.publication,request,raw.publication.outcome==='committed'?200:409);
  matchOutcome(outcome,pub);return {outcome,publication:pub,dispatched:raw.dispatched};
}
export function position(state) {
  const index=state.steps.findIndex(s=>s.outcome?.state!=='committed');
  return index===-1?state.steps.length:index;
}
export async function journal(loaded, life, synchronize=false) {
  const root=join(loaded.root,'journal'), reader=synchronize?readSynchronizedOperatorRecord:readPrivateOperatorFile;
  await guard(loaded);const names=await inventory(root,L.attempts+1,life.check);
  if(names.length>L.attempts||names.some((n,i)=>n!==attemptName(i)))fail('journal_gap');
  const state={steps:loaded.requests.map(()=>({attempts:0,outcome:null,publication:null})),attempts:0,unsettled:0,bytes:0,tip:loaded.confirm};
  for(const [i,name] of names.entries()){
    life.check();await guard(loaded);const dir=join(root,name),id=await directory(dir);
    const entries=await inventory(dir,3,life.check);
    if(!isDeepStrictEqual(entries,['started.json'])&&!isDeepStrictEqual(entries,['result.json','started.json']))fail('attempt_inventory');
    const startBytes=await reader(join(dir,'started.json'),1024,life.check), start=canonical(startBytes);
    fields(start,['schema','plan_sha256','sequence','previous_sha256','step','key','operation']);
    if(start.schema!=='frankengit-branch-bootstrap-attempt-v1'||start.plan_sha256!==loaded.confirm||start.sequence!==i+1||start.previous_sha256!==state.tip)fail('attempt_chain');
    bounded(start.step,0,loaded.requests.length-1);const step=state.steps[start.step],request=loaded.requests[start.step];
    if(start.key!==request.key||!['send','retry','recover'].includes(start.operation)||start.step>position(state))fail('attempt_step');
    if(start.operation==='send'?step.attempts!==0:step.attempts===0)fail('attempt_operation');
    if(++step.attempts>L.perBranch)fail('attempt_limit');state.attempts++;state.tip=hash(startBytes);state.bytes+=startBytes.length;
    if(entries.length===1){state.unsettled++;state.bytes+=L.result;}
    else{
      const resultBytes=await reader(join(dir,'result.json'),L.result,life.check), r=canonical(resultBytes);
      fields(r,['schema','started_sha256','observation','error']);
      if(r.schema!=='frankengit-branch-bootstrap-result-v1'||r.started_sha256!==state.tip)fail('result_binding');
      if(r.error!==null){fields(r.error,['code','phase']);if(typeof r.error.code!=='string'||!/^[a-z_]{1,128}$/.test(r.error.code)||!['preflight','publication','confirmation'].includes(r.error.phase))fail('result_error');}
      const value=observation(r.observation,request);
      if(r.error===null&&value.outcome===null)fail('result_empty');
      if(start.operation==='recover'&&value.dispatched)fail('recovery_dispatched');
      if(step.publication&&value.publication&&!isDeepStrictEqual(step.publication,value.publication))fail('publication_conflict');
      step.publication??=value.publication;step.outcome=joinOutcome(step.outcome,value.outcome,outcomeBinding(request.scope));
      matchOutcome(step.outcome,step.publication);state.bytes+=resultBytes.length;
    }
    if(state.bytes>L.journalBytes)fail('journal_bytes');await directory(dir,id);
  }
  await guard(loaded);life.check();return state;
}
export async function reserve(loaded, state, index, operation, life) {
  if(state.attempts>=L.attempts||state.steps[index].attempts>=L.perBranch)fail('attempt_limit');
  const started={schema:'frankengit-branch-bootstrap-attempt-v1',plan_sha256:loaded.confirm,
    sequence:state.attempts+1,previous_sha256:state.tip,step:index,key:loaded.requests[index].key,operation};
  const bytes=encode(started);if(bytes.length>1024||state.bytes+bytes.length+L.result>L.journalBytes)fail('journal_bytes');
  life.check();await guard(loaded);const root=join(loaded.root,'journal',attemptName(state.attempts));
  await mkdir(root,{mode:0o700});const identity=await directory(root);await syncDirectory(dirname(root));
  await saveOperatorRecord(join(root,'started.json'),bytes,life.check);await guard(loaded);await directory(root,identity);life.check();
  return {root,identity,sha256:hash(bytes),started};
}
export async function finishAttempt(loaded, reservation, result, error=null) {
  // An observed terminal survives network cancellation. Drain this bounded
  // local record independently; a torn result remains an explicit refusal.
  const r={schema:'frankengit-branch-bootstrap-result-v1',started_sha256:reservation.sha256,
    observation:observation(result,loaded.requests[reservation.started.step]),
    error:error===null?null:{code:/^[a-z_]{1,128}$/.test(error.code??'')?error.code:'branch_bootstrap_operation_unavailable',phase:error.phase??'preflight'}};
  const bytes=encode(r);if(bytes.length>L.result)fail('result_bytes');
  await guard(loaded);await directory(reservation.root,reservation.identity);
  await saveOperatorRecord(join(reservation.root,'result.json'),bytes);await guard(loaded);await directory(reservation.root,reservation.identity);
}
export function summary(loaded, state) {
  const next=position(state),current=state.steps[next];
  return {type:'branch_bootstrap_status',workdir:loaded.root,plan_sha256:loaded.confirm,namespace:loaded.selection.namespace,
    branches:state.steps.length,committed:next,attempts:state.attempts,unsettled_attempts:state.unsettled,
    current:next===state.steps.length?null:{index:next,key:loaded.requests[next].key,ref:loaded.requests[next].ref,
      new_commit:loaded.requests[next].new_commit,attempts:current.attempts,outcome:current.outcome,publication:current.publication},
    state:next===state.steps.length?'complete':current.outcome?.state==='refused'?'refused':current.attempts?'unresolved':'ready',
    complete:next===state.steps.length,atomic_batch:false,current_ref_state_verified:false,git_objects_imported:false};
}
