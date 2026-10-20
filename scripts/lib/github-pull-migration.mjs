// FG-049: compose complete collections and existing native request batches.
// Child request slots and journals remain the only mutation/recovery machinery.
import { mkdir, opendir, lstat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { pullFields, pullU64, pullTokenFingerprint } from '../operator/pull_command.mjs';
import { readPullToken, privatePullDirectory } from '../operator/pull_files.mjs';
import { directory, readPrivate, writeNew, syncDirectory, encode, digest, pin, safePath, number }
  from './forge-pull-archive-store.mjs';
import { loadGithubPullCollection, collectionGuard, collectionRead, collectionLifetime, batchName }
  from './github-pull-collection-store.mjs';
import { parseGithubPullCapture } from './github-pull-source.mjs';
import { githubPullImportSelection, compileGithubPullImport } from './github-pull-import-plan.mjs';
import { prepareGithubPullImport, loadGithubPullImport, executeGithubPullImport,
  githubPullBranchRequirements } from './github-pull-import.mjs';
import { readImportJournal } from './native-pull-import-journal.mjs';

export const GITHUB_PULL_MIGRATION_LIMITS = Object.freeze({ steps:32768, requestBytes:128*1024*1024,
  manifestBytes:4*1024*1024, batches:10000 });
const L=GITHUB_PULL_MIGRATION_LIMITS, SCHEMA='frankengit-github-pull-migration-v1';
const fail=code=>{const e=new Error(`github_pull_migration_${code}`);e.code=e.message;throw e;};
const slot=i=>`batch-${String(i+1).padStart(6,'0')}`;
const config=life=>({timeoutMs:life.remaining(),signal:life.signal});
const childLife=life=>({check:life.check,signal:life.signal,timeout:life.remaining()});
async function inventory(path,names,life) {
  const expected=new Set(names);
  for await(const entry of await opendir(path)){life.check();if(!expected.delete(entry.name))fail('unexpected_file');}
  if(expected.size)fail('missing_file');
}
function selectionAt(selection,first) {
  return githubPullImportSelection({...selection,number_start:pullU64(String(BigInt(selection.number_start)+BigInt(first)),1n)});
}
function window(selection,count) {
  if(count)pullU64(String(BigInt(selection.number_start)+BigInt(count)-1n),1n);
}
async function captureAt(source,index,life) {
  life.check();await collectionGuard(source);
  const bytes=await collectionRead(join(source.root,'captures',batchName(index)),1024*1024,life);
  if(bytes.length!==source.rows[index].bytes||digest(bytes)!==source.rows[index].capture_sha256)fail('source_changed');
  return {bytes,capture:parseGithubPullCapture(bytes)};
}
// The independently retained completion pin binds all source bytes, not merely
// an inventory's names. Compile EVERY batch before creating any destination key.
async function preflight(source,selection,maxSteps,maxBytes,life) {
  window(selection,source.pulls);let steps=0,bytes=0;
  for(let i=0;i<source.rows.length;i++) {
    const {capture}=await captureAt(source,i,life);
    const compiled=compileGithubPullImport(capture,selectionAt(selection,i*source.inventory.batch_size));
    steps+=compiled.steps.length;bytes+=compiled.encodedBytes;
    if(steps>maxSteps||bytes>maxBytes)fail('plan_capacity');
  }
  return steps;
}
async function copyCollection(source,target,life) {
  await mkdir(target,{mode:0o700});
  for(const part of ['captures','journal'])await mkdir(join(target,part),{mode:0o700});
  await syncDirectory(target);await syncDirectory(dirname(target));
  for(const name of ['plan.json','inventory.json']) {
    life.check();await collectionGuard(source);
    const bytes=await collectionRead(join(source.root,name),1024*1024,life);
    if(digest(bytes)!==(name==='plan.json'?source.confirm:source.plan.inventory_sha256))fail('source_changed');
    await writeNew(join(target,name),bytes);
  }
  for(let i=0;i<source.rows.length;i++) {
    const {bytes}=await captureAt(source,i,life);await writeNew(join(target,'captures',batchName(i)),bytes);
    const checkpoint=await collectionRead(join(source.root,'journal',batchName(i)),1024,life);
    await writeNew(join(target,'journal',batchName(i)),checkpoint);
  }
  life.check();await collectionGuard(source);
  const complete=await collectionRead(join(source.root,'complete.json'),1024,life);
  if(digest(complete)!==source.completeSha)fail('source_changed');
  await writeNew(join(target,'complete.json'),complete);
  // This also checks every copied checkpoint against the original completion.
  return loadGithubPullCollection(target,source.confirm,life,true,source.completeSha);
}
function manifest(value) {
  pullFields(value,['schema','collection_plan_sha256','collection_complete_sha256','selection','credential_fingerprint',
    'max_steps','max_request_bytes','pulls','steps','request_bytes','batches']);
  if(value.schema!==SCHEMA)fail('schema');
  for(const key of ['collection_plan_sha256','collection_complete_sha256','credential_fingerprint'])pin(value[key]);
  if(!isDeepStrictEqual(githubPullImportSelection(value.selection),value.selection))fail('selection');
  number(value.max_steps,1,L.steps,'migration_steps');number(value.max_request_bytes,1,L.requestBytes,'migration_bytes');
  number(value.pulls,0,10000,'migration_pulls');number(value.steps,0,value.max_steps,'migration_steps');
  number(value.request_bytes,0,value.max_request_bytes,'migration_bytes');window(value.selection,value.pulls);
  if(!Array.isArray(value.batches)||value.batches.length>L.batches)fail('batches');
  for(const [i,row] of value.batches.entries()) {
    pullFields(row,['batch','first_index','pulls','plan_sha256','capture_sha256','steps','request_bytes']);
    if(row.batch!==i+1)fail('batch_order');
    number(row.first_index,0,9999,'migration_index');number(row.pulls,1,100,'migration_pulls');
    pin(row.plan_sha256);pin(row.capture_sha256);number(row.steps,1,8192,'migration_steps');
    number(row.request_bytes,1,64*1024*1024,'migration_bytes');
  }
  return value;
}
function progress(child,journal) {
  const at=journal.current,intent=child.intents[at],state=journal.states[at],complete=at===child.intents.length;
  return {complete,state:complete?'complete':state.outcome?.state==='refused'?'refused':state.attempts?'pending':'ready',
    steps:child.intents.length,committed_steps:at,attempts:journal.attempts,
    unsettled_attempts:journal.states.reduce((n,s)=>n+s.unsettled,0),
    current:intent?{step:at+1,number:intent.number,action:intent.action,key:intent.key,attempts:state.attempts,
      outcome:state.outcome?.state??null,publication:state.publication?.outcome??null,last_error:state.error}:null};
}
function order(states) {
  const at=states.findIndex(s=>!s.complete),current=at<0?states.length:at;
  if(states.slice(current+1).some(s=>s.attempts!==0))fail('crossed_unresolved_batch');
  return current;
}
async function contents(root,m,life,sealed,synchronize) {
  const identity=await directory(root);await privatePullDirectory(root);
  await inventory(root,['collection','batches',...(sealed?['manifest.json']:[])],life);
  const source=await loadGithubPullCollection(join(root,'collection'),m.collection_plan_sha256,life,synchronize,m.collection_complete_sha256);
  if(source.pulls!==m.pulls||source.rows.length!==m.batches.length)fail('source_partition');
  const children=join(root,'batches'),childrenIdentity=await directory(children);
  await inventory(children,m.batches.map((_,i)=>slot(i)),life);
  const states=[],identities=[];let steps=0,bytes=0;
  for(const [i,row] of m.batches.entries()) {
    life.check();await directory(root,identity);await directory(children,childrenIdentity);
    if(row.first_index!==i*source.inventory.batch_size||row.pulls!==source.rows[i].pulls||
        row.capture_sha256!==source.rows[i].capture_sha256)fail('batch_partition');
    const child=await loadGithubPullImport(join(children,slot(i)),row.plan_sha256,childLife(life),synchronize),cm=child.manifest;
    if(cm.capture_sha256!==row.capture_sha256||cm.credential_fingerprint!==m.credential_fingerprint||
        !isDeepStrictEqual(cm.selection,selectionAt(m.selection,row.first_index))||cm.step_count!==row.steps||
        cm.request_bytes!==row.request_bytes||child.compiled.mapping.length!==row.pulls)fail('child_plan_changed');
    steps+=row.steps;bytes+=row.request_bytes;
    if(steps>m.max_steps||bytes>m.max_request_bytes)fail('plan_capacity');
    const journal=await readImportJournal(child,childLife(life),synchronize);
    states.push(progress(child,journal));identities.push(child.identity);
  }
  if(steps!==m.steps||bytes!==m.request_bytes)fail('plan_totals');
  order(states);life.check();await directory(root,identity);await directory(children,childrenIdentity);
  return {root,identity,childrenIdentity,identities,manifest:m,source:source.inventory.source,states};
}
export async function loadGithubPullMigration(root,confirm,life,synchronize=false) {
  safePath(root);pin(confirm);life.check();const identity=await directory(root);
  const bytes=await readPrivate(join(root,'manifest.json'),L.manifestBytes,synchronize,life.check);
  if(digest(bytes)!==confirm)fail('plan_pin');
  const m=manifest(JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes)));
  if(!encode(m).equals(bytes))fail('manifest_encoding');
  const loaded=await contents(root,m,life,true,synchronize);await directory(root,identity);
  return {...loaded,confirm};
}
function summary(loaded,operations=0,dispatched=0,network=false) {
  const {manifest:m,states}=loaded,at=order(states),complete=at===states.length,current=states[at];
  return {type:'github_pull_migration',schema_version:1,workdir:loaded.root,plan_sha256:loaded.confirm,
    collection_complete_sha256:m.collection_complete_sha256,source:loaded.source,destination:m.selection.endpoint,
    scope:m.selection.scope,total_pulls:m.pulls,total_batches:states.length,committed_batches:at,
    steps:m.steps,committed_steps:states.reduce((n,s)=>n+s.committed_steps,0),
    attempts:states.reduce((n,s)=>n+s.attempts,0),unsettled_attempts:states.reduce((n,s)=>n+s.unsettled_attempts,0),
    request_bytes:m.request_bytes,state:complete?'complete':current.state,
    current:current?{batch:at+1,plan_sha256:m.batches[at].plan_sha256,...current.current}:null,
    complete,new_operations:operations,mutations_dispatched:dispatched,network_accessed:network,
    mutation_submitted:dispatched>0,atomic_migration:false,canonical_restore:false,approvals_imported:false,refs_changed:false};
}
export async function prepareGithubPullMigration(raw) {
  const required=['workdir','collectionDir','collectionConfirm','completeConfirm','selection','tokenFile'];
  pullFields(raw,[...required,'maxSteps','maxRequestBytes','timeoutMs','signal'],required);
  const o={...raw,workdir:safePath(raw.workdir),collectionDir:safePath(raw.collectionDir),
    collectionConfirm:pin(raw.collectionConfirm),completeConfirm:pin(raw.completeConfirm),
    selection:githubPullImportSelection(raw.selection),tokenFile:safePath(raw.tokenFile),
    maxSteps:number(raw.maxSteps??L.steps,1,L.steps,'migration_steps'),
    maxRequestBytes:number(raw.maxRequestBytes??L.requestBytes,1,L.requestBytes,'migration_bytes')};
  const life=collectionLifetime(o);let created=false,confirm=null,prepared=0;
  try {
    life.check();await privatePullDirectory(dirname(o.workdir));
    try{await lstat(o.workdir);fail('workdir_exists');}catch(e){if(e.code!=='ENOENT')throw e;}
    const original=await loadGithubPullCollection(o.collectionDir,o.collectionConfirm,life,false,o.completeConfirm);
    const expectedSteps=await preflight(original,o.selection,o.maxSteps,o.maxRequestBytes,life);
    const credential=pullTokenFingerprint(await readPullToken(o.tokenFile));life.check();
    await mkdir(o.workdir,{mode:0o700});created=true;await syncDirectory(dirname(o.workdir));const identity=await directory(o.workdir);
    const source=await copyCollection(original,join(o.workdir,'collection'),life);
    await mkdir(join(o.workdir,'batches'),{mode:0o700});await syncDirectory(o.workdir);
    const rows=[];let steps=0,bytes=0;
    for(let i=0;i<source.rows.length;i++) {
      life.check();await directory(o.workdir,identity);
      const first=i*source.inventory.batch_size;
      const child=await prepareGithubPullImport({workdir:join(o.workdir,'batches',slot(i)),
        captureFile:join(source.root,'captures',batchName(i)),captureConfirm:source.rows[i].capture_sha256,
        selection:selectionAt(o.selection,first),tokenFile:o.tokenFile,...config(life)});
      prepared++;steps+=child.steps;bytes+=child.request_bytes;
      if(steps>o.maxSteps||bytes>o.maxRequestBytes)fail('plan_capacity');
      rows.push({batch:i+1,first_index:first,pulls:source.rows[i].pulls,plan_sha256:child.plan_sha256,
        capture_sha256:source.rows[i].capture_sha256,steps:child.steps,request_bytes:child.request_bytes});
    }
    if(steps!==expectedSteps)fail('plan_changed');
    const m=manifest({schema:SCHEMA,collection_plan_sha256:o.collectionConfirm,collection_complete_sha256:o.completeConfirm,
      selection:o.selection,credential_fingerprint:credential,max_steps:o.maxSteps,max_request_bytes:o.maxRequestBytes,
      pulls:source.pulls,steps,request_bytes:bytes,batches:rows});
    const bytesRoot=encode(m);confirm=digest(bytesRoot);if(bytesRoot.length>L.manifestBytes)fail('manifest_limit');
    const loaded=await contents(o.workdir,m,life,false,true);
    if(loaded.states.some(s=>s.attempts))fail('preparation_already_attempted');
    life.check();await directory(o.workdir,identity);await writeNew(join(o.workdir,'manifest.json'),bytesRoot);
    return {...summary({...loaded,confirm}),type:'github_pull_migration_prepared',preparation_complete:true};
  } catch(cause) {
    const e=cause instanceof Error?cause:new Error('github_pull_migration_interrupted');
    e.migration_progress={workdir:o.workdir,directory_created:created,plan_sha256:confirm,prepared_batches:prepared,
      preparation_complete:false,mutation_submitted:false};throw e;
  } finally{life.close();}
}
export async function executeGithubPullMigration(raw) {
  const required=['workdir','confirm','operation'];
  pullFields(raw,[...required,'tokenFile','caFile','retryKey','maxOperations','timeoutMs','signal'],required);
  const o={...raw,workdir:safePath(raw.workdir),confirm:pin(raw.confirm)};
  if(!['run','recover','status'].includes(o.operation)||o.operation!=='run'&&o.retryKey!==undefined||
      o.operation==='status'&&['tokenFile','caFile','maxOperations'].some(k=>o[k]!==undefined))fail('execution_options');
  if(o.retryKey!==undefined&&(typeof o.retryKey!=='string'||!/^fgp1-[0-9a-f]{32}-[0-9a-f]{64}$/.test(o.retryKey)))fail('retry_key');
  const max=number(o.maxOperations??100,1,8192,'migration_operations'),life=collectionLifetime(o);
  let loaded,operations=0,dispatched=0,network=false;
  try {
    loaded=await loadGithubPullMigration(o.workdir,o.confirm,life,o.operation!=='status');
    let at=order(loaded.states),current=loaded.states[at];
    if(o.retryKey!==undefined&&(!current?.current||current.current.key!==o.retryKey||!current.current.attempts||
        current.state==='refused'))fail('retry_original_pending_key');
    if(o.operation==='status')return {...summary(loaded),local_read_only:true};
    while(at<loaded.states.length&&operations<max) {
      current=loaded.states[at];if(current.state==='refused'||o.operation==='recover'&&current.attempts===0)break;
      life.check();await directory(loaded.root,loaded.identity);await directory(join(loaded.root,'batches'),loaded.childrenIdentity);
      const path=join(loaded.root,'batches',slot(at));await directory(path,loaded.identities[at]);
      const result=await executeGithubPullImport({workdir:path,confirm:loaded.manifest.batches[at].plan_sha256,
        operation:o.operation,...(o.tokenFile===undefined?{}:{tokenFile:o.tokenFile}),...(o.caFile===undefined?{}:{caFile:o.caFile}),
        ...(o.retryKey===undefined?{}:{retryKey:o.retryKey}),maxOperations:max-operations,...config(life)});
      operations+=result.new_operations;dispatched+=result.mutations_dispatched;network ||= result.network_accessed;
      loaded.states[at]=result;
      // The original child executor owns terminal interpretation and local drain.
      // A confirmed prefix is retained evidence; status always does a fresh read.
      if(!result.complete||o.operation==='recover')break;
      at++;delete o.retryKey; // Consent was for the original pending key only.
    }
    return summary(loaded,operations,dispatched,network);
  } catch(cause) {
    const e=cause instanceof Error?cause:new Error('github_pull_migration_interrupted');
    e.migration_progress={workdir:o.workdir,plan_sha256:o.confirm,plan_verified:Boolean(loaded),
      new_operations:operations,mutations_dispatched:dispatched,outcome_unknown:true,complete:false};throw e;
  } finally{life.close();}
}
export async function githubPullMigrationBatch(raw) {
  pullFields(raw,['workdir','confirm','batch','principal','timeoutMs','signal'],['workdir','confirm','batch']);
  const o={...raw,workdir:safePath(raw.workdir),confirm:pin(raw.confirm)},life=collectionLifetime(o);
  try {
    const loaded=await loadGithubPullMigration(o.workdir,o.confirm,life),index=number(o.batch,1,loaded.manifest.batches.length,'migration_batch')-1;
    const row=loaded.manifest.batches[index],workdir=join(o.workdir,'batches',slot(index));
    const requirements=o.principal===undefined?{}:await githubPullBranchRequirements({workdir,confirm:row.plan_sha256,principal:o.principal,...config(life)});
    return {...requirements,type:'github_pull_migration_batch',migration_sha256:o.confirm,batch:o.batch,
      workdir,plan_sha256:row.plan_sha256,capture_sha256:row.capture_sha256,pulls:row.pulls,
      destination_number_start:selectionAt(loaded.manifest.selection,row.first_index).number_start,
      network_accessed:false,mutation_submitted:false};
  } finally{life.close();}
}
