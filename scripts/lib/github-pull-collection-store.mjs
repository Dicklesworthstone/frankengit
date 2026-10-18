// Immutable capture custody, not GitHub snapshot authority or native retry state.
import { constants } from 'node:fs';
import { open, lstat, realpath, opendir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
import { operatorPath, readPrivateOperatorFile, readSynchronizedOperatorRecord, recordDigest } from './forge-operator-io.mjs';
import { parseGithubPullInventory, GITHUB_PULL_INVENTORY_LIMITS as I } from './github-pull-inventory.mjs';
import { parseGithubPullCapture, GITHUB_PULL_LIMITS as C, pullSourceFields as fields,
  pullSourceNumber as integer, encodeGithubPulls as encode, githubPullFail as fail } from './github-pull-source.mjs';

export { encode, fields, integer, fail, recordDigest as hash };
export const COLLECTION_LIMITS = Object.freeze({ bytes:64*1024*1024, records:200000, control:1024 });
const L=COLLECTION_LIMITS;
export const COLLECTION_SCHEMA='frankengit-github-pull-collection-v1';
export const batchName=index=>`batch-${String(index+1).padStart(6,'0')}.json`;
export function collectionPin(v) { if(typeof v!=='string'||!/^[0-9a-f]{64}$/.test(v))fail('collection_pin');return v; }
export function collectionPath(v) {
  const path=operatorPath(v);if(path!==v)fail('collection_absolute_path');return path;
}
export async function collectionDirectory(path,expected=null) {
  const s=await lstat(path,{bigint:true});
  if(typeof process.getuid!=='function'||!s.isDirectory()||s.uid!==BigInt(process.getuid())||(s.mode&0o077n)!==0n||
      await realpath(path)!==path||expected&&(s.dev!==expected.dev||s.ino!==expected.ino))fail('collection_directory');
  return s;
}
export async function outsideWorktree(path) {
  collectionPath(path);
  for(let at=path;;at=dirname(at)) {
    if(at.split('/').includes('.git'))fail('collection_worktree');
    try{await lstat(join(at,'.git'));fail('collection_worktree');}catch(e){if(e.code!=='ENOENT'&&e.code!=='ENOTDIR')throw e;}
    if(dirname(at)===at)break;
  }
  return path;
}
export async function syncCollectionDirectory(path) {
  const fd=await open(path,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
  try{await fd.sync();}finally{await fd.close();}
}
export function collectionLifetime(raw) {
  const timeout=integer(raw.timeoutMs??300000,1,300000);
  if(raw.signal!==undefined&&!(raw.signal instanceof AbortSignal))fail('collection_signal');
  const stop=new AbortController(),signal=raw.signal?AbortSignal.any([raw.signal,stop.signal]):stop.signal,deadline=performance.now()+timeout;
  const timer=setTimeout(()=>stop.abort(),timeout);
  const check=()=>{if(performance.now()>=deadline)stop.abort();signal.throwIfAborted();};
  return {signal,check,remaining(){check();return Math.max(1,Math.ceil(deadline-performance.now()));},close(){clearTimeout(timer);stop.abort();}};
}
function plan(raw) {
  fields(raw,['schema','inventory_sha256','batches','max_capture_bytes','max_records']);
  if(raw.schema!==COLLECTION_SCHEMA)fail('collection_schema');collectionPin(raw.inventory_sha256);
  integer(raw.batches,0,I.pulls);integer(raw.max_capture_bytes,1,L.bytes);integer(raw.max_records,0,L.records);
  return raw;
}
export function collectionPlan(inventory,inventorySha,raw) {
  return plan({schema:COLLECTION_SCHEMA,inventory_sha256:collectionPin(inventorySha),batches:Math.ceil(inventory.pulls.length/inventory.batch_size),
    max_capture_bytes:raw.maxCaptureBytes??L.bytes,max_records:raw.maxRecords??L.records});
}
function json(bytes) {
  const value=JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes));
  if(!encode(value).equals(bytes))fail('collection_encoding');return value;
}
export async function collectionRead(path,maximum,life,sync=false) {
  return sync?readSynchronizedOperatorRecord(path,maximum,life.check):readPrivateOperatorFile(path,maximum,life.check);
}
async function names(path,maximum,life) {
  const result=[];
  for await(const entry of await opendir(path)){life.check();if(!/^batch-[0-9]{6}\.json$/.test(entry.name)||result.length>=maximum)fail('collection_inventory');result.push(entry.name);}
  result.sort();if(result.some((s,i)=>s!==batchName(i)))fail('collection_gap');return result;
}
export function collectionSelection(loaded,index) {
  integer(index,0,loaded.plan.batches-1);
  const first=index*loaded.inventory.batch_size;
  return {source:loaded.inventory.source,pulls:loaded.inventory.pulls.slice(first,first+loaded.inventory.batch_size)};
}
// A new invocation verifies every body and checkpoint. These sets are owned by
// the loader/collector, never supplied by an untrusted file or public option.
export function collectionCapture(loaded,index,bytes) {
  const capture=parseGithubPullCapture(bytes),expected=collectionSelection(loaded,index);
  if(!isDeepStrictEqual(capture.source,expected.source)||!isDeepStrictEqual(capture.pulls.map(e=>({number:e.pull.number,id:e.pull.id})),expected.pulls))fail('collection_capture_selection');
  let records=0;
  for(const e of capture.pulls)for(const kind of ['discussion','reviews','inline'])for(const row of e[kind]) {
    if(loaded.seen[kind].has(row.id))fail('collection_duplicate_record');loaded.seen[kind].add(row.id);records++;
  }
  if(loaded.bytes+bytes.length>loaded.plan.max_capture_bytes||loaded.records+records>loaded.plan.max_records)fail('collection_capacity');
  return {capture_sha256:recordDigest(bytes),bytes:bytes.length,pulls:capture.pulls.length,records};
}
export function collectionCheckpoint(loaded,index,previous,desc) {
  const bytes=encode({schema:'frankengit-github-pull-batch-checkpoint-v1',plan_sha256:loaded.confirm,batch:index+1,previous_sha256:previous,...desc});
  if(bytes.length>L.control)fail('collection_checkpoint_limit');return bytes;
}
export function completeCollectionBytes(loaded) {
  if(loaded.tail||loaded.rows.length!==loaded.plan.batches)fail('collection_incomplete');
  return encode({schema:'frankengit-github-pull-collection-complete-v1',plan_sha256:loaded.confirm,inventory_sha256:loaded.plan.inventory_sha256,
    checkpoint_sha256:loaded.tip,batches:loaded.rows.length,pulls:loaded.pulls,records:loaded.records,capture_bytes:loaded.bytes,
    consistency:'independent-two-equal-batches-not-atomic',complete:true});
}
export async function collectionGuard(loaded) {
  await collectionDirectory(loaded.root,loaded.identity);
  await collectionDirectory(join(loaded.root,'captures'),loaded.capturesId);
  await collectionDirectory(join(loaded.root,'journal'),loaded.journalId);
}
export async function loadGithubPullCollection(root,confirm,life,sync=false,completeConfirm=null) {
  collectionPath(root);collectionPin(confirm);if(completeConfirm!==null)collectionPin(completeConfirm);life.check();
  const identity=await collectionDirectory(root);await outsideWorktree(root);
  const rootNames=new Set(['plan.json','inventory.json','captures','journal']);let sealed=false;
  for await(const entry of await opendir(root)) {
    life.check();if(entry.name==='complete.json'){sealed=true;continue;}if(!rootNames.delete(entry.name))fail('collection_unexpected_file');
  }
  if(rootNames.size)fail('collection_missing_file');
  const bytes=await collectionRead(join(root,'plan.json'),L.control,life,sync);
  if(recordDigest(bytes)!==confirm)fail('collection_pin_mismatch');const selected=plan(json(bytes));
  const inventoryBytes=await collectionRead(join(root,'inventory.json'),I.bytes,life,sync);
  if(recordDigest(inventoryBytes)!==selected.inventory_sha256)fail('collection_inventory_pin');
  const inventory=parseGithubPullInventory(inventoryBytes);
  if(selected.batches!==Math.ceil(inventory.pulls.length/inventory.batch_size))fail('collection_partition');
  const capturesId=await collectionDirectory(join(root,'captures')),journalId=await collectionDirectory(join(root,'journal'));
  const data=await names(join(root,'captures'),selected.batches,life),saved=await names(join(root,'journal'),selected.batches,life);
  if(saved.length>data.length||data.length>saved.length+1)fail('collection_checkpoint_gap');
  const loaded={root,confirm,identity,capturesId,journalId,plan:selected,inventory,rows:[],bytes:0,records:0,pulls:0,tip:confirm,
    tail:null,completeSha:null,seen:{discussion:new Set(),reviews:new Set(),inline:new Set()}};
  for(let i=0;i<data.length;i++) {
    life.check();await collectionGuard(loaded);
    const raw=await collectionRead(join(root,'captures',data[i]),C.bytes,life,sync),desc=collectionCapture(loaded,i,raw);
    const expected=collectionCheckpoint(loaded,i,loaded.tip,desc);
    if(i<saved.length) {
      const checkpoint=await collectionRead(join(root,'journal',saved[i]),L.control,life,sync);
      if(!checkpoint.equals(expected))fail('collection_checkpoint_changed');loaded.tip=recordDigest(checkpoint);
    } else loaded.tail={index:i,raw,checkpoint:expected};
    loaded.rows.push(desc);loaded.bytes+=raw.length;loaded.records+=desc.records;loaded.pulls+=desc.pulls;
  }
  if(sealed) {
    const expected=completeCollectionBytes(loaded),raw=await collectionRead(join(root,'complete.json'),L.control,life,sync);
    if(!raw.equals(expected))fail('collection_complete_changed');loaded.completeSha=recordDigest(raw);
  }
  if(completeConfirm!==null&&loaded.completeSha!==completeConfirm)fail('collection_complete_pin');
  life.check();await collectionGuard(loaded);return loaded;
}
export function collectionSummary(loaded) {
  return {type:'github_pull_collection',workdir:loaded.root,plan_sha256:loaded.confirm,inventory_sha256:loaded.plan.inventory_sha256,
    source:loaded.inventory.source,total_pulls:loaded.inventory.pulls.length,total_batches:loaded.plan.batches,
    captured_batches:loaded.rows.length,checkpointed_batches:loaded.rows.length-(loaded.tail?1:0),captured_pulls:loaded.pulls,
    records:loaded.records,capture_bytes:loaded.bytes,max_capture_bytes:loaded.plan.max_capture_bytes,max_records:loaded.plan.max_records,
    checkpoint_sha256:loaded.tip,complete_sha256:loaded.completeSha,
    next_batch:loaded.tail?loaded.tail.index+1:loaded.rows.length<loaded.plan.batches?loaded.rows.length+1:null,
    uncheckpointed_batch:loaded.tail?loaded.tail.index+1:null,ready_to_seal:!loaded.completeSha&&!loaded.tail&&loaded.rows.length===loaded.plan.batches,
    complete:loaded.completeSha!==null,atomic_snapshot:false,mutation_submitted:false};
}
