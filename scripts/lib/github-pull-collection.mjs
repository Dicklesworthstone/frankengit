// Collect a pinned GitHub population in bounded, independently verified batches.
// No native mutation, replacement request key, source refresh or damaged-file repair.
import { mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { absentRecord, saveOperatorRecord, readPrivateOperatorFile } from './forge-operator-io.mjs';
import { parseGithubPullInventory, GITHUB_PULL_INVENTORY_LIMITS as I } from './github-pull-inventory.mjs';
import { createGithubPullCaptureSession } from './github-pull-source.mjs';
import { fields, integer, fail, encode, hash, COLLECTION_LIMITS as L, collectionPath, collectionPin, collectionDirectory,
  outsideWorktree, syncCollectionDirectory, collectionLifetime, collectionPlan, collectionRead, batchName,
  loadGithubPullCollection, collectionSelection, collectionCapture, collectionCheckpoint, completeCollectionBytes,
  collectionGuard, collectionSummary } from './github-pull-collection-store.mjs';

export async function prepareGithubPullCollection(raw) {
  fields(raw,['workdir','inventoryFile','inventoryConfirm','maxCaptureBytes','maxRecords','timeoutMs','signal'],['workdir','inventoryFile','inventoryConfirm']);
  const o={...raw,workdir:collectionPath(raw.workdir),inventoryFile:collectionPath(raw.inventoryFile),inventoryConfirm:collectionPin(raw.inventoryConfirm)};
  const life=collectionLifetime(o);let created=false,confirm=null;
  try {
    life.check();await outsideWorktree(o.workdir);await collectionDirectory(dirname(o.workdir));await absentRecord(o.workdir);
    await outsideWorktree(o.inventoryFile);
    const bytes=await collectionRead(o.inventoryFile,I.bytes,life);if(hash(bytes)!==o.inventoryConfirm)fail('collection_inventory_pin');
    const inventory=parseGithubPullInventory(bytes),plan=collectionPlan(inventory,o.inventoryConfirm,o),encoded=encode(plan);confirm=hash(encoded);
    life.check();await mkdir(o.workdir,{mode:0o700});created=true;await syncCollectionDirectory(dirname(o.workdir));
    for(const name of ['captures','journal'])await mkdir(join(o.workdir,name),{mode:0o700});await syncCollectionDirectory(o.workdir);
    await saveOperatorRecord(join(o.workdir,'inventory.json'),bytes,life.check);
    await saveOperatorRecord(join(o.workdir,'plan.json'),encoded,life.check);
    return {...collectionSummary(await loadGithubPullCollection(o.workdir,confirm,life)),type:'github_pull_collection_prepared',network_accessed:false};
  } catch(cause) {
    const error=cause instanceof Error?cause:new Error('github_pull_collection_interrupted');
    error.collection_progress={workdir:o.workdir,plan_sha256:confirm,directory_created:created,complete:false};throw error;
  } finally {life.close();}
}
export async function inspectGithubPullCollection(raw) {
  fields(raw,['workdir','confirm','completeConfirm','timeoutMs','signal'],['workdir','confirm']);
  const o={...raw},life=collectionLifetime(o);
  try{return {...collectionSummary(await loadGithubPullCollection(o.workdir,o.confirm,life,false,o.completeConfirm??null)),network_accessed:false,local_read_only:true};}
  finally{life.close();}
}
export async function collectGithubPulls(raw) {
  fields(raw,['workdir','confirm','tokenFile','maxBatches','maxRequests','maxReadBytes','timeoutMs','signal','fetchImpl'],['workdir','confirm']);
  const o={...raw,workdir:collectionPath(raw.workdir),confirm:collectionPin(raw.confirm)};
  const maximum=integer(o.maxBatches??5,1,I.pulls),maxRequests=integer(o.maxRequests??4096,1,4096),maxReadBytes=integer(o.maxReadBytes??64*1024*1024,1,256*1024*1024);
  const life=collectionLifetime(o);let loaded,owner,done=0;
  try {
    loaded=await loadGithubPullCollection(o.workdir,o.confirm,life,true);
    if(!loaded.completeSha&&(loaded.tail||loaded.rows.length<loaded.plan.batches)) {
      let token=null;
      if(o.tokenFile!==undefined) {
        const path=await outsideWorktree(collectionPath(o.tokenFile)),bytes=await readPrivateOperatorFile(path,256,life.check);
        try{token=bytes.toString('utf8').replace(/\n$/,'');if(!/^[A-Za-z0-9_]{1,255}$/.test(token))fail('collection_token');}finally{bytes.fill(0);}
      }
      owner=createGithubPullCaptureSession({repository:loaded.inventory.source.full_name,token,signal:life.signal,
        timeoutMs:life.remaining(),maxRequests,maxReadBytes,...(o.fetchImpl===undefined?{}:{fetchImpl:o.fetchImpl})});
      while(done<maximum&&(loaded.tail||loaded.rows.length<loaded.plan.batches)) {
        life.check();const index=loaded.tail?loaded.tail.index:loaded.rows.length,selected=collectionSelection(loaded,index);
        const result=await owner.capture(selected.pulls.map(r=>r.number),{expectedSelection:selected});
        life.check();await collectionGuard(loaded);
        let checkpoint;
        if(loaded.tail) {
          // Valid bytes left between body sync and checkpoint publication are
          // re-observed, never adopted by existence or replaced with newer data.
          if(!result.bytes.equals(loaded.tail.raw))fail('collection_uncheckpointed_changed');
          checkpoint=loaded.tail.checkpoint;
        } else {
          const desc=collectionCapture(loaded,index,result.bytes);checkpoint=collectionCheckpoint(loaded,index,loaded.tip,desc);
          await saveOperatorRecord(join(o.workdir,'captures',batchName(index)),result.bytes,life.check);
          loaded.rows.push(desc);loaded.bytes+=result.bytes.length;loaded.records+=desc.records;loaded.pulls+=desc.pulls;
        }
        await collectionGuard(loaded);await saveOperatorRecord(join(o.workdir,'journal',batchName(index)),checkpoint,life.check);
        loaded.tip=hash(checkpoint);loaded.tail=null;done++;
      }
    }
    // Read back all retained files before reporting a batch or sealing complete.
    loaded=await loadGithubPullCollection(o.workdir,o.confirm,life,true);
    if(!loaded.completeSha&&!loaded.tail&&loaded.rows.length===loaded.plan.batches) {
      const bytes=completeCollectionBytes(loaded);if(bytes.length>L.control)fail('collection_complete_limit');
      life.check();await collectionGuard(loaded);await saveOperatorRecord(join(o.workdir,'complete.json'),bytes,life.check);
      loaded.completeSha=hash(bytes);
    }
    return {...collectionSummary(loaded),new_batches:done,network_accessed:Boolean(owner),
      statistics:owner?.statistics()??{requests:0,read_bytes:0,source_retries:0}};
  } catch(cause) {
    const error=cause instanceof Error?cause:new Error('github_pull_collection_interrupted');
    error.collection_progress={workdir:o.workdir,plan_sha256:o.confirm,plan_verified:Boolean(loaded),new_batches:done,
      checkpoint_sha256:loaded?.tip??null,statistics:owner?.statistics()??null,complete:false};throw error;
  } finally {try{owner?.close();}finally{life.close();}}
}

// Final-root consent binds captured content, not just the inventory membership.
// Offset arithmetic is exact u64 and never generates or changes a native request.
export async function selectGithubPullCollectionBatch(raw) {
  fields(raw,['workdir','confirm','completeConfirm','batch','numberStart','timeoutMs','signal'],['workdir','confirm','completeConfirm','batch']);
  const o={...raw},life=collectionLifetime(o);
  try {
    collectionPin(o.completeConfirm);
    const loaded=await loadGithubPullCollection(o.workdir,o.confirm,life,false,o.completeConfirm);
    const index=integer(o.batch,1,loaded.rows.length)-1,first=index*loaded.inventory.batch_size,desc=loaded.rows[index];
    let destination;
    if(o.numberStart!==undefined) {
      if(typeof o.numberStart!=='string'||!/^[1-9][0-9]{0,19}$/.test(o.numberStart))fail('collection_destination_number');
      const start=BigInt(o.numberStart),last=start+BigInt(loaded.inventory.pulls.length)-1n;
      if(last>18446744073709551615n)fail('collection_destination_number');destination=String(start+BigInt(first));
    }
    return {type:'github_pull_collection_batch',plan_sha256:o.confirm,complete_sha256:loaded.completeSha,
      inventory_sha256:loaded.plan.inventory_sha256,batch:index+1,total_batches:loaded.rows.length,first_index:first,
      source:loaded.inventory.source,numbers:collectionSelection(loaded,index).pulls.map(r=>r.number),
      capture_file:join(loaded.root,'captures',batchName(index)),...desc,...(destination?{destination_number_start:destination}:{}),
      complete:true,atomic_snapshot:false,network_accessed:false,mutation_submitted:false};
  } finally {life.close();}
}
