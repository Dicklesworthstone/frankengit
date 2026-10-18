#!/usr/bin/env node
// Read-only repository PR discovery and capture. Destination migration is explicit.
import { dirname, join } from 'node:path';
import { lstat } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { discoverGithubPulls, parseGithubPullInventory, selectGithubPullBatch, captureGithubPullBatch,
  GITHUB_PULL_INVENTORY_LIMITS as L } from './lib/github-pull-inventory.mjs';
import { operatorPath, privateRecordPath, absentRecord, readPrivateOperatorFile, saveOperatorRecord,
  recordDigest, operatorJson, operatorError } from './lib/forge-operator-io.mjs';

const HELP = `usage: node scripts/discover_github_pulls.mjs discover --repository OWNER/REPO --out NEW_PRIVATE_FILE
       node scripts/discover_github_pulls.mjs inspect --inventory PRIVATE_FILE --confirm INVENTORY_SHA256 [--batch N]
       node scripts/discover_github_pulls.mjs capture-batch --inventory PRIVATE_FILE --confirm INVENTORY_SHA256 --batch N --out NEW_CAPTURE
All: [--timeout-ms 1..300000]. Source reads: [--token-file PRIVATE_TOKEN]
[--max-requests 1..4096] [--max-read-bytes 1..268435456].
discover: [--batch-size 1..100] (default 25), [--max-pulls 1..10000].
Membership and partition are pinned, not an atomic GitHub snapshot. Captures retain
all existing per-batch limits. No native mutation, automatic retry or source URL override.
Use the resulting ordinary capture with migrate_github_pulls.mjs prepare.
Exit 0: success; 2: refusal; 4: retained/potentially published custody or output error.`;
const fail = code => { throw operatorError(`github_pull_inventory_${code}`); };
const decimal = value => {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value))) fail('arguments');
  return Number(value);
};
function parse(args) {
  if (!Array.isArray(args) || args.length>40 || args.some(v=>typeof v!=='string'||v.length>4096) ||
      args.reduce((n,s)=>n+s.length,0)>32768) fail('arguments');
  const operation = args[0], definitions = {
    discover: [['--repository','--out'],['--batch-size','--max-pulls']],
    inspect: [['--inventory','--confirm'],['--batch']],
    'capture-batch': [['--inventory','--confirm','--batch','--out'],[]],
  };
  if (!Object.hasOwn(definitions,operation)) fail('command');
  const [required, optional] = definitions[operation], allowed = new Set([...required,...optional,'--timeout-ms',
    ...(operation==='inspect'?[]:['--token-file','--max-requests','--max-read-bytes'])]), flags = new Map();
  for (let i=1;i<args.length;) {
    const key=args[i++], value=args[i++];
    if (!allowed.has(key) || flags.has(key) || value===undefined || value.startsWith('--')) fail('arguments');
    flags.set(key,value);
  }
  if (required.some(k=>!flags.has(k))) fail('arguments');
  const timeoutMs=decimal(flags.get('--timeout-ms')??'300000'); if(timeoutMs<1||timeoutMs>300000) fail('timeout');
  return {operation,flags,timeoutMs};
}
async function externalPath(value) {
  const path=operatorPath(value);
  for(let cursor=dirname(path);;cursor=dirname(cursor)) {
    if(cursor.split('/').includes('.git')) fail('worktree');
    try{await lstat(join(cursor,'.git'));fail('worktree');}catch(e){if(e.code!=='ENOENT')throw e;}
    if(dirname(cursor)===cursor)break;
  }
  return path;
}
async function output(stream, value, wait) {
  const text=operatorJson(value); if(Buffer.byteLength(text)>L.bytes) fail('output_limit');
  await new Promise((resolve,reject)=>{
    let settled=false; const finish=error=>{if(settled)return;settled=true;clearTimeout(timer);
      setImmediate(()=>{stream.removeListener?.('error',onError);error?reject(error):resolve();});};
    const onError=error=>finish(error),timer=setTimeout(()=>finish(operatorError('github_pull_inventory_output_deadline')),wait);
    stream.once?.('error',onError);try{stream.write(text,finish);}catch(e){finish(e);}
  });
}
export async function main(args,{stdout=process.stdout,stderr=process.stderr,signal}={}) {
  const stop=new AbortController(),abort=()=>stop.abort(),combined=signal?AbortSignal.any([signal,stop.signal]):stop.signal;
  process.on('SIGTERM',abort);process.on('SIGINT',abort);let timer,result,pending;
  try {
    if(args.length===1&&args[0]==='--help'){await output(stdout,{usage:HELP},10000);return 0;}
    const {operation,flags:f,timeoutMs}=parse(args),deadline=performance.now()+timeoutMs;
    timer=setTimeout(abort,timeoutMs);
    const check=()=>{combined.throwIfAborted();if(performance.now()>=deadline)fail('deadline');};
    const remaining=()=>{check();return Math.max(1,Math.ceil(deadline-performance.now()));};
    let inventory,confirm,path;
    if(operation!=='discover') {
      const bytes=await readPrivateOperatorFile(await externalPath(f.get('--inventory')),L.bytes,check);
      confirm=f.get('--confirm');if(!/^[0-9a-f]{64}$/.test(confirm??'')||recordDigest(bytes)!==confirm)fail('pin_mismatch');
      inventory=parseGithubPullInventory(bytes);
    }
    if(operation==='inspect') {
      result={type:'github_pull_inventory_inspected',inventory_sha256:confirm,source:inventory.source,
        pulls:inventory.pulls.length,batch_size:inventory.batch_size,total_batches:Math.ceil(inventory.pulls.length/inventory.batch_size),
        ...(f.has('--batch')?{selection:selectGithubPullBatch(inventory,confirm,decimal(f.get('--batch')))}:{}),
        consistency:inventory.consistency,complete:true,atomic_snapshot:false,network_accessed:false,mutation_submitted:false};
    } else {
      // Validate a requested batch before reading a token or making an HTTP call.
      const batch=operation==='capture-batch'?decimal(f.get('--batch')):null;
      if(batch!==null)selectGithubPullBatch(inventory,confirm,batch);
      path=await privateRecordPath(await externalPath(f.get('--out')));await absentRecord(path);check();let token=null;
      if(f.has('--token-file')) {
        const raw=await readPrivateOperatorFile(await externalPath(f.get('--token-file')),256,check);
        try{token=raw.toString('utf8').replace(/\n$/,'');if(!/^[A-Za-z0-9_]{1,255}$/.test(token))fail('token');}finally{raw.fill(0);}
      }
      const options={token,signal:combined,timeoutMs:remaining(),
        ...(f.has('--max-requests')?{maxRequests:decimal(f.get('--max-requests'))}:{}),
        ...(f.has('--max-read-bytes')?{maxReadBytes:decimal(f.get('--max-read-bytes'))}:{})};
      const captured=operation==='discover'?await discoverGithubPulls({...options,repository:f.get('--repository'),
        ...(f.has('--batch-size')?{batchSize:decimal(f.get('--batch-size'))}:{}),...(f.has('--max-pulls')?{maxPulls:decimal(f.get('--max-pulls'))}:{})})
        :await captureGithubPullBatch({...options,inventory,confirm,batch});
      pending={path,...(operation==='discover'?{inventory_sha256:captured.sha256}:{capture_sha256:captured.sha256,inventory_sha256:confirm,batch})};
      check();await saveOperatorRecord(path,captured.bytes,check);
      result={type:operation==='discover'?'github_pull_inventory_saved':'github_pull_batch_saved',...pending,
        pulls:operation==='discover'?captured.inventory.pulls.length:captured.capture.pulls.length,
        total_batches:captured.total_batches,...(batch===null?{}:{next_batch:captured.next_batch,first_index:captured.first_index}),
        statistics:captured.statistics,complete:true,atomic_snapshot:false,mutation_submitted:false};
    }
    await output(stdout,result,Math.min(10000,remaining()));return 0;
  } catch(error) {
    try{await output(stderr,{type:'github_pull_inventory_error',code:typeof error.code==='string'&&/^[A-Za-z0-9_]+$/.test(error.code)?error.code:'operation_failed',
      ...(pending?{retained:pending}:{}),...(result?{retained_result:result}:{}),mutation_submitted:false},10000);}catch{}
    return pending||result?4:2;
  } finally {clearTimeout(timer);process.removeListener('SIGTERM',abort);process.removeListener('SIGINT',abort);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)process.exitCode=await main(process.argv.slice(2));
