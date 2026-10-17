#!/usr/bin/env node
// Restartable source collection only. Native imports keep their own explicit plans.
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { operatorPath,operatorJson,operatorError } from './lib/forge-operator-io.mjs';
import { prepareGithubPullCollection,inspectGithubPullCollection,collectGithubPulls,selectGithubPullCollectionBatch } from './lib/github-pull-collection.mjs';

const HELP=`usage: node scripts/collect_github_pulls.mjs prepare --inventory PRIVATE_FILE --inventory-confirm INVENTORY_SHA256 --workdir NEW_JOB
       node scripts/collect_github_pulls.mjs run --workdir JOB --confirm PLAN_SHA256 [--token-file PRIVATE_GITHUB_TOKEN]
       node scripts/collect_github_pulls.mjs status --workdir JOB --confirm PLAN_SHA256 [--complete-confirm COMPLETE_SHA256]
       node scripts/collect_github_pulls.mjs batch --workdir JOB --confirm PLAN_SHA256 --complete-confirm COMPLETE_SHA256 --batch N [--number-start EXACT_U64]
prepare: [--max-capture-bytes 1..67108864] [--max-records 0..200000].
run: [--max-batches 1..10000] (default 5), [--max-requests 1..4096], [--max-read-bytes 1..268435456].
All: [--timeout-ms 1..300000]. Keep the original plan and final completion pins.
Completed batches are never downloaded again. A valid body awaiting its checkpoint
must match a fresh two-observation capture before adoption. Torn files refuse in place.
Collections preserve frozen membership, not an atomic GitHub snapshot. No native writes.
Exit 0: success; 2: refusal; 3: run paused; 4: retained/uncertain custody or output error.`;
const fail=code=>{throw operatorError(`github_pull_collection_${code}`);};
const decimal=v=>{if(typeof v!=='string'||!/^(0|[1-9][0-9]*)$/.test(v)||!Number.isSafeInteger(Number(v)))fail('arguments');return Number(v);};
function options(args) {
  if(!Array.isArray(args)||args.length>32||args.some(v=>typeof v!=='string'||v.length>4096)||args.reduce((n,s)=>n+s.length,0)>32768)fail('arguments');
  const definitions={
    prepare:[['--inventory','--inventory-confirm','--workdir'],['--max-capture-bytes','--max-records']],
    run:[['--workdir','--confirm'],['--token-file','--max-batches','--max-requests','--max-read-bytes']],
    status:[['--workdir','--confirm'],['--complete-confirm']],
    batch:[['--workdir','--confirm','--complete-confirm','--batch'],['--number-start']],
  },operation=args[0];
  if(!Object.hasOwn(definitions,operation))fail('command');
  const [required,optional]=definitions[operation],allowed=new Set([...required,...optional,'--timeout-ms']),flags=new Map();
  for(let i=1;i<args.length;) {
    const name=args[i++],value=args[i++];
    if(!allowed.has(name)||flags.has(name)||value===undefined||value.startsWith('--'))fail('arguments');flags.set(name,value);
  }
  if(required.some(k=>!flags.has(k)))fail('arguments');
  const timeoutMs=decimal(flags.get('--timeout-ms')??'300000');if(timeoutMs<1||timeoutMs>300000)fail('timeout');
  const value={workdir:operatorPath(flags.get('--workdir'))};
  const text={'--inventory-confirm':'inventoryConfirm','--confirm':'confirm','--complete-confirm':'completeConfirm','--number-start':'numberStart'};
  const paths={'--inventory':'inventoryFile','--token-file':'tokenFile'};
  const numbers={'--batch':'batch','--max-batches':'maxBatches','--max-capture-bytes':'maxCaptureBytes','--max-records':'maxRecords','--max-requests':'maxRequests','--max-read-bytes':'maxReadBytes'};
  for(const [k,v] of flags) {
    if(Object.hasOwn(text,k))value[text[k]]=v;
    else if(Object.hasOwn(paths,k))value[paths[k]]=operatorPath(v);
    else if(Object.hasOwn(numbers,k))value[numbers[k]]=decimal(v);
  }
  return {operation,value,timeoutMs};
}
async function output(stream,value,wait) {
  const text=operatorJson(value);if(Buffer.byteLength(text)>1024*1024)fail('output_limit');
  await new Promise((resolve,reject)=>{
    let done=false;const finish=e=>{if(done)return;done=true;clearTimeout(timer);setImmediate(()=>{stream.removeListener?.('error',error);e?reject(e):resolve();});};
    const error=e=>finish(e),timer=setTimeout(()=>finish(operatorError('github_pull_collection_output_deadline')),wait);
    stream.once?.('error',error);try{stream.write(text,finish);}catch(e){finish(e);}
  });
}
export async function main(args,{stdout=process.stdout,stderr=process.stderr,signal}={}) {
  const stop=new AbortController(),abort=()=>stop.abort(),combined=signal?AbortSignal.any([signal,stop.signal]):stop.signal;
  process.on('SIGTERM',abort);process.on('SIGINT',abort);let timer,result;
  try {
    if(args.length===1&&args[0]==='--help'){await output(stdout,{usage:HELP},10000);return 0;}
    const parsed=options(args),deadline=performance.now()+parsed.timeoutMs;timer=setTimeout(abort,parsed.timeoutMs);
    const remaining=()=>{combined.throwIfAborted();const n=Math.ceil(deadline-performance.now());if(n<1)fail('deadline');return n;};
    const operation={prepare:prepareGithubPullCollection,run:collectGithubPulls,status:inspectGithubPullCollection,batch:selectGithubPullCollectionBatch}[parsed.operation];
    result=await operation({...parsed.value,signal:combined,timeoutMs:remaining()});await output(stdout,result,Math.min(10000,remaining()));
    return parsed.operation==='run'&&!result.complete?3:0;
  } catch(error) {
    try{await output(stderr,{type:'github_pull_collection_error',code:typeof error.code==='string'&&/^[A-Za-z0-9_]+$/.test(error.code)?error.code:'operation_failed',
      ...(error.collection_progress?{collection_progress:error.collection_progress}:{}),...(result?{retained_result:result}:{}),mutation_submitted:false},10000);}catch{}
    return result||error.collection_progress?.directory_created||error.collection_progress?.plan_verified?4:2;
  } finally {clearTimeout(timer);process.removeListener('SIGTERM',abort);process.removeListener('SIGINT',abort);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)process.exitCode=await main(process.argv.slice(2));
