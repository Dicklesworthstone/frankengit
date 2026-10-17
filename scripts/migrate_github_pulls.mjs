#!/usr/bin/env node
// Explicit foreign-source reads. No API response or saved link chooses authority.
import { dirname, join } from 'node:path';
import { lstat } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { captureGithubPulls,parseGithubPullCapture,GITHUB_PULL_LIMITS,pullSourceNumber } from './lib/github-pull-source.mjs';
import { operatorPath,privateRecordPath,absentRecord,readPrivateOperatorFile,saveOperatorRecord,
  recordDigest,operatorJson,operatorError } from './lib/forge-operator-io.mjs';

const HELP=`usage: node scripts/migrate_github_pulls.mjs capture --repository OWNER/REPO --pull NUMBER [--pull NUMBER...] --out NEW_PRIVATE_FILE [--token-file PRIVATE_GITHUB_TOKEN]
       node scripts/migrate_github_pulls.mjs inspect-capture --capture PRIVATE_FILE --confirm SHA256
capture: [--max-requests 1..4096] [--max-read-bytes 1..268435456]
all: [--timeout-ms 1..300000]
Captures selected PR metadata, discussions, submitted reviews and inline review locations.
Two equal observations are NOT an atomic GitHub snapshot. Quiesce source edits.
Keep the returned capture_sha256 independently. No native writes, approvals or merges.
Exit 0: success; 2: refusal; 4: retained/potentially published capture or output failure.`;
function options(args){
  if(!Array.isArray(args)||args.length>230||args.some(v=>typeof v!=='string'||v.length>4096)||args.reduce((n,s)=>n+s.length,0)>32768)throw operatorError('github_pull_arguments');
  const operation=args[0],capturing=operation==='capture';
  if(!capturing&&operation!=='inspect-capture')throw operatorError('github_pull_command');
  const required=capturing?['--repository','--pull','--out']:['--capture','--confirm'];
  const allowed=new Set([...required,'--timeout-ms',...(capturing?['--token-file','--max-requests','--max-read-bytes']:[])]),flags=new Map(),numbers=[];
  for(let i=1;i<args.length;){const k=args[i++],v=args[i++];if(!allowed.has(k)||v===undefined||v.startsWith('--')||flags.has(k)&&k!=='--pull')throw operatorError('github_pull_arguments');
    if(k==='--pull')numbers.push(decimal(v));flags.set(k,v);}
  if(required.some(k=>!flags.has(k)))throw operatorError('github_pull_arguments');
  return {operation,flags,numbers,timeoutMs:pullSourceNumber(decimal(flags.get('--timeout-ms')??'300000'),1,300000)};
}
function decimal(v){if(!/^(0|[1-9][0-9]*)$/.test(v))throw operatorError('github_pull_decimal');return pullSourceNumber(Number(v));}
async function outsideWorktree(value){
  const path=operatorPath(value);
  for(let cursor=dirname(path);;cursor=dirname(cursor)){
    if(cursor.split('/').includes('.git'))throw operatorError('github_pull_worktree');
    try{await lstat(join(cursor,'.git'));throw operatorError('github_pull_worktree');}catch(e){if(e.code!=='ENOENT')throw e;}
    if(dirname(cursor)===cursor)break;
  }
  return path;
}
async function write(stream,value,maximumWait){
  const bytes=operatorJson(value);if(Buffer.byteLength(bytes)>1024*1024)throw operatorError('github_pull_output_limit');
  await new Promise((resolve,reject)=>{
    let settled=false;const finish=e=>{if(settled)return;settled=true;clearTimeout(timer);
      setImmediate(()=>{stream.removeListener?.('error',error);e?reject(e):resolve();});};
    const error=e=>finish(e),timer=setTimeout(()=>finish(operatorError('github_pull_output_deadline')),maximumWait);
    stream.once?.('error',error);try{stream.write(bytes,finish);}catch(e){finish(e);}
  });
}
export async function main(args,{stdout=process.stdout,stderr=process.stderr,signal}={}){
  const stop=new AbortController(),abort=()=>stop.abort(),combined=signal?AbortSignal.any([signal,stop.signal]):stop.signal;
  process.on('SIGTERM',abort);process.on('SIGINT',abort);
  let timer,result,pending;
  try{
    if(args.length===1&&args[0]==='--help'){await write(stdout,{usage:HELP},10000);return 0;}
    const o=options(args),f=o.flags,deadline=performance.now()+o.timeoutMs;
    timer=setTimeout(abort,o.timeoutMs);
    const check=()=>{combined.throwIfAborted();if(performance.now()>=deadline)throw operatorError('github_pull_deadline');};
    const remaining=()=>{check();return Math.max(1,Math.ceil(deadline-performance.now()));};
    if(o.operation==='capture'){
      const path=await privateRecordPath(await outsideWorktree(f.get('--out')));await absentRecord(path);check();let token=null;
      if(f.has('--token-file')){
        const raw=await readPrivateOperatorFile(await outsideWorktree(f.get('--token-file')),256,check);
        try{token=raw.toString('utf8').replace(/\n$/,'');if(!/^[A-Za-z0-9_]{1,255}$/.test(token))throw operatorError('github_pull_token');}finally{raw.fill(0);}
      }
      const captured=await captureGithubPulls({repository:f.get('--repository'),numbers:o.numbers,token,signal:combined,timeoutMs:remaining(),
        ...(f.has('--max-requests')?{maxRequests:decimal(f.get('--max-requests'))}:{}),
        ...(f.has('--max-read-bytes')?{maxReadBytes:decimal(f.get('--max-read-bytes'))}:{})});
      pending={path,capture_sha256:captured.sha256};check();await saveOperatorRecord(path,captured.bytes,check);
      result={type:'github_pull_capture_saved',...pending,pulls:captured.capture.pulls.length,statistics:captured.statistics,
        consistency:captured.capture.consistency,atomic_snapshot:false,mutation_submitted:false};
    }else{
      const bytes=await readPrivateOperatorFile(await outsideWorktree(f.get('--capture')),GITHUB_PULL_LIMITS.bytes,check),sha=recordDigest(bytes);
      if(!/^[0-9a-f]{64}$/.test(f.get('--confirm')??'')||sha!==f.get('--confirm'))throw operatorError('github_pull_pin');
      const capture=parseGithubPullCapture(bytes);check();result={type:'github_pull_capture_inspected',capture_sha256:sha,source:capture.source,
        pulls:capture.pulls.map(e=>({number:e.pull.number,state:e.pull.state,draft:e.pull.draft,merged:e.pull.merged,
          head:e.pull.head,base:e.pull.base,discussion:e.discussion.length,reviews:e.reviews.length,inline:e.inline.length})),
        consistency:capture.consistency,network_accessed:false,mutation_submitted:false};
    }
    await write(stdout,result,Math.min(10000,remaining()));return 0;
  }catch(error){
    try{await write(stderr,{type:'github_pull_error',code:typeof error.code==='string'&&/^[A-Za-z0-9_]+$/.test(error.code)?error.code:'github_pull_operation_failed',
      ...(pending?{capture_progress:pending}:{}),...(result?{retained_result:result}:{}),mutation_submitted:false},10000);}catch{}
    return pending||result?4:2;
  }finally{clearTimeout(timer);process.removeListener('SIGTERM',abort);process.removeListener('SIGINT',abort);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)process.exitCode=await main(process.argv.slice(2));
