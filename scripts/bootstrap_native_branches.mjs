#!/usr/bin/env node
// Explicit native branch prerequisites. This command never invokes Git, submits
// PRs, updates/deletes a ref, or guesses whether an absent outcome was committed.
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { prepareBootstrap, runBootstrap, bootstrapStatus, inspectBootstrap } from './lib/branch-bootstrap.mjs';
import { pullBootstrapRequirements, preparePullBootstrap } from './lib/branch-bootstrap-pulls.mjs';
import { BOOTSTRAP_LIMITS, parse, fail } from './lib/branch-bootstrap-protocol.mjs';
import { path, directory, lifetime } from './lib/branch-bootstrap-store.mjs';
import { readPrivateOperatorFile, operatorJson } from './lib/forge-operator-io.mjs';

export const HELP = `usage: node scripts/bootstrap_native_branches.mjs prepare --workdir NEW --selection PRIVATE_JSON --token-file PRIVATE_TOKEN
       node scripts/bootstrap_native_branches.mjs requirements --migration-dir PR_JOB --migration-confirm PR_PLAN_SHA256 --namespace refs/heads/import/NAME/ --principal HEX32
       node scripts/bootstrap_native_branches.mjs prepare-pulls --migration-dir PR_JOB --migration-confirm PR_PLAN_SHA256 --namespace refs/heads/import/NAME/ --principal HEX32 --workdir NEW --token-file PRIVATE_TOKEN
       node scripts/bootstrap_native_branches.mjs run|recover --workdir JOB --confirm PLAN_SHA256 [--token-file PRIVATE_TOKEN] [--max-operations 1..8192] [--ca-file PRIVATE_PEM]
       node scripts/bootstrap_native_branches.mjs status|inspect --workdir JOB --confirm PLAN_SHA256

All commands accept --timeout-ms 1..300000. Only run accepts --retry-key ORIGINAL_PENDING_KEY.
requirements, prepare, prepare-pulls, status and inspect make no network requests.
The branch principal must be selected independently; source attribution is not authority.
Every requested branch must be absent and under the exact selected namespace.
Git objects must already be authorized and reachable in the destination.
Preserve the returned plan_sha256. Continue a paused run with the same plan and keys.
Exit 0: operation succeeded (prepare/status may report incomplete progress).
Exit 1: native refusal. Exit 2: argument/preflight refusal. Exit 3: paused/unresolved.
Exit 4: error with retained or potentially published custody; inspect the original plan.
See docs/NATIVE_BRANCH_BOOTSTRAP.md.
`;
const COMMANDS = ['prepare','requirements','prepare-pulls','run','recover','status','inspect'];
const NAMES = { '--workdir':'workdir','--confirm':'confirm','--selection':'selectionFile','--token-file':'tokenFile',
  '--migration-dir':'migrationDir','--migration-confirm':'migrationConfirm','--namespace':'namespace',
  '--principal':'principal','--retry-key':'retryKey','--max-operations':'maxOperations','--timeout-ms':'timeoutMs','--ca-file':'caFile' };
function options(args) {
  if (!Array.isArray(args) || args.length>32 || args.some(v=>typeof v!=='string'||v.length>4096) ||
      args.reduce((n,v)=>n+v.length,0)>32768 || !COMMANDS.includes(args[0])) fail('arguments');
  const command=args[0], deriving=['requirements','prepare-pulls'].includes(command);
  const required=deriving?['--migration-dir','--migration-confirm','--namespace','--principal',
    ...(command==='prepare-pulls'?['--workdir','--token-file']:[])]:command==='prepare'
    ?['--workdir','--selection','--token-file']:['--workdir','--confirm'];
  const allowed=new Set([...required,'--timeout-ms',...(['run','recover'].includes(command)
    ?['--token-file','--max-operations','--ca-file',...(command==='run'?['--retry-key']:[])]:[])]);
  const seen=new Set(), values={};
  for(let i=1;i<args.length;){
    const key=args[i++],value=args[i++];
    if(!allowed.has(key)||seen.has(key)||value===undefined||!value||value.startsWith('--'))fail('arguments');
    seen.add(key);
    if(['--max-operations','--timeout-ms'].includes(key)){
      const max=key==='--timeout-ms'?300000:8192;
      if(!/^[1-9][0-9]*$/.test(value)||!Number.isSafeInteger(Number(value))||Number(value)>max)fail('arguments');
      values[NAMES[key]]=Number(value);
    }else values[NAMES[key]]=value;
  }
  if(required.some(k=>!seen.has(k)))fail('arguments');
  return {command,values};
}
async function dispatch(command, raw, life) {
  const withBudget=o=>({...o,timeoutMs:life.remaining(),signal:life.signal});
  if(command==='prepare'){
    const {selectionFile,...o}=raw, file=path(selectionFile);
    await directory(dirname(file));life.check();
    const bytes=await readPrivateOperatorFile(file,BOOTSTRAP_LIMITS.file,life.check);
    return prepareBootstrap(withBudget({...o,selection:parse(bytes)}));
  }
  if(command==='requirements')return pullBootstrapRequirements(withBudget(raw));
  if(command==='prepare-pulls')return preparePullBootstrap(withBudget(raw));
  if(command==='status')return bootstrapStatus(withBudget(raw));
  if(command==='inspect')return inspectBootstrap(withBudget(raw));
  return runBootstrap(withBudget({...raw,operation:command}));
}
function write(stream,value,timeoutMs=10000) {
  const text=operatorJson(value);
  // A <=1 MiB selection may expand when terminal controls are escaped.
  if(Buffer.byteLength(text)>8*1024*1024)fail('output_bytes');
  return new Promise((resolve,reject)=>{
    let done=false;
    const finish=error=>{
      if(done)return;done=true;clearTimeout(timer);
      setImmediate(()=>{stream.removeListener?.('error',onError);error?reject(error):resolve();});
    };
    const onError=error=>finish(error);
    const timer=setTimeout(()=>finish(new Error('branch_bootstrap_output_timeout')),timeoutMs);
    stream.once?.('error',onError);
    try{stream.write(text,finish);}catch(error){finish(error);}
  });
}
export async function main(args,{stdout=process.stdout,stderr=process.stderr,signal}={}) {
  const stop=new AbortController(), abort=()=>stop.abort();
  process.on('SIGTERM',abort);process.on('SIGINT',abort);
  let result,life;
  // Keep Node's asynchronous broken-pipe emission observable through callbacks,
  // including an error emitted after a bounded output wait already timed out.
  const pipe=()=>{};stdout.on?.('error',pipe);stderr.on?.('error',pipe);
  try{
    if(args.length===1&&args[0]==='--help'){await write(stdout,{usage:HELP});return 0;}
    const {command,values}=options(args);
    life=lifetime({...values,signal:signal?AbortSignal.any([signal,stop.signal]):stop.signal});
    result=await dispatch(command,values,life);
    await write(stdout,result,Math.min(10000,life.remaining()));
    return ['run','recover'].includes(command)?result.complete?0:result.state==='refused'?1:3:0;
  }catch(error){
    const retained=Boolean(result||error.bootstrap_progress?.directory_created||error.bootstrap_progress?.plan_verified);
    try{await write(stderr,{type:'branch_bootstrap_error',code:typeof error.code==='string'&&/^[a-z_]{1,128}$/.test(error.code)
      ?error.code:'branch_bootstrap_operation_or_output_failure',...(error.bootstrap_progress?{bootstrap_progress:error.bootstrap_progress}:{}),
      ...(result?{retained_result:result}:{})});}catch{/* Original custody remains; no replay or cleanup. */}
    return retained?4:2;
  }finally{
    life?.close();process.removeListener('SIGTERM',abort);process.removeListener('SIGINT',abort);
    stdout.removeListener?.('error',pipe);stderr.removeListener?.('error',pipe);
  }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)process.exitCode=await main(process.argv.slice(2));
