#!/usr/bin/env node
// One explicitly pinned destination migration over a completed source collection.
// No GitHub credential, source refresh, replacement key or authority bypass.
import { pathToFileURL } from 'node:url';
import { prepareGithubPullMigration, executeGithubPullMigration, githubPullMigrationBatch }
  from './lib/github-pull-migration.mjs';
import { collectionLifetime } from './lib/github-pull-collection-store.mjs';
import { readPullPrivate, privatePullDirectory } from './operator/pull_files.mjs';
import { parsePullJson } from './operator/pull_command.mjs';
import { operatorPath, operatorJson, operatorError, privateRecordPath, absentRecord,
  saveOperatorRecord } from './lib/forge-operator-io.mjs';
import { encode } from './lib/forge-pull-archive-store.mjs';
import { dirname } from 'node:path';

const HELP=`usage: node scripts/migrate_github_pull_collection.mjs prepare
  --collection-dir COMPLETE_COLLECTION --collection-confirm COLLECTION_PLAN_SHA256
  --complete-confirm COLLECTION_COMPLETE_SHA256 --selection PRIVATE_DESTINATION_JSON
  --workdir NEW_PRIVATE_JOB --token-file NATIVE_PR_TOKEN
  [--max-steps 1..32768] [--max-request-bytes 1..134217728]
  node scripts/migrate_github_pull_collection.mjs inspect|status --workdir JOB --confirm MIGRATION_SHA256
  node scripts/migrate_github_pull_collection.mjs run|recover --workdir JOB --confirm MIGRATION_SHA256
    [--token-file NATIVE_TOKEN] [--ca-file PRIVATE_PEM] [--max-operations 1..8192]
  node scripts/migrate_github_pull_collection.mjs batch --workdir JOB --confirm MIGRATION_SHA256 --batch N
  node scripts/migrate_github_pull_collection.mjs requirements --workdir JOB --confirm MIGRATION_SHA256
    --batch N --principal BRANCH_PRINCIPAL_HEX32 --out NEW_PRIVATE_SELECTION
run only: [--retry-key ORIGINAL_PENDING_KEY]; all: [--timeout-ms 1..300000]
Prepare is offline and one-shot; interrupted preparation is retained, not repaired.
Execution is restartable with the same outer pin and original child request keys.
Git objects and exact historical branches must be provisioned separately.
Exit 0: successful command or complete execution; 1: native refusal;
2: argument/preflight refusal; 3: incomplete execution; 4: retained/uncertain result.`;
const definitions={
  prepare:[['--collection-dir','--collection-confirm','--complete-confirm','--selection','--workdir','--token-file'],['--max-steps','--max-request-bytes']],
  inspect:[['--workdir','--confirm'],[]],status:[['--workdir','--confirm'],[]],
  run:[['--workdir','--confirm'],['--token-file','--ca-file','--max-operations','--retry-key']],
  recover:[['--workdir','--confirm'],['--token-file','--ca-file','--max-operations']],
  batch:[['--workdir','--confirm','--batch'],[]],
  requirements:[['--workdir','--confirm','--batch','--principal','--out'],[]]
};
const fail=code=>{throw operatorError(`github_pull_migration_${code}`);};
function decimal(text,max) {
  if(typeof text!=='string'||!/^[1-9][0-9]*$/.test(text)||!Number.isSafeInteger(Number(text))||Number(text)>max)fail('decimal');
  return Number(text);
}
function argumentsFor(args) {
  if(!Array.isArray(args)||args.length>40||args.some(s=>typeof s!=='string'||s.includes('\0')||s.length>4096)||
      args.reduce((n,s)=>n+Buffer.byteLength(s),0)>32768)fail('arguments');
  const operation=args[0];if(!Object.hasOwn(definitions,operation))fail('command');
  const [required,optional]=definitions[operation],allowed=new Set([...required,...optional,'--timeout-ms']),flags=new Map();
  for(let i=1;i<args.length;) {
    const flag=args[i++],value=args[i++];
    if(!allowed.has(flag)||flags.has(flag)||value===undefined||value.startsWith('--'))fail('arguments');
    flags.set(flag,value);
  }
  if(required.some(flag=>!flags.has(flag)))fail('arguments');
  return {operation,flags,timeoutMs:decimal(flags.get('--timeout-ms')??'300000',300000)};
}
async function write(stream,value,wait) {
  const text=operatorJson(value);if(Buffer.byteLength(text)>8*1024*1024)fail('output_limit');
  await new Promise((resolve,reject)=>{
    let done=false;
    const finish=error=>{if(done)return;done=true;clearTimeout(timer);
      setImmediate(()=>{stream.removeListener?.('error',onError);error?reject(error):resolve();});};
    const onError=error=>finish(error),timer=setTimeout(()=>finish(operatorError('github_pull_migration_output_deadline')),wait);
    stream.once?.('error',onError);try{stream.write(text,finish);}catch(error){finish(error);}
  });
}
export async function main(args,{stdout=process.stdout,stderr=process.stderr,signal}={}) {
  const stop=new AbortController(),abort=()=>stop.abort();
  process.on('SIGTERM',abort);process.on('SIGINT',abort);
  let life,result,pending,execution=false;
  try {
    if(args.length===1&&args[0]==='--help'){await write(stdout,{usage:HELP},10000);return 0;}
    const o=argumentsFor(args),f=o.flags;
    life=collectionLifetime({timeoutMs:o.timeoutMs,signal:signal?AbortSignal.any([signal,stop.signal]):stop.signal});
    const config=()=>({timeoutMs:life.remaining(),signal:life.signal}),workdir=operatorPath(f.get('--workdir'));
    if(o.operation==='prepare') {
      const selection=parsePullJson(await readPullPrivate(operatorPath(f.get('--selection')),1024*1024));life.check();
      result=await prepareGithubPullMigration({workdir,collectionDir:operatorPath(f.get('--collection-dir')),
        collectionConfirm:f.get('--collection-confirm'),completeConfirm:f.get('--complete-confirm'),selection,
        tokenFile:operatorPath(f.get('--token-file')),
        ...(f.has('--max-steps')?{maxSteps:decimal(f.get('--max-steps'),32768)}:{}),
        ...(f.has('--max-request-bytes')?{maxRequestBytes:decimal(f.get('--max-request-bytes'),134217728)}:{}),...config()});
    } else if(o.operation==='batch'||o.operation==='requirements') {
      let path;
      if(o.operation==='requirements') {
        path=operatorPath(f.get('--out'));await privatePullDirectory(dirname(path));path=await privateRecordPath(path);await absentRecord(path);life.check();
      }
      result=await githubPullMigrationBatch({workdir,confirm:f.get('--confirm'),batch:decimal(f.get('--batch'),10000),
        ...(o.operation==='requirements'?{principal:f.get('--principal')}:{}),...config()});
      if(path) {
        pending={path,requirements_sha256:result.requirements_sha256,migration_sha256:f.get('--confirm')};
        await saveOperatorRecord(path,encode(result.selection),life.check);result={...result,selection_path:path};
      }
    } else {
      execution=['run','recover'].includes(o.operation);
      result=await executeGithubPullMigration({workdir,confirm:f.get('--confirm'),operation:execution?o.operation:'status',
        ...(f.has('--token-file')?{tokenFile:operatorPath(f.get('--token-file'))}:{}),
        ...(f.has('--ca-file')?{caFile:operatorPath(f.get('--ca-file'))}:{}),
        ...(f.has('--retry-key')?{retryKey:f.get('--retry-key')}:{}),
        ...(f.has('--max-operations')?{maxOperations:decimal(f.get('--max-operations'),8192)}:{}),...config()});
    }
    await write(stdout,result,Math.min(10000,life.remaining()));
    return execution?(result.complete?0:result.state==='refused'?1:3):0;
  } catch(error) {
    try{await write(stderr,{type:'github_pull_migration_error',code:typeof error?.code==='string'&&/^[A-Za-z0-9_]+$/.test(error.code)?error.code:'github_pull_migration_unavailable',
      ...(error?.migration_progress?{migration_progress:error.migration_progress}:{}),
      ...(error?.import_progress?{child_progress:error.import_progress}:{}),...(pending?{output_progress:pending}:{}),
      ...(result?{retained_result:result}:{}),outcome_unknown:execution},10000);}catch{}
    return result||pending||error?.migration_progress?.directory_created||error?.migration_progress?.plan_verified?4:2;
  } finally{life?.close();process.removeListener('SIGTERM',abort);process.removeListener('SIGINT',abort);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)process.exitCode=await main(process.argv.slice(2));
