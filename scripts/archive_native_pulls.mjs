#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { exportPullArchive, inspectPullArchive } from './lib/forge-pull-archive.mjs';

const USAGE=`usage: node scripts/archive_native_pulls.mjs export --workdir ABS --url REPO_UI_PULLS --tenant HEX32 --repository HEX32 --token-file ABS [--head TOKEN] [--page-size 1..100] [--timeout-ms 1..300000]
       node scripts/archive_native_pulls.mjs inspect --workdir ABS --confirm SHA256 [--timeout-ms 1..300000]`;
function options(args){
  if(!['export','inspect'].includes(args[0])) throw new Error(USAGE);
  const operation=args[0], map=new Map();
  for(let i=1;i<args.length;){ const k=args[i++]; if(!k.startsWith('--')||map.has(k)) throw new Error(USAGE); const v=args[i++]; if(v===undefined||v.startsWith('--')) throw new Error(USAGE); map.set(k,v); }
  const required=operation==='export'?['--workdir','--url','--tenant','--repository','--token-file']:['--workdir','--confirm'];
  for(const k of required) if(!map.has(k)) throw new Error(USAGE);
  const allowed=new Set([...required,'--head','--page-size','--timeout-ms','--max-pages','--max-pulls','--max-reviews','--max-comments','--max-archive-bytes']);
  if([...map.keys()].some(k=>!allowed.has(k)) || operation==='inspect' && [...map.keys()].some(k=>!['--workdir','--confirm','--timeout-ms'].includes(k))) throw new Error(USAGE);
  const n=flag=>map.has(flag)?Number(map.get(flag)):undefined;
  return {operation,map,values:{workdir:map.get('--workdir'),...(operation==='export'?{href:map.get('--url'),tenant:map.get('--tenant'),repository:map.get('--repository'),tokenFile:map.get('--token-file'),
    ...(map.has('--head')?{head:map.get('--head')}:{}),...(map.has('--page-size')?{pageSize:n('--page-size')}:{}),...(map.has('--max-pages')?{maxPages:n('--max-pages')}:{}),
    ...(map.has('--max-pulls')?{maxPulls:n('--max-pulls')}:{}),...(map.has('--max-reviews')?{maxReviews:n('--max-reviews')}:{}),...(map.has('--max-comments')?{maxComments:n('--max-comments')}:{}),
    ...(map.has('--max-archive-bytes')?{maxArchiveBytes:n('--max-archive-bytes')}:{}),}:{confirm:map.get('--confirm')}),...(map.has('--timeout-ms')?{timeoutMs:n('--timeout-ms')}:{})}};
}
async function write(stream,value){
  const text=`${JSON.stringify(value)}\n`;
  if(Buffer.byteLength(text)>1024*1024) throw new Error('pull archive output exceeds limit');
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('pull archive output deadline exceeded')),10000);stream.write(text,error=>{clearTimeout(timer);error?reject(error):resolve();});});
}
export async function main(args,{stdout=process.stdout,stderr=process.stderr}={}){
  if(args.length===1&&args[0]==='--help'){await write(stdout,{usage:USAGE});return 0;}
  const stop=new AbortController(),abort=()=>stop.abort(new Error('pull archive stop requested'));
  process.on('SIGTERM',abort);process.on('SIGINT',abort);
  let result;
  try{
    const parsed=options(args);
    result=await(parsed.operation==='export'?exportPullArchive({...parsed.values,signal:stop.signal}):inspectPullArchive({...parsed.values,signal:stop.signal}));
    await write(stdout,result);return 0;
  }catch(error){
    try{await write(stderr,{type:'pull_archive_error',message:error.message,...(error.archive_progress?{archive_progress:error.archive_progress}:{}),...(result?{retained_result:result}:{})});}catch{}
    return result||error.archive_progress?.expected_archive_sha256?4:2;
  }finally{process.removeListener('SIGTERM',abort);process.removeListener('SIGINT',abort);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) process.exitCode=await main(process.argv.slice(2));
