// Destination response-schema peer only. It is not native Git, authorization,
// a durable authority engine or evidence that referenced commits are reachable.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp,writeFile,chmod,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureGithubPulls } from '../../scripts/lib/github-pull-source.mjs';
import { prepareGithubPullImport } from '../../scripts/lib/github-pull-import.mjs';
import { githubPeer } from './github-pull-fixture.mjs';
export const NATIVE_TOKEN='aa'.repeat(32),ROTATED='bb'.repeat(32);
export const SCOPE={tenant_id:'11'.repeat(16),repository_id:'22'.repeat(16),repository_incarnation:'33'.repeat(16),principal_id:'44'.repeat(16),object_format:'sha1'};
const counters=['number','expected_version','comment_version','decision_sequence'];
export const wire=v=>JSON.stringify(v,(k,x)=>counters.includes(k)&&typeof x==='string'&&/^[0-9]+$/.test(x)?JSON.rawJSON(x):x);
export function selection(endpoint){return {endpoint,scope:{...SCOPE},number_start:'100',namespace:'refs/heads/import/github/'};}
export async function destinationPeer(t,{alter=null}={}){
 const calls=[],mutations=[],states=new Map(),sockets=new Set();let sequence=0;
 const server=createServer(async(req,res)=>{
  try{
   assert.equal(req.method,'POST');assert([`Bearer ${NATIVE_TOKEN}`,`Bearer ${ROTATED}`].includes(req.headers.authorization));
   const chunks=[];for await(const c of req){chunks.push(c);if(chunks.reduce((n,b)=>n+b.length,0)>256*1024)throw new Error('request bound');}
   const body=Buffer.concat(chunks).toString(),key=req.headers['idempotency-key'];assert.match(key,/^fgp1-/);
   const recovery=req.url==='/repo/api/v1/outcomes';let stored=states.get(key),value,action=null,number=null,fields=null;
   if(recovery){
    assert.equal(body,'');const {object_format,...scope}=SCOPE;
    value={type:'transaction_outcome',schema_version:1,...scope,selector:'transaction',command_index:null,
     state:stored?.outcome??'key_not_observed',terminal:Boolean(stored),transaction:stored?{tx_id:stored.tx_id,seal_id:`seal-${key}`,request_schema:'receive-v1',canonical_request_digest:{algorithm:2,hex:'11'.repeat(32)}}:null,
     decision:stored?{kind:stored.outcome,decision_sequence:stored.decision_sequence,...(stored.outcome==='committed'?{repository_commit_id:stored.repository_commit_id}:{code:stored.refusal_code,code_point:stored.refusal_code_point,refusal_record_id:stored.refusal_record_id})}:null,
     read_only:true,request_reexecuted:false,absence_proves_non_commit:false,session_completeness_established:false};
   }else{
    const m=/^\/repo\/api\/v1\/pulls\/([1-9][0-9]*)\/(open|comments|close)$/.exec(req.url);assert(m,'unexpected mutation endpoint');
    [,number,action]=m;action=action==='comments'?'comment':action;fields=Object.fromEntries(new URLSearchParams(body));
    assert.equal(req.headers.authorization,`Bearer ${NATIVE_TOKEN}`);
    if(stored){assert.equal(stored.saved_body,body);value={...stored};delete value.saved_body;}
    else{
     value={type:action==='comment'?'pull_request_comment_publication':'pull_request_publication',schema_version:1,...SCOPE,number,action,
      tx_id:`tx-${++sequence}`,outcome:'committed',decision_sequence:String(sequence),repository_commit_id:`rcr-${sequence}`,
      refusal_record_id:null,refusal_code:null,refusal_code_point:null,delivery_acknowledged:null,expected_version:fields.expected_version,
      ...(action==='comment'?{comment_version:String(BigInt(fields.expected_version)+1n),refs_changed:false}:{})};
    }
   }
   const call={recovery,key,body,action,number,fields,value,req,res,index:calls.length+1};calls.push(call);
   const command=await alter?.(call);
   if(!recovery&&command!=='not-committed'){
    states.set(key,{...value,saved_body:body});mutations.push({key,action,number,fields,body});
   }
   if(command===false||command==='not-committed')return;
   res.writeHead(!recovery&&value.outcome==='refused'?409:200,{'content-type':'application/json'});res.end(wire(value));
  }catch(e){res.writeHead(500,{'content-type':'application/json'});res.end(JSON.stringify({error:e.message}));}
 });
 server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));let closed=false;
 const close=async()=>{if(closed)return;closed=true;for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));};t.after(close);
 return {endpoint:`http://127.0.0.1:${server.address().port}/repo`,calls,mutations,states,close};
}
export async function migrationFixture(t,{source={},destination={},select={},prepare=true}={}){
 const root=await mkdtemp(join(tmpdir(),'fg-github-migration-'));await chmod(root,0o700);t.after(()=>rm(root,{recursive:true,force:true}));
 const upstream=await githubPeer(t,source),captured=await captureGithubPulls(upstream.options);await upstream.close();
 const captureFile=join(root,'source.json'),tokenFile=join(root,'native.token'),workdir=join(root,'job');
 await writeFile(captureFile,captured.bytes,{mode:0o600});await writeFile(tokenFile,NATIVE_TOKEN+'\n',{mode:0o600});
 const peer=await destinationPeer(t,destination),selected={...selection(peer.endpoint),...select};
 const input={workdir,captureFile,captureConfirm:captured.sha256,tokenFile,selection:selected};
 const prepared=prepare?await prepareGithubPullImport(input):null;
 return {root,captureFile,tokenFile,workdir,upstream,captured,peer,input,prepared,
  run:{workdir,confirm:prepared?.plan_sha256,tokenFile,operation:'run'}};
}
