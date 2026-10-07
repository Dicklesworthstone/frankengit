// Real loopback HTTP and default Node Fetch, with explicit synthetic native
// replies. This checks browser transport bytes/recovery, NOT Rust admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { InitialSourceClient } from '../../crates/fgit-node/src/smart_http/server/browser/initial.mjs';
import { importInitialFiles, initialImportDescriptors } from '../../crates/fgit-node/src/smart_http/server/browser/initial-plan.mjs';
import { fixture, metadata, token, crypto } from './initial-fixtures.mjs';
function uploadParts(body,type){
 const boundary=/^multipart\/form-data; boundary=([A-Za-z0-9._-]{1,70})$/.exec(type)?.[1];assert(boundary);
 const opening=Buffer.from(`--${boundary}\r\n`),separator=Buffer.from(`\r\n--${boundary}`),parts=new Map();let start=0;
 while(start<body.length){
  assert(body.subarray(start,start+opening.length).equals(opening));
  const headersEnd=body.indexOf('\r\n\r\n',start),end=body.indexOf(separator,headersEnd+4);assert(headersEnd>start&&end>=headersEnd+4);
  const header=body.subarray(start,headersEnd).toString('ascii'),name=/name="(command|patch|bundle)"/.exec(header)?.[1];assert(name&&!parts.has(name));
  parts.set(name,body.subarray(headersEnd+4,end));start=end+separator.length;
  if(body.subarray(start).equals(Buffer.from('--\r\n')))break;
  start=end+2;
 }
 return parts;
}
for(const algorithm of ['sha1','sha256'])test(`${algorithm}: imported binary project crosses real HTTP and recovers the exact lost creation request`,{timeout:10000},async()=>{
 const uploads=[new File([new Uint8Array([0,255,13,10])],'a.bin'),new File([],'empty')];
 const entries=await importInitialFiles([],initialImportDescriptors(uploads)),f=await fixture(algorithm,entries),calls=[];let assertion;
 const server=createServer(async(req,res)=>{
  try{
   assert.equal(req.method,'POST');assert.equal(req.headers.authorization,`Bearer ${token}`);let size=0;const chunks=[];
   for await(const chunk of req){size+=chunk.length;assert(size<=2*1024*1024);chunks.push(chunk);}
   const bytes=Buffer.concat(chunks),path=req.url.slice('/repo.git/api/v1/'.length);calls.push({path,bytes,key:req.headers['idempotency-key']});
   assert(req.url.startsWith('/repo.git/api/v1/'));
   if(path==='outcomes'){assert.equal(bytes.length,0);assert(req.headers['idempotency-key']);}
   else{
    const parts=uploadParts(bytes,req.headers['content-type']),command=new URLSearchParams(parts.get('command').toString());
    assert.equal(command.get('ref'),'refs/heads/main');assert.equal(command.get('object_format'),algorithm);assert.equal(command.get('expected_absent'),'true');
    assert.equal(command.has('expected_commit'),false);
    if(path==='source/initial/prepare'){assert.equal(req.headers['idempotency-key'],undefined);assert.deepEqual(parts.get('patch'),Buffer.from(f.plan.patch));assert(parts.get('patch').includes(0));}
    else{assert.equal(path,'source/initial/apply');assert.deepEqual(parts.get('bundle'),Buffer.from(f.bundle));assert.equal(command.get('candidate_commit'),f.plan.commit);}
   }
   // Drop the reply only after the full original body was received.
   if(path==='source/initial/apply'&&calls.filter(c=>c.path===path).length===1){req.socket.destroy();return;}
   const reply=await f.fetchImpl(`http://127.0.0.1${req.url}`,{method:'POST',body:path==='outcomes'?undefined:new Uint8Array(bytes),headers:req.headers});
   res.writeHead(reply.status,Object.fromEntries(reply.headers));res.end(Buffer.from(await reply.arrayBuffer()));
  }catch(error){assertion=error;res.destroy();}
 });
 server.listen(0,'127.0.0.1');await once(server,'listening');
 const href=`http://127.0.0.1:${server.address().port}/repo.git/ui/initial/`;
 try{
  const client=new InitialSourceClient({href,cryptoImpl:crypto,timeoutMs:2000});await client.connect(token);
  await client.prepare(f.fields,entries,metadata);await client.stageApply();assert.equal(calls.length,1);
  await assert.rejects(client.send(),e=>e.outcomeUnknown);assert.equal(calls.length,2);const receipt=client.exportReceipt(),key=client.pending.key;
  const restored=new InitialSourceClient({href,cryptoImpl:crypto,timeoutMs:2000});await restored.connect(token);await restored.restoreReceipt(receipt);assert.equal(calls.length,2);
  const absent=await restored.recover();assert.equal(absent.terminal,false);assert.equal(restored.pending.key,key);
  assert.equal((await restored.send()).outcome,'committed');assert.equal(restored.pending,null);
  assert.deepEqual(calls.map(c=>c.path),['source/initial/prepare','source/initial/apply','outcomes','source/initial/apply']);
  assert.deepEqual(calls[1].bytes,calls[3].bytes);assert.equal(calls[1].key,calls[3].key);assert.equal(calls[2].key,key);
  if(assertion)throw assertion;
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
