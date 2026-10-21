// An HTTP response-schema peer, not Rust fg, native Git or an authority proof.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, chmod, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hash, outcomeBinding } from '../../scripts/lib/branch-bootstrap-protocol.mjs';

export const TOKEN='aa'.repeat(32), ROTATED='bb'.repeat(32);
export const SCOPE={tenant_id:'11'.repeat(16),repository_id:'22'.repeat(16),repository_incarnation:'33'.repeat(16),principal_id:'44'.repeat(16),object_format:'sha1'};
export const wire=value=>JSON.stringify(value).replace(/"decision_sequence":"([0-9]+)"/g,'"decision_sequence":$1');
export function absent(scope=SCOPE){return {type:'transaction_outcome',schema_version:1,...outcomeBinding(scope),selector:'transaction',command_index:null,
  state:'key_not_observed',terminal:false,transaction:null,decision:null,read_only:true,request_reexecuted:false,
  absence_proves_non_commit:false,session_completeness_established:false};}
export async function fixture(t,{format='sha1',branches=3,behavior={},existing=[]}={}){
  // Custody paths are canonical by contract; macOS's default TMPDIR is an alias.
  const root=await realpath(await mkdtemp(join(tmpdir(),'fg-bootstrap-')));await chmod(root,0o700);
  const tokenFile=join(root,'token');await writeFile(tokenFile,`${TOKEN}\n`,{mode:0o600});
  const scope={...SCOPE,object_format:format},requests=[],outcomes=new Map(),publications=new Map(),refs=new Map(existing),sockets=new Set();
  let sequence=9007199254740991n,posts=0;
  const server=createServer(async(req,res)=>{
    try{
      const chunks=[];let size=0;
      for await(const chunk of req){size+=chunk.length;assert(size<=16384);chunks.push(chunk);}
      const body=Buffer.concat(chunks).toString('utf8'),key=req.headers['idempotency-key'];
      assert.equal(req.method,'POST');assert(/^fgbb1-[0-9a-f]{32}-[0-9a-f]{64}$/.test(key));
      assert([`Bearer ${TOKEN}`,`Bearer ${ROTATED}`].includes(req.headers.authorization));
      assert.equal(req.headers['accept-encoding'],'identity');
      const call={path:req.url,key,body,token:req.headers.authorization};requests.push(call);
      if(req.url==='/repo/api/v1/outcomes'){
        assert.equal(body,'');let result=structuredClone(outcomes.get(key)??absent(scope));
        if(behavior.outcome){const v=await behavior.outcome({req,res,key,result,call});if(v===false)return;if(v)result=v;}
        res.writeHead(200,{'content-type':'application/json'});res.end(wire(result));return;
      }
      assert.equal(req.url,'/repo/api/v1/source/branches/create');posts++;
      assert.equal(req.headers['content-type'],'application/x-www-form-urlencoded');
      const form=new URLSearchParams(body);assert.deepEqual([...form.keys()],['object_format','ref','new_commit']);
      assert.equal(form.get('object_format'),format);assert(form.get('ref').startsWith('refs/heads/import/'));
      assert.equal(form.get('new_commit').length,format==='sha1'?40:64);
      if(behavior.beforeSend && await behavior.beforeSend({req,res,key,form,call})===false)return;
      let pub=publications.get(key);
      if(!pub){
        const committed=!refs.has(form.get('ref')), n=String(++sequence), tx=`tx-${n}`;
        const decision=committed?{kind:'committed',decision_sequence:n,repository_commit_id:`rcr-${n}`}:
          {kind:'refused',decision_sequence:n,code:'ExpectedOldRefMismatch',code_point:5,refusal_record_id:`refusal-${n}`};
        const result={...absent(scope),state:decision.kind,terminal:true,
          transaction:{tx_id:tx,seal_id:`seal-${n}`,request_schema:'native-receive-v1',canonical_request_digest:{algorithm:2,hex:hash(Buffer.from(body))}},decision};
        outcomes.set(key,result);if(committed)refs.set(form.get('ref'),form.get('new_commit'));
        pub={type:'branch_publication',schema_version:1,...scope,operation:'create',atomic:true,terminal:true,tx_id:tx,decision_sequence:n,
          outcome:decision.kind,...(committed?{repository_commit_id:decision.repository_commit_id}:{code:decision.code,code_point:decision.code_point,refusal_record_id:decision.refusal_record_id}),
          forge_transition:false,updates:[{ref:form.get('ref'),ref_hex:Buffer.from(form.get('ref')).toString('hex'),expected_commit:null,
            new_commit:`${format}:${form.get('new_commit')}`,force:false}]};
        publications.set(key,pub);
      }
      pub=structuredClone(pub);
      if(behavior.send){const v=await behavior.send({req,res,key,pub,call});if(v===false)return;if(v)pub=v;}
      res.writeHead(pub.outcome==='committed'?200:409,{'content-type':'application/json'});res.end(wire(pub));
    }catch(error){res.writeHead(500,{'content-type':'application/json'});res.end(JSON.stringify({error:error.message}));}
  });
  server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  let closed=false;const close=async()=>{if(closed)return;closed=true;for(const s of sockets)s.destroy();await new Promise(resolve=>server.close(resolve));};
  t.after(async()=>{await close();await rm(root,{recursive:true,force:true});});
  const endpoint=`http://127.0.0.1:${server.address().port}/repo`, selection={endpoint,scope,namespace:'refs/heads/import/',
    refs:Array.from({length:branches},(_,i)=>({ref:`refs/heads/import/${String(i+1).padStart(4,'0')}`,new_commit:((i%9)+1).toString().repeat(format==='sha1'?40:64)}))};
  return {root,tokenFile,selection,requests,refs,outcomes,publications,close,behavior,posts:()=>posts,
    prepare:{workdir:join(root,'job'),selection,tokenFile}};
}
