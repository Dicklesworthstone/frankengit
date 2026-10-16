import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './branch-bootstrap-fixture.mjs';
import { prepareBootstrap, runBootstrap, bootstrapStatus } from '../../scripts/lib/branch-bootstrap.mjs';
const gate=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};

test('101 real HTTP creations cross the default 100-operation boundary without duplicate keys',async t=>{
  const f=await fixture(t,{branches:101}),p=await prepareBootstrap(f.prepare),o={workdir:p.workdir,confirm:p.plan_sha256,tokenFile:f.tokenFile};
  const first=await runBootstrap(o);assert.equal(first.committed,100);assert.equal(first.complete,false);assert.equal(first.operations,100);
  const last=await runBootstrap(o);assert.equal(last.committed,101);assert.equal(last.complete,true);assert.equal(last.operations,1);
  const posts=f.requests.filter(r=>r.path.endsWith('/create'));assert.equal(posts.length,101);assert.equal(new Set(posts.map(r=>r.key)).size,101);
});
test('late concurrent absence cannot erase an independently confirmed native commit',async t=>{
  const createArrived=gate(),allowCreate=gate(),recoveryArrived=gate(),allowRecovery=gate();let held=false;
  const f=await fixture(t,{branches:1,behavior:{
    beforeSend:async()=>{held=true;createArrived.resolve();await allowCreate.promise;},
    outcome:async({result})=>{if(held&&!result.terminal){recoveryArrived.resolve();await allowRecovery.promise;return result;}}
  }}),p=await prepareBootstrap(f.prepare),o={workdir:p.workdir,confirm:p.plan_sha256,tokenFile:f.tokenFile};
  t.after(()=>{allowCreate.resolve();allowRecovery.resolve();});
  const writer=runBootstrap(o);await createArrived.promise;
  const reader=runBootstrap({...o,operation:'recover'});await recoveryArrived.promise;
  allowCreate.resolve();assert.equal((await writer).complete,true);
  allowRecovery.resolve();assert.equal((await reader).complete,true);assert.equal(f.posts(),1);
  const s=await bootstrapStatus({workdir:p.workdir,confirm:p.plan_sha256});assert.equal(s.complete,true);assert.equal(s.attempts,2);
});
for(const mode of ['redirect','oversized','wrong-principal'])test(`HTTP ${mode} response cannot authorize successful bootstrap`,async t=>{
  const f=await fixture(t,{branches:1,behavior:{send:({res,pub})=>{
    if(mode==='redirect'){res.writeHead(307,{location:'http://127.0.0.1:1/elsewhere'});res.end();return false;}
    if(mode==='oversized'){res.writeHead(200,{'content-type':'application/json','content-length':'20000'});res.end('x'.repeat(20000));return false;}
    pub.principal_id='ff'.repeat(16);return pub;
  }}}),p=await prepareBootstrap(f.prepare),o={workdir:p.workdir,confirm:p.plan_sha256,tokenFile:f.tokenFile};
  const r=await runBootstrap(o);assert.equal(r.state,'unresolved');assert.equal(r.complete,false);assert.equal(f.posts(),1);
  const recovered=await runBootstrap(o);assert.equal(recovered.complete,true);assert.equal(f.posts(),1);
});
