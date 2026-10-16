import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Writable } from 'node:stream';
import { join } from 'node:path';
import { writeFile, readFile, unlink, rm } from 'node:fs/promises';
import { fixture } from './branch-bootstrap-fixture.mjs';
import { migrationFixture, fileHashes } from './branch-bootstrap-pulls-fixture.mjs';
import { main } from '../../scripts/bootstrap_native_branches.mjs';

const script=fileURLToPath(new URL('../../scripts/bootstrap_native_branches.mjs',import.meta.url));
function start(t,args){
  const child=spawn(process.execPath,[script,...args],{stdio:['ignore','pipe','pipe']});let stdout='',stderr='';
  const exited=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('CLI fixture deadline'));},15000);
    child.stdout.on('data',b=>{stdout+=b;if(stdout.length>8*1024*1024)child.kill('SIGKILL');});
    child.stderr.on('data',b=>{stderr+=b;if(stderr.length>8*1024*1024)child.kill('SIGKILL');});
    child.once('error',e=>{clearTimeout(timer);reject(e);});
    child.once('close',(code,signal)=>{clearTimeout(timer);resolve({code,signal,stdout,stderr});});
  });
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
  return {child,exited};
}
const run=(t,args)=>start(t,args).exited;
function value(r,code=0){assert.equal(r.code,code,r.stderr);assert.equal(r.signal,null);assert.equal(r.stderr,'');return JSON.parse(r.stdout);}
async function selectionFile(f){const p=join(f.root,'selection.json');await writeFile(p,JSON.stringify(f.selection),{mode:0o600});return p;}
const stored=(f,p,command)=>[command,'--workdir',p.workdir,'--confirm',p.plan_sha256];
const network=(f,p,command='run')=>[...stored(f,p,command),'--token-file',f.tokenFile];
async function prep(t,f){return value(await run(t,['prepare','--workdir',f.prepare.workdir,'--selection',await selectionFile(f),'--token-file',f.tokenFile]));}

test('CLI preparation, exact bounded run, inspect, recovery and offline completion',async t=>{
  const f=await fixture(t),p=await prep(t,f);assert.equal(f.requests.length,0);assert.equal(p.complete,false);
  const inspected=value(await run(t,stored(f,p,'inspect')));assert.equal(inspected.selection.refs.length,3);assert.equal(inspected.state,'ready');
  const paused=value(await run(t,[...network(f,p),'--max-operations','1']),3);assert.equal(paused.committed,1);assert.equal(paused.state,'ready');
  const recovered=value(await run(t,network(f,p,'recover')),3);assert.equal(recovered.operations,0);assert.equal(f.posts(),1);
  const done=value(await run(t,network(f,p)));assert.equal(done.complete,true);assert.equal(f.posts(),3);
  await f.close();await unlink(f.tokenFile);
  assert.equal(value(await run(t,stored(f,p,'status'))).complete,true);
  assert.equal(value(await run(t,stored(f,p,'run'))).network_accessed,false);
});
for(const signal of ['SIGTERM','SIGINT','SIGKILL'])test(`new CLI process recovers after ${signal} during a committed native response`,async t=>{
  let child,stop=true;const f=await fixture(t,{behavior:{send:({res})=>{
    if(stop){stop=false;res.writeHead(200,{'content-type':'application/json'});res.write('{');assert(child.kill(signal));return false;}
  }}});
  const p=await prep(t,f),intent=await readFile(join(p.workdir,'requests','request-000001.json'));
  const active=start(t,network(f,p));child=active.child;const killed=await active.exited;
  if(signal==='SIGKILL'){assert.equal(killed.signal,'SIGKILL');assert.equal(killed.code,null);}
  else{assert.equal(killed.signal,null);assert.equal(killed.code,4);assert.equal(JSON.parse(killed.stderr).bootstrap_progress.plan_verified,true);}
  assert.equal(killed.stdout,'');const s=value(await run(t,stored(f,p,'status')));assert.equal(s.state,'unresolved');assert.equal(s.current.attempts,1);
  const done=value(await run(t,network(f,p)));assert.equal(done.complete,true);assert.equal(f.posts(),3);
  assert.equal(f.requests.filter(r=>r.path.endsWith('/create')&&r.key===JSON.parse(intent).key).length,1);
  assert((await readFile(join(p.workdir,'requests','request-000001.json'))).equals(intent));
});
test('CLI unresolved retry requires exactly the current original key',async t=>{
  let drop=true;const f=await fixture(t,{branches:1,behavior:{beforeSend:({res})=>{if(drop){res.destroy();return false;}}}});
  const p=await prep(t,f),uncertain=value(await run(t,network(f,p)),3);assert.equal(uncertain.state,'unresolved');
  value(await run(t,network(f,p)),3);assert.equal(f.posts(),1);
  drop=false;const done=value(await run(t,[...network(f,p),'--retry-key',uncertain.current.key]));assert.equal(done.complete,true);assert.equal(f.posts(),2);
  const posts=f.requests.filter(r=>r.path.endsWith('/create'));assert.equal(posts[0].key,posts[1].key);assert.equal(posts[0].body,posts[1].body);
});
test('CLI native refusal returns 1 and stops further creations',async t=>{
  const f=await fixture(t,{existing:[['refs/heads/import/0001','9'.repeat(40)]]}),p=await prep(t,f);
  const result=value(await run(t,network(f,p)),1);assert.equal(result.state,'refused');assert.equal(result.committed,0);assert.equal(f.posts(),1);
});
test('real command deadline drains the HTTP request and retains the original attempt',async t=>{
  const f=await fixture(t,{branches:1,behavior:{send:({res})=>{res.writeHead(200,{'content-type':'application/json'});res.write('{');return false;}}}),p=await prep(t,f);
  const r=await run(t,[...network(f,p),'--timeout-ms','150']);assert.equal(r.code,4);assert.equal(r.stdout,'');
  assert.equal(value(await run(t,stored(f,p,'status'))).state,'unresolved');
  assert.equal(value(await run(t,network(f,p))).complete,true);assert.equal(f.posts(),1);
});
test('broken output retains a prepared plan and never repeats a native call',async t=>{
  const f=await fixture(t),file=await selectionFile(f);let err='';
  const stdout=new Writable({write(_b,_e,done){done(new Error('closed output'));}});
  const stderr=new Writable({write(b,_e,done){err+=b;done();}});
  const code=await main(['prepare','--workdir',f.prepare.workdir,'--selection',file,'--token-file',f.tokenFile],{stdout,stderr});
  assert.equal(code,4);assert.equal(f.requests.length,0);const p=JSON.parse(err).retained_result;assert(p.plan_sha256);
  assert.equal(value(await run(t,stored(f,p,'status'))).state,'ready');assert.equal(value(await run(t,network(f,p))).complete,true);
});
test('stalled output remains bounded by the command deadline with retained result diagnostics',async t=>{
  const f=await fixture(t),p=await prep(t,f);let err='';
  const stdout=new Writable({write(){}}),stderr=new Writable({write(b,_e,done){err+=b;done();}});
  const code=await main([...stored(f,p,'status'),'--timeout-ms','80'],{stdout,stderr});
  assert.equal(code,4);assert.equal(JSON.parse(err).retained_result.plan_sha256,p.plan_sha256);assert.equal(f.requests.length,0);
});
test('CLI rejects ambiguous numbers, duplicated flags and implicit scope overrides before HTTP',async t=>{
  const f=await fixture(t),p=await prep(t,f);
  for(const extra of [['--max-operations','0'],['--max-operations','01'],['--max-operations','1e2'],['--max-operations','0x10'],
    ['--max-operations','8193'],['--timeout-ms','300001'],['--confirm',p.plan_sha256],['--force','true'],['--token','secret']]){
    const r=await run(t,[...network(f,p),...extra]);assert.equal(r.code,2);assert.equal(r.stdout,'');assert.equal(JSON.parse(r.stderr).type,'branch_bootstrap_error');
  }
  const bad=await run(t,[...network(f,p,'recover'),'--retry-key','fgbb1-'+'a'.repeat(32)+'-'+'b'.repeat(64)]);assert.equal(bad.code,2);
  const statusWithToken=await run(t,[...stored(f,p,'status'),'--token-file',f.tokenFile]);assert.equal(statusWithToken.code,2);
  assert.equal(f.requests.length,0);
});
test('requirements and prepare-pulls CLI use the full retained PR plan without altering any PR request',async t=>{
  const f=await migrationFixture(t),before=await fileHashes(f.migration.workdir);
  const common=['--migration-dir',f.bridge.migrationDir,'--migration-confirm',f.bridge.migrationConfirm,'--namespace',f.bridge.namespace,'--principal',f.bridge.principal];
  const r=value(await run(t,['requirements',...common]));assert.equal(r.required_branches,3);assert.equal(r.network_accessed,false);
  const p=value(await run(t,['prepare-pulls',...common,'--workdir',f.prepareBranches.workdir,'--token-file',f.tokenFile]));
  assert.equal(p.requirements_sha256,r.requirements_sha256);assert.equal(p.migration_plan_sha256,f.migration.plan_sha256);
  assert.deepEqual(await fileHashes(f.migration.workdir),before);assert.equal(f.requests.length,0);
  await rm(f.migration.workdir,{recursive:true});await rm(f.archive,{recursive:true});await unlink(f.prToken);
  assert.equal(value(await run(t,network(f,p))).complete,true);assert.equal(f.posts(),3);
});
test('missing branch principal cannot be inferred from PR grant or source attribution',async t=>{
  const f=await migrationFixture(t);
  const r=await run(t,['requirements','--migration-dir',f.bridge.migrationDir,'--migration-confirm',f.bridge.migrationConfirm,'--namespace',f.bridge.namespace]);
  assert.equal(r.code,2);assert.equal(f.requests.length,0);
});
test('CLI help states exact-key recovery and limited branch authority',async t=>{
  const help=value(await run(t,['--help'])).usage;assert.match(help,/ORIGINAL_PENDING_KEY/);assert.match(help,/Git objects must already/);assert.match(help,/source attribution is not authority/);
});
