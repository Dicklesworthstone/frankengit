import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { unlink, readFile } from 'node:fs/promises';
import { main } from '../../scripts/archive_native_pulls.mjs';
import { inspectPullCapture } from '../../scripts/lib/forge-pull-capture.mjs';
import { fixture, HEAD } from './pull-archive-fixture.mjs';

const script = fileURLToPath(new URL('../../scripts/archive_native_pulls.mjs',import.meta.url));
function start(t,args) {
  const child = spawn(process.execPath,[script,...args],{stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='';
  const exited = new Promise((resolve,reject) => {
    const timer=setTimeout(() => { child.kill('SIGKILL'); reject(new Error('test CLI deadline exceeded')); },8000);
    child.stdout.on('data',chunk => { stdout+=chunk; if(stdout.length>1024*1024)child.kill('SIGKILL'); });
    child.stderr.on('data',chunk => { stderr+=chunk; if(stderr.length>1024*1024)child.kill('SIGKILL'); });
    child.once('error',error => { clearTimeout(timer); reject(error); });
    child.once('close',(code,signal) => { clearTimeout(timer); resolve({code,signal,stdout,stderr}); });
  });
  t.after(() => { if(child.exitCode===null && child.signalCode===null)child.kill('SIGKILL'); });
  return {child,exited};
}
const run = (t,args) => start(t,args).exited;
function value(result,code=0) {
  assert.equal(result.code,code,result.stderr); assert.equal(result.signal,null);
  assert.equal(result.stderr,''); const lines=result.stdout.trim().split('\n'); assert.equal(lines.length,1);
  return JSON.parse(lines[0]);
}
function selectArgs(f,operation='prepare') {
  return [operation,'--workdir',join(f.root,'job'),'--url',f.href,'--tenant',f.options.tenant,
    '--repository',f.options.repository,'--token-file',f.token,'--page-size','1'];
}
const storedArgs = (f,p,operation='resume') => [operation,'--workdir',join(f.root,'job'),'--confirm',p.selection_sha256];
const resumeArgs = (f,p) => [...storedArgs(f,p),'--token-file',f.token];

test('actual CLI prepares, pauses, resumes and inspects its ordinary archive',async t => {
  const f=await fixture(t), p=value(await run(t,selectArgs(f)));
  assert.equal(p.complete,false);assert.equal(p.pages,1);
  const status=value(await run(t,storedArgs(f,p,'status')));assert.equal(status.checkpoint_sha256,p.checkpoint_sha256);assert.equal(status.network_accessed,false);
  const paused=value(await run(t,[...resumeArgs(f,p),'--page-budget','1']),3);
  assert.equal(paused.complete,false);assert.equal(paused.pages,2);assert.equal(paused.new_requests,1);
  const finished=value(await run(t,resumeArgs(f,p)));assert.equal(finished.complete,true);assert.equal(f.requests.length,14);
  assert(f.requests.slice(1).every(request=>request.head===HEAD));
  await f.close();await unlink(f.token);
  const read=value(await run(t,['inspect','--workdir',finished.archive_workdir,'--confirm',finished.archive_sha256]));
  assert.equal(read.complete,true);assert.equal(read.network_accessed,false);
  const cached=value(await run(t,storedArgs(f,p)));assert.equal(cached.complete,true);assert.equal(cached.new_requests,0);
  const observed=value(await run(t,storedArgs(f,p,'status')));assert.equal(observed.archive_sha256,finished.archive_sha256);
});

for(const signal of ['SIGTERM','SIGINT','SIGKILL'])test(`fresh CLI resumes after actual ${signal} while a continuation body is stalled`,async t => {
  let block=false, child, interrupted=false;
  const f=await fixture(t,{alter:({kind,res})=>{
    // The show response/checkpoint has been written before reviews are requested.
    if(block && kind==='reviews') {
      res.writeHead(200,{'content-type':'application/json'});res.write('{');
      interrupted=child.kill(signal);return false;
    }
  }});
  const p=value(await run(t,selectArgs(f)));
  const first=await readFile(join(f.root,'job','archive','page-000001.json'));
  block=true;
  const pending=start(t,resumeArgs(f,p));child=pending.child;const stopped=await pending.exited;
  assert.equal(interrupted,true);assert.equal(stopped.stdout,'');
  if(signal==='SIGKILL'){assert.equal(stopped.signal,'SIGKILL');assert.equal(stopped.code,null);}
  else {assert.equal(stopped.signal,null);assert.equal(stopped.code,4);assert.equal(JSON.parse(stopped.stderr).capture_progress.selection_verified,true);}
  block=false;
  const status=value(await run(t,storedArgs(f,p,'status')));assert.equal(status.pages,2);assert.equal(status.checkpointed_pages,2);assert.equal(status.complete,false);
  const completed=value(await run(t,resumeArgs(f,p)));assert.equal(completed.complete,true);
  assert.equal(f.requests.length,15); // Fourteen pages plus exactly one interrupted GET.
  assert.equal(f.requests.filter(r=>r.kind==='show'&&r.number===1).length,1);
  assert(f.requests.slice(1).every(r=>r.head===HEAD));
  assert((await readFile(join(f.root,'job','archive','page-000001.json'))).equals(first));
});

test('command output failure retains the selection and never repeats a request',async t => {
  const f=await fixture(t);let stderr='';
  const output=new Writable({write(_chunk,_encoding,callback){callback(new Error('test broken pipe'));}});
  const errors=new Writable({write(chunk,_encoding,callback){stderr+=chunk;callback();}});
  const exit=await main(selectArgs(f),{stdout:output,stderr:errors});assert.equal(exit,4);assert.equal(f.requests.length,1);
  const result=JSON.parse(stderr).retained_result;assert(result.selection_sha256);assert.equal(result.complete,false);
  const status=await inspectPullCapture({workdir:join(f.root,'job'),confirm:result.selection_sha256});assert.equal(status.checkpointed_pages,1);
  const finished=value(await run(t,resumeArgs(f,result)));assert.equal(finished.complete,true);assert.equal(f.requests.length,14);
});

test('invalid command selectors refuse before HTTP or custody changes',async t => {
  const f=await fixture(t),p=value(await run(t,selectArgs(f))),n=f.requests.length;
  for(const args of [
    [...resumeArgs(f,p),'--head',HEAD], [...resumeArgs(f,p),'--max-pages','16384'],
    [...resumeArgs(f,p),'--page-budget','0'], [...resumeArgs(f,p),'--page-budget','0x10'],
    [...resumeArgs(f,p),'--page-budget','1e2'], [...resumeArgs(f,p),'--page-budget','01'],
    [...resumeArgs(f,p),'--confirm',p.selection_sha256], ['resume','--workdir',join(f.root,'job')],
    ['status','--workdir','relative','--confirm',p.selection_sha256],['__proto__'],
  ]){const refused=await run(t,args);assert.equal(refused.code,2);assert.equal(refused.stdout,'');assert.equal(JSON.parse(refused.stderr).type,'pull_archive_error');}
  assert.equal(f.requests.length,n);assert.equal(value(await run(t,storedArgs(f,p,'status'))).checkpoint_sha256,p.checkpoint_sha256);
});

test('one-shot export and inspect remain available in the expanded CLI',async t => {
  const f=await fixture(t,{pulls:0});const result=value(await run(t,selectArgs(f,'export')));assert.equal(result.complete,true);
  await f.close();await unlink(f.token);
  const inspected=value(await run(t,['inspect','--workdir',join(f.root,'job'),'--confirm',result.archive_sha256]));assert.equal(inspected.complete,true);
});

test('help describes pins and explicit paused completion',async t => {
  const help=value(await run(t,['--help']));assert.match(help.usage,/SELECTION_SHA256/);assert.match(help.usage,/resume exit 3/);
});
