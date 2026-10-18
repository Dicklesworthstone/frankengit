import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp,writeFile,readFile,chmod,unlink,rm,access,mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { main } from '../../scripts/migrate_github_pulls.mjs';
import { githubPeer,REPO,TOKEN } from './github-pull-fixture.mjs';
const script=new URL('../../scripts/migrate_github_pulls.mjs',import.meta.url).pathname;
async function env(t,options={}){
  const root=await mkdtemp(join(tmpdir(),'fg-github-pull-'));await chmod(root,0o700);t.after(()=>rm(root,{recursive:true,force:true}));
  const token=join(root,'token'),out=join(root,'capture.json'),preload=join(root,'test-http.mjs');await writeFile(token,TOKEN+'\n',{mode:0o600});
  await writeFile(preload,`const original=globalThis.fetch;globalThis.fetch=async(url,init)=>{const u=new URL(url);if(u.origin!=='https://api.github.com')throw new Error('unexpected source');const r=await original(process.env.FG_TEST_PEER+u.pathname+u.search,init);return new Response(r.body,{status:r.status,headers:r.headers});};`);
  const peer=await githubPeer(t,options);
  const capture=['capture','--repository',REPO,'--pull','9','--out',out,'--token-file',token];
  const start=args=>{const child=spawn(process.execPath,['--import',preload,script,...args],{env:{...process.env,FG_TEST_PEER:peer.origin}});let stdout='',stderr='';
    const done=new Promise((resolve,reject)=>{const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('CLI test deadline'));},5000);
      child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);child.once('error',reject);
      child.once('close',(code,signal)=>{clearTimeout(timer);resolve({code,signal,stdout,stderr});});});
    t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});return {child,done};};
  return {root,token,out,peer,capture,start,run:args=>start(args).done};
}
const okay=r=>{assert.equal(r.code,0,r.stderr);assert.equal(r.stderr,'');return JSON.parse(r.stdout);};
test('fresh CLI captures to private file and inspects offline with independent pin',async t=>{
  const e=await env(t),r=okay(await e.run(e.capture));assert.equal(r.pulls,1);assert.equal(e.peer.calls.length,14);
  const bytes=await readFile(e.out);assert(bytes.length>0);assert(!bytes.includes(Buffer.from(TOKEN)));await e.peer.close();await unlink(e.token);
  const s=okay(await e.run(['inspect-capture','--capture',e.out,'--confirm',r.capture_sha256]));assert.equal(s.network_accessed,false);assert.equal(s.pulls[0].reviews,1);
  const bad=await e.run(['inspect-capture','--capture',e.out,'--confirm','0'.repeat(64)]);assert.equal(bad.code,2);
});
test('existing output and worktree destinations refuse before any source request',async t=>{
  const e=await env(t);await writeFile(e.out,'kept',{mode:0o600});assert.equal((await e.run(e.capture)).code,2);assert.equal(await readFile(e.out,'utf8'),'kept');
  await unlink(e.out);await mkdir(join(e.root,'.git'));assert.equal((await e.run(e.capture)).code,2);assert.equal(e.peer.calls.length,0);
});
for(const signal of ['SIGTERM','SIGINT','SIGKILL'])test(`actual ${signal} does not publish a partial capture`,async t=>{
  let child;const e=await env(t,{alter:s=>{if(s.kind==='reviews'){s.res.writeHead(200,{'content-type':'application/json'});s.res.write('[');child.kill(signal);return false;}}});
  const run=e.start(e.capture);child=run.child;const r=await run.done;assert.equal(r.stdout,'');assert(signal==='SIGKILL'?r.signal==='SIGKILL':r.code===2);
  await assert.rejects(access(e.out));
});
test('output failure retains the completed capture and pin',async t=>{
  const e=await env(t),fetch=globalThis.fetch;globalThis.fetch=e.peer.fetchImpl;let err='';
  const stdout=new Writable({write(_b,_e,cb){cb(new Error('broken output'));}}),stderr=new Writable({write(b,_e,cb){err+=b;cb();}});
  try{assert.equal(await main(e.capture,{stdout,stderr}),4);}finally{globalThis.fetch=fetch;}
  const result=JSON.parse(err).retained_result;assert(result.capture_sha256);assert.equal(e.peer.calls.length,14);assert((await readFile(e.out)).length>0);
});
test('closed argument grammar does not permit URLs, secrets or rounded numbers',async t=>{
  const e=await env(t);for(const extra of [['--url','https://evil.test'],['--token','secret'],['--timeout-ms','1e2'],['--pull','01'],['--out',e.out]]){
    const r=await e.run([...e.capture,...extra]);assert.equal(r.code,2);assert.equal(r.stdout,'');
  }assert.equal(e.peer.calls.length,0);
});
