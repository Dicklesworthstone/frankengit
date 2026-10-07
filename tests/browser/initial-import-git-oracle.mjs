// Explicit, non-production, pinned Git oracle for INITIAL BINARY PATCH bytes.
// No network, native FrankenGit execution or proof of admission is asserted.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import { createHash, webcrypto } from 'node:crypto';
import assert from 'node:assert/strict';
import { initialPlan } from '../../crates/fgit-node/src/smart_http/server/browser/initial-plan.mjs';
const [git, version, executableHash] = process.argv.slice(2);
if (!git || !isAbsolute(git) || !version || !/^[0-9a-f]{64}$/.test(executableHash ?? '')) throw Error('Usage: node initial-import-git-oracle.mjs /absolute/git "git version <exact>" <executable-sha256>');
assert.equal(createHash('sha256').update(readFileSync(git)).digest('hex'), executableHash);
assert.equal(execFileSync(git, ['--version'], {encoding:'utf8',timeout:10000}).trim(), version);
const home=mkdtempSync(join(tmpdir(),'fg-initial-import-oracle-'));
const env={PATH:'/usr/bin:/bin',HOME:home,LANG:'C',LC_ALL:'C',TZ:'UTC',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',
 GIT_AUTHOR_NAME:'Author',GIT_AUTHOR_EMAIL:'a@example.invalid',GIT_AUTHOR_DATE:'@1 +0000',
 GIT_COMMITTER_NAME:'Committer',GIT_COMMITTER_EMAIL:'c@example.invalid',GIT_COMMITTER_DATE:'@1 +0000'};
const metadata={author:'Author <a@example.invalid>',committer:'Committer <c@example.invalid>',timestamp:1,message:'Initial binary project\n'};
const file=(path,bytes,mode=0o100644)=>({path_hex:Buffer.isBuffer(path)?path.toString('hex'):Buffer.from(path).toString('hex'),bytes:new Uint8Array(bytes),mode});
const cases=[
 ['all-byte-values',[file('all.bin',Buffer.from(Array.from({length:256},(_,i)=>i)))]],
 ['mixed',[file('assets/icon',Buffer.from([0,255,13,10])),file('README',Buffer.from('one\r\ntwo')),file('empty',Buffer.alloc(0),0o100755)]],
 ['path-order',[file('a.b',Buffer.from([0])),file('a/z',Buffer.from([255])),file('a0',Buffer.from([0,255]))]],
 ['raw-paths',[file(Buffer.from([0xff,47,97]),Buffer.from([0,1,255])),file('tab\tquote"\\',Buffer.from([0,10])),file('line\nname',Buffer.from([0]))]],
 ['marker-lines',[file('markers',Buffer.from('\0\n--- a/not-a-path\n+++ b/not-a-path\n@@ -0,0 +1 @@\n\\ No newline at end of file\n'))]],
 ['file-ceiling',[file('maximum.bin',Buffer.alloc(256*1024,0))]],
 ['count-ceiling',Array.from({length:64},(_,i)=>file(`dir/f${i}`,Buffer.from([0,i]),i%2?0o100755:0o100644))],
 ['same-blobs',[file('one',Buffer.from([0])),file('two',Buffer.from([0])),file('three',Buffer.alloc(0)),file('four',Buffer.alloc(0),0o100755)]],
];
const observations=[];let checks=0;
const equal=(a,b)=>{assert.deepEqual(a,b);checks++;};
try {
 for(const algorithm of ['sha1','sha256']) for(const [name,files] of cases) {
  const repo=join(home,`${algorithm}-${name}`);
  const run=(args,input)=>execFileSync(git,['-C',repo,...args],{env,input,timeout:15000,maxBuffer:16*1024*1024});
  execFileSync(git,['init','--quiet','--bare','--initial-branch=main',`--object-format=${algorithm}`,repo],{env,timeout:15000});
  const plan=await initialPlan(files,metadata,algorithm,webcrypto);
  run(['read-tree','--empty']);run(['apply','--cached','--binary','--whitespace=nowarn','-'],plan.patch);
  equal(run(['write-tree']).toString().trim(),plan.tree);
  const rows=run(['ls-files','--stage','-z']),actual=new Map();
  let start=0;
  for(let i=0;i<rows.length;i++) if(rows[i]===0) {
    const line=rows.subarray(start,i),tab=line.indexOf(9),[mode,id,stage]=line.subarray(0,tab).toString().split(' ');
    equal(stage,'0');actual.set(line.subarray(tab+1).toString('hex'),{mode:Number.parseInt(mode,8),id});start=i+1;
  }
  equal(actual.size,files.length);
  for(const f of files) {
    const item=actual.get(f.path_hex);assert(item);equal(item.mode,f.mode);
    equal(run(['cat-file','blob',item.id]),Buffer.from(f.bytes));
    equal(item.id,plan.files.find(row=>row.path_hex===f.path_hex).blob);
  }
  const commit=run(['commit-tree',plan.tree],metadata.message).toString().trim();equal(commit,plan.commit);
  equal(run(['cat-file','commit',commit]),Buffer.from(plan.commitBody));
  run(['update-ref','refs/heads/main',commit]);run(['fsck','--strict','--no-reflogs']);checks++;
  observations.push({algorithm,name,files:files.length,patch_bytes:plan.patch.length,tree:plan.tree,commit});
 }
 console.log(JSON.stringify({oracle:version,executable_sha256:executableHash,scenarios:observations.length,checks,results:observations,
   native_frankengit_executed:false,production_git_subprocess_added:false},null,2));
} finally { rmSync(home,{recursive:true,force:true}); }
