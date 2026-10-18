import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir,writeFile,readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { executeGithubPullImport } from '../../scripts/lib/github-pull-import.mjs';
import { preparePullImport } from '../../scripts/lib/native-pull-import.mjs';
import { executePullImport } from '../../scripts/lib/native-pull-import-execute.mjs';
import { encode,digest,buildManifest,sealArchive,directory,lifetime } from '../../scripts/lib/forge-pull-archive-store.mjs';
import { PullArchiveWalk } from '../../scripts/lib/forge-pull-archive-protocol.mjs';
import { migrationFixture,SCOPE } from './github-pull-import-fixture.mjs';

test('native archive preparation/execution keeps its original schema and request path',async t=>{
 const f=await migrationFixture(t,{prepare:false}),root=join(f.root,'native-archive');await mkdir(root,{mode:0o700});
 const source={tenant:'55'.repeat(16),repository:'66'.repeat(16),incarnation:'77'.repeat(16),format:'sha1'},head='alg:2:'+'88'.repeat(32);
 const header={schema_version:1,tenant_id:source.tenant,repository_id:source.repository,repository_incarnation:source.incarnation,object_format:'sha1',snapshot_token:head,source_head:'native-head'};
 const row={number:9,version:1,state:'open',merge_only:false,opened_by:'99'.repeat(16),last_metadata_actor:'99'.repeat(16),merge:null,
  data:{object_format:'sha1',source_ref:'refs/heads/topic',source_ref_hex:Buffer.from('refs/heads/topic').toString('hex'),target_ref:'refs/heads/main',target_ref_hex:Buffer.from('refs/heads/main').toString('hex'),source_tip:'a'.repeat(40),target_tip:'b'.repeat(40),title:'Native title',body:'Native body'}};
 const replies=[{...header,type:'pull_request_page',after:0,limit:1,pull_requests:[row],next_after:null},
  {...header,type:'pull_request',number:9,found:true,pull_request:row},
  {...header,type:'review_page',number:9,found:true,merge_authorized:false,after:null,limit:1,reviews:[],next_after:null,pull_request_version:1,policy_epoch:1},
  {...header,type:'pull_request_comments',number:9,found:true,discussion_version:0,after:0,limit:1,comments:[],next_after:null,complete:true,merge_permission:null,transaction_created:false}];
 const walk=new PullArchiveWalk({...source,pageSize:1,limits:{pages:4,pulls:1,reviews:0,comments:0}}),pages=[];let size=0;
 for(const [i,reply] of replies.entries()){const request=walk.request;walk.accept(request,reply);const bytes=encode(reply);size+=bytes.length;
  pages.push({...request,sha256:digest(bytes),bytes:bytes.length});await writeFile(join(root,`page-${String(i+1).padStart(6,'0')}.json`),bytes,{mode:0o600});}
 const m=buildManifest({...source,href:'https://source.test/repo/ui/pulls/',pageSize:1},walk.finish(),pages,size),life=lifetime({});
 try{await sealArchive(root,m,life,await directory(root));}finally{life.close();}
 const job=join(f.root,'native-job'),prepared=await preparePullImport({workdir:job,archiveDir:root,archiveConfirm:digest(encode(m)),tokenFile:f.tokenFile,
  selection:{endpoint:f.peer.endpoint,scope:{...SCOPE},number_start:'200'}});
 const r=await executePullImport({workdir:job,confirm:prepared.plan_sha256,tokenFile:f.tokenFile,operation:'run'});
 assert.equal(r.type,'native_pull_import_progress');assert.equal(r.archive_sha256,digest(encode(m)));assert(!Object.hasOwn(r,'capture_sha256'));
 assert.equal(r.complete,true);assert.equal(r.steps,2);assert.deepEqual(f.peer.mutations.map(c=>c.action),['open','comment']);assert.equal(f.peer.mutations[0].fields.body,'Native body');
 const stable=await executePullImport({workdir:job,confirm:prepared.plan_sha256,operation:'status'});assert.equal(stable.complete,true);assert.equal(stable.network_accessed,false);
});
test('105-operation GitHub migration pauses at default 100 and resumes the same original keys',async t=>{
 const f=await migrationFixture(t,{source:{pulls:Array.from({length:21},(_,i)=>i+1)}});
 assert.equal(f.prepared.steps,105);const initial=await executeGithubPullImport(f.run);
 assert.equal(initial.complete,false);assert.equal(initial.committed_steps,100);assert.equal(f.peer.mutations.length,100);
 const second=await executeGithubPullImport(f.run);assert.equal(second.complete,true);assert.equal(second.new_operations,5);
 assert.equal(f.peer.mutations.length,105);assert.equal(new Set(f.peer.mutations.map(c=>c.key)).size,105);
});
test('concurrent runners do not both send the original first mutation',async t=>{
 let release;const arrived=new Promise(r=>release=r);let proceed;
 const blocked=new Promise(r=>proceed=r);let first=true;
 const f=await migrationFixture(t,{destination:{alter:async c=>{if(c.recovery&&first){first=false;release();await blocked;}}}});
 const a=executeGithubPullImport({...f.run,maxOperations:1});await arrived;
 const b=await executeGithubPullImport({...f.run,maxOperations:1});assert.equal(b.state,'pending');assert.equal(f.peer.mutations.length,0);
 proceed();const r=await a;assert.equal(r.committed_steps,1);assert.equal(f.peer.mutations.length,1);
 const done=await executeGithubPullImport(f.run);assert.equal(done.complete,true);assert.equal(f.peer.mutations.length,5);
});
test('late weaker concurrent read cannot erase a committed observation',async t=>{
 let started,continueRead;const seen=new Promise(r=>started=r),wait=new Promise(r=>continueRead=r);
 let dropping=true,holding=false,announced=false;
 const f=await migrationFixture(t,{destination:{alter:async c=>{
  if(!c.recovery&&dropping){c.res.destroy();return 'not-committed';}
  if(c.recovery&&holding&&!announced){announced=true;started();await wait;}
 }}});
 const pending=await executeGithubPullImport(f.run),key=pending.current.key;
 assert.equal(pending.state,'pending');assert.equal(f.peer.mutations.length,0);
 dropping=false;holding=true;
 const stale=executeGithubPullImport({...f.run,operation:'recover'});await seen;
 const committed=await executeGithubPullImport({...f.run,retryKey:key,maxOperations:1});
 assert.equal(committed.committed_steps,1);assert.equal(f.peer.mutations.length,1);
 continueRead();const late=await stale;assert.equal(late.committed_steps,1);
 const s=await executeGithubPullImport({workdir:f.workdir,confirm:f.prepared.plan_sha256,operation:'status'});
 assert.equal(s.committed_steps,1);assert.equal(f.peer.mutations.length,1);
});
