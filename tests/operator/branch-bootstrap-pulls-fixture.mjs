// Static native read-archive fixtures plus the actual production PR preparer.
// No replacement importer/loader/decoder is injected into the bridge.
import { mkdir, writeFile, readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fixture, ROTATED } from './branch-bootstrap-fixture.mjs';
import { preparePullImport } from '../../scripts/lib/native-pull-import.mjs';
import { encode, hash } from '../../scripts/lib/branch-bootstrap-protocol.mjs';

export async function migrationFixture(t,{format='sha1',pulls=2,sharedBase=true,byteOnly=false,modifySelection=null,modifyRow=null}={}) {
  const f=await fixture(t,{format}), archive=join(f.root,'source-archive'), token=join(f.root,'pr.token');
  await mkdir(archive,{mode:0o700});await writeFile(token,ROTATED,{mode:0o600});
  const oid=c=>`${format}:${c.repeat(format==='sha1'?40:64)}`, hex=s=>Buffer.from(s).toString('hex');
  const header={schema_version:1,tenant_id:'77'.repeat(16),repository_id:'88'.repeat(16),repository_incarnation:'99'.repeat(16),
    object_format:format,snapshot_token:'alg:2:'+'ab'.repeat(32),source_head:'source-head-1'};
  const rows=Array.from({length:pulls},(_,i)=>{
    const n=i+1,source_ref=`refs/heads/topic-${n}`,target_ref='refs/heads/main';
    const row={number:n,version:1,state:i%2?'closed':'open',merge_only:false,opened_by:'aa'.repeat(16),last_metadata_actor:'aa'.repeat(16),merge:null,
      data:{object_format:format,source_ref:byteOnly?null:source_ref,source_ref_hex:byteOnly?hex('refs/heads/topic-')+'ff'+hex(String(n)):hex(source_ref),
        target_ref,target_ref_hex:hex(target_ref),source_tip:oid(String(n%9+1)),target_tip:oid('b'),title:`History ${n}`,body:`Literal body ${n}\r\n雪`}};
    modifyRow?.(row);return row;
  });
  const pages=[{kind:'list',number:null,cursor:0,reply:{...header,type:'pull_request_page',after:0,limit:100,pull_requests:rows,next_after:null}}];
  for(const row of rows){
    const n=row.number;
    pages.push({kind:'show',number:n,cursor:0,reply:{...header,type:'pull_request',number:n,found:true,pull_request:row}});
    pages.push({kind:'reviews',number:n,cursor:null,reply:{...header,type:'review_page',number:n,found:true,
      pull_request_version:1,policy_epoch:1,after:null,limit:100,next_after:null,merge_authorized:false,reviews:[]}});
    pages.push({kind:'comments',number:n,cursor:0,reply:{...header,type:'pull_request_comments',number:n,found:true,
      discussion_version:1,after:0,limit:100,next_after:null,complete:true,merge_permission:null,transaction_created:false,
      comments:[{version:1,actor:'aa'.repeat(16),body:'A preserved observation',body_rendered:null}]}});
  }
  const m={schema:'frankengit-pull-read-archive-v1',href:'https://source.example/repo/ui/pulls/',tenant_id:header.tenant_id,
    repository_id:header.repository_id,repository_incarnation:header.repository_incarnation,object_format:format,
    snapshot_token:header.snapshot_token,source_head:header.source_head,page_size:100,pull_count:pulls,review_count:0,
    comment_count:pulls,data_bytes:0,pages:[]};
  for(const [i,p]of pages.entries()){
    const b=encode(p.reply);m.data_bytes+=b.length;
    m.pages.push({kind:p.kind,number:p.number,cursor:p.cursor,sha256:hash(b),bytes:b.length});
    await writeFile(join(archive,`page-${String(i+1).padStart(6,'0')}.json`),b,{mode:0o600});
  }
  const b=encode(m);await writeFile(join(archive,'archive.json'),b,{mode:0o600});
  const selected={endpoint:f.selection.endpoint,scope:{...f.selection.scope,principal_id:'55'.repeat(16)},number_start:'9007199254740993',
    pull_ref_map:rows.map(row=>({source_number:String(row.number),source_ref:`refs/heads/import/project/pr-${row.number}/source`,
      target_ref:sharedBase?'refs/heads/import/project/base':`refs/heads/import/project/pr-${row.number}/base`}))};
  modifySelection?.(selected);
  const prepare={workdir:join(f.root,'pull-job'),archiveDir:archive,archiveConfirm:hash(b),selection:selected,tokenFile:token};
  const migration=await preparePullImport(prepare);
  const bridge={migrationDir:migration.workdir,migrationConfirm:migration.plan_sha256,
    namespace:'refs/heads/import/project/',principal:f.selection.scope.principal_id};
  return {...f,archive,prToken:token,prepareMigration:prepare,migration,bridge,
    prepareBranches:{...bridge,workdir:join(f.root,'branches'),tokenFile:f.tokenFile}};
}
export async function fileHashes(root) {
  const out={};
  async function walk(dir,prefix=''){
    for(const item of await readdir(dir,{withFileTypes:true})){
      const p=join(dir,item.name),name=prefix+item.name;
      if(item.isDirectory())await walk(p,name+'/');else out[name]=hash(await readFile(p));
    }
  }
  await walk(root);return out;
}
