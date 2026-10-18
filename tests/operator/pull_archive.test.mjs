import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportPullArchive, inspectPullArchive } from '../../scripts/lib/forge-pull-archive.mjs';

const TEN='11'.repeat(16), REP='22'.repeat(16), INC='33'.repeat(16), ACT='44'.repeat(16), REV='55'.repeat(16);
const HEAD='alg:2:'+ '66'.repeat(32), SOURCE='source-head-1';
const hex=s=>Buffer.from(s).toString('hex');
function row(n){return {number:n,version:1,state:'open',merge_only:false,data:{object_format:'sha1',source_ref:`refs/heads/topic${n}`,source_ref_hex:hex(`refs/heads/topic${n}`),target_ref:'refs/heads/main',target_ref_hex:hex('refs/heads/main'),source_tip:String(n).padStart(40,'a').slice(-40),target_tip:'b'.repeat(40),title:`PR ${n}`,body:`Body ${n}`},opened_by:ACT,last_metadata_actor:ACT,merge:null};}
function common(){return {schema_version:1,tenant_id:TEN,repository_id:REP,repository_incarnation:INC,object_format:'sha1',source_head:SOURCE,snapshot_token:HEAD};}
function fixtureBackend(){
 const binding={tenant:TEN,repository:REP,incarnation:INC,format:'sha1'};
 return {
  close(){},
  async list({after,limit,head}){assert(head===null||head===HEAD);const prs=after===0?[row(1)]:[row(2)];return {binding,head:HEAD,reply:{...common(),type:'pull_request_page',after,limit,pull_requests:prs,next_after:after===0?1:null}};},
  async show(n,head){assert.equal(head,HEAD);return {binding,head:HEAD,reply:{...common(),type:'pull_request',number:n,found:true,pull_request:row(n)}};},
  async reviews(n,{after,limit,head}){assert.equal(head,HEAD);const rs=after===null?[{reviewer:REV,version:1,subject:{number:n,source_ref:`refs/heads/topic${n}`,source_ref_hex:hex(`refs/heads/topic${n}`),target_ref:'refs/heads/main',target_ref_hex:hex('refs/heads/main'),pull_request_version:1,policy_epoch:1,source_tip:String(n).padStart(40,'a').slice(-40),target_tip:'b'.repeat(40)},candidate:null,decision:'approve',freshness:'current',reviewer_is_opener:false,reason:'ok'}]:[];return {binding,head:HEAD,reply:{...common(),type:'review_page',number:n,found:true,merge_authorized:false,after,limit,reviews:rs,next_after:null,pull_request_version:1,policy_epoch:1}};},
  async comments(n,{after,limit,head}){assert.equal(head,HEAD);const cs=after===0?[{version:1,actor:ACT,body:`comment ${n}`,body_rendered:null}]:[];return {binding,head:HEAD,reply:{...common(),type:'pull_request_comments',number:n,found:true,discussion_version:1,after,limit,next_after:null,complete:true,merge_permission:null,transaction_created:false,comments:cs}};},
  validate(kind,reply,ctx){assert.equal(reply.snapshot_token,HEAD);assert.equal(reply.source_head,SOURCE);if(kind==='show')assert.equal(reply.number,ctx.number);return {binding,head:HEAD,reply};}
 };
}
async function env(){const root=await mkdtemp(join(tmpdir(),'fg-pull-'));await chmod(root,0o700);const token=join(root,'token');await writeFile(token,'aa'.repeat(32)+'\n',{mode:0o600});return {root,token,out:join(root,'archive')};}
const opts=e=>({workdir:e.out,href:'https://forge.test/repo/ui/pulls/',tenant:TEN,repository:REP,tokenFile:e.token,pageSize:1});

test('exports and inspects full PR metadata/reviews/conversations',async()=>{const e=await env();const result=await exportPullArchive(opts(e),fixtureBackend());assert.equal(result.pulls,2);assert.equal(result.reviews,2);assert.equal(result.comments,2);assert.equal(result.complete,true);const names=await readdir(e.out);assert(names.includes('archive.json'));assert.equal(names.filter(n=>n.startsWith('page-')).length,8);const inspected=await inspectPullArchive({workdir:e.out,confirm:result.archive_sha256},fixtureBackend());assert.equal(inspected.pulls,2);assert.equal(inspected.reviews,2);assert.equal(inspected.comments,2);assert.equal(inspected.network_accessed,false);});
test('pins explicit snapshot across every request',async()=>{const e=await env();const seen=[];const b=fixtureBackend();for(const name of ['list','show','reviews','comments']){const original=b[name];b[name]=async(...args)=>{const v=await original(...args);seen.push(v.head);return v;};}const r=await exportPullArchive({...opts(e),head:HEAD},b);assert.equal(r.snapshot_token,HEAD);assert(seen.every(v=>v===HEAD));});
test('corrupted saved page fails offline inspection',async()=>{const e=await env();const r=await exportPullArchive(opts(e),fixtureBackend());await writeFile(join(e.out,'page-000002.json'),'{}\n');await assert.rejects(inspectPullArchive({workdir:e.out,confirm:r.archive_sha256},fixtureBackend()),/pull_archive_page_commitment/);});
test('pull budget refuses before a successful complete claim',async()=>{const e=await env();await assert.rejects(exportPullArchive({...opts(e),maxPulls:1},fixtureBackend()),/pull_archive_pull_limit/);const names=await readdir(e.out);assert(!names.includes('archive.json'));});
test('unknown retained files invalidate archive inspection',async()=>{const e=await env();const r=await exportPullArchive(opts(e),fixtureBackend());await writeFile(join(e.out,'extra'),Buffer.from('x'),{mode:0o600});await assert.rejects(inspectPullArchive({workdir:e.out,confirm:r.archive_sha256},fixtureBackend()),/pull_archive_unexpected_file/);});
test('root manifest binds every page hash',async()=>{const e=await env();const r=await exportPullArchive(opts(e),fixtureBackend());const manifest=JSON.parse(await readFile(join(e.out,'archive.json'),'utf8'));assert.equal(manifest.pages.length,8);assert.equal(manifest.pull_count,2);assert.equal(manifest.review_count,2);assert.equal(manifest.comment_count,2);assert(manifest.pages.every(p=>/^[0-9a-f]{64}$/.test(p.sha256)));assert.equal(r.archive_sha256,(await import('node:crypto')).createHash('sha256').update(await readFile(join(e.out,'archive.json'))).digest('hex'));});
