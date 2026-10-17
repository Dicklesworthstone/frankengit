import test from 'node:test';
import assert from 'node:assert/strict';
import { captureGithubPulls,encodeGithubPulls,parseGithubPullCapture } from '../../scripts/lib/github-pull-source.mjs';
import { compileGithubPullImport,githubPullImportSelection } from '../../scripts/lib/github-pull-import-plan.mjs';
import { pullHash } from '../../scripts/operator/pull_command.mjs';
import { githubPeer,AT } from './github-pull-fixture.mjs';
export const target=()=>({endpoint:'https://destination.test/repo',scope:{tenant_id:'11'.repeat(16),repository_id:'22'.repeat(16),
  repository_incarnation:'33'.repeat(16),principal_id:'44'.repeat(16),object_format:'sha1'},number_start:'100',namespace:'refs/heads/import/github/'});
function restored(steps){const groups=[];let current;
 for(const step of steps.filter(s=>s.action==='comment')){
  const cut=step.fields.body.indexOf('\n\n'),[warning,header]=step.fields.body.slice(0,cut).split('\n');assert.match(warning,/not native approval/);
  const h=JSON.parse(header);if(h.part===1){current={header:h,parts:[]};groups.push(current);}assert.equal(h.part,current.parts.length+1);
  assert.equal(h.sha256,current.header.sha256);current.parts.push(step.fields.body.slice(cut+2));
 }
 return groups.map(g=>{assert.equal(g.parts.length,g.header.parts);const bytes=Buffer.from(g.parts.join(''));assert.equal(pullHash(bytes),g.header.sha256);return {kind:g.header.kind,record:JSON.parse(bytes)};});
}
test('compiles only native open/comment/close with exact historical refs and attribution',async t=>{
 const f=await githubPeer(t),c=(await captureGithubPulls(f.options)).capture,p=compileGithubPullImport(c,target());
 assert.deepEqual(p.steps.map(s=>s.action),['open','comment','comment','comment','comment']);assert.equal(p.mapping[0].destination,'100');
 assert.equal(p.steps[0].fields.body,c.pulls[0].pull.body);assert.equal(p.steps[0].fields.source_tip,c.pulls[0].pull.head.sha);
 assert.equal(p.steps[0].fields.source_ref,'refs/heads/import/github/pr-9/head');assert.equal(p.refs.length,2);
 assert.deepEqual(p.steps.filter(s=>s.action==='comment').map(s=>s.fields.expected_version),['0','1','2','3']);
 const r=restored(p.steps);assert.deepEqual(r.map(x=>x.record),[c.pulls[0].pull,c.pulls[0].discussion[0],c.pulls[0].reviews[0],c.pulls[0].inline[0]]);
 assert.equal(r[2].record.state,'APPROVED');assert.equal(p.steps.filter(s=>s.action==='approve'||s.action==='merge').length,0);
 assert.equal(p.captureSha256,pullHash(encodeGithubPulls(c)));assert.deepEqual(compileGithubPullImport(c,target()),p);
});
test('splits large review and diff provenance without changing BOM/CRLF/Unicode bytes',async t=>{
 const f=await githubPeer(t,{alter:s=>{if(s.kind==='reviews')s.value[0].body='\ufeff'+('雪\r\n'.repeat(10000));
  if(s.kind==='inline'){s.value[0].diff_hunk='💻'.repeat(15000);s.value[0].body='\ufeff\r\n';}}});
 const c=(await captureGithubPulls(f.options)).capture,p=compileGithubPullImport(c,target()),r=restored(p.steps);
 assert(p.steps.length>5);assert.deepEqual(r[2].record,c.pulls[0].reviews[0]);assert.deepEqual(r[3].record,c.pulls[0].inline[0]);
 assert(p.steps.every(s=>Buffer.byteLength(s.body)<=256*1024));
});
test('metadata-less body remains null in provenance but empty in native field',async t=>{
 const f=await githubPeer(t,{alter:s=>{if(s.kind==='pull')s.value.body=null;}}),c=(await captureGithubPulls(f.options)).capture;
 const p=compileGithubPullImport(c,target());assert.equal(p.steps[0].fields.body,'');assert.equal(restored(p.steps)[0].record.body,null);
});
for(const [name,changes,consent] of [['draft',{draft:true},{drafts:'as-ordinary'}],
 ['merged',{state:'closed',merged:true,closed_at:AT,merged_at:AT,merge_commit_sha:'d'.repeat(40)},{merged:'as-closed'}]])test(`${name} needs explicit destination lifecycle consent`,async t=>{
 const f=await githubPeer(t,{alter:s=>{if(s.kind==='pull')Object.assign(s.value,changes);}}),c=(await captureGithubPulls(f.options)).capture;
 assert.throws(()=>compileGithubPullImport(c,target()),/requires_consent/);const p=compileGithubPullImport(c,{...target(),...consent});
 assert.equal(p.steps.at(-1).action,name==='merged'?'close':'comment');if(name==='merged')assert.equal(p.steps.at(-1).fields.expected_version,'1');
});
test('native title/body limits refuse compilation rather than truncating captured source',async t=>{
 for(const [key,v] of [['title','x'.repeat(257)],['body','x'.repeat(65537)]]){
  const f=await githubPeer(t,{alter:s=>{if(s.kind==='pull')s.value[key]=v;}}),c=(await captureGithubPulls(f.options)).capture;
  assert.throws(()=>compileGithubPullImport(c,target()),/invalid_pull_text/);assert.equal(c.pulls[0].pull[key],v);
 }
});
test('exact u64 numbering and per-PR branch bases do not alias historical tips',async t=>{
 const f=await githubPeer(t,{pulls:[9,17],alter:s=>{if(s.kind==='pull'&&s.n===17)s.value.base.sha='c'.repeat(40);}}),c=(await captureGithubPulls(f.options)).capture;
 const p=compileGithubPullImport(c,{...target(),number_start:'18446744073709551614'});
 assert.deepEqual(p.mapping.map(r=>r.destination),['18446744073709551614','18446744073709551615']);assert.equal(new Set(p.refs.map(r=>r.ref)).size,4);
 assert.throws(()=>compileGithubPullImport(c,{...target(),number_start:'18446744073709551615'}),/u64/);
});
test('compile rejects unknown fields, authorization overrides, domain translation and limits',async t=>{
 const f=await githubPeer(t),c=(await captureGithubPulls(f.options)).capture;
 for(const delta of [{force:true},{source_actor:'admin'},{namespace:'refs/heads/'},{namespace:'refs/heads/../'},{namespace:'refs/tags/import/'},
  {number_start:100},{number_start:'01'},{scope:{...target().scope,object_format:'sha256'}},{merged:'merge'},{drafts:'ignore'},
  {max_steps:1},{max_request_bytes:1}])assert.throws(()=>compileGithubPullImport(c,{...target(),...delta}));
 const bad=structuredClone(c);bad.pulls[0].reviews[0].authority=true;assert.throws(()=>compileGithubPullImport(bad,target()));
 assert.deepEqual(parseGithubPullCapture(encodeGithubPulls(c)),c);assert.equal(githubPullImportSelection(target()).namespace,target().namespace);
});
