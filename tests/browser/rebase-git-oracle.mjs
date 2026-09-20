// Explicit non-production compatibility oracle over real Git-produced rebases.
// It exercises browser validators, NOT the native Rust replay/admission engine.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash, webcrypto } from 'node:crypto';
import assert from 'node:assert/strict';
import { prepared } from '../../crates/fgit-node/src/smart_http/server/browser/rebase-data.mjs';
import { inspectReply } from '../../crates/fgit-node/src/smart_http/server/browser/rebase-inspection.mjs';
import { digest } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { multipart } from './source-edit-fixtures.mjs';
const [git, version, sha] = process.argv.slice(2);
if (!git || !isAbsolute(git) || !version || !/^[a-f0-9]{64}$/.test(sha ?? '')) throw new Error('Supply absolute Git executable, exact version string and executable SHA-256.');
const executable = realpathSync(git);
assert.equal(createHash('sha256').update(readFileSync(executable)).digest('hex'), sha, 'Git binary identity');
const root = mkdtempSync(join(tmpdir(), 'fg-rebase-oracle-'));
const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM:'1', GIT_CONFIG_GLOBAL:'/dev/null',
  GIT_TERMINAL_PROMPT:'0', GIT_EDITOR:'true', GIT_SEQUENCE_EDITOR:'true', LC_ALL:'C', TZ:'UTC',
  GIT_AUTHOR_NAME:'Original', GIT_AUTHOR_EMAIL:'o@example.invalid', GIT_COMMITTER_NAME:'Rebaser',
  GIT_COMMITTER_EMAIL:'r@example.invalid', GIT_AUTHOR_DATE:'@100 +0130', GIT_COMMITTER_DATE:'@1000 +0000' };
let checks = 0;
const equal = (a,b,label) => { assert.deepEqual(a,b,label); checks++; };
function run(cwd,args,input) {
  const p=spawnSync(executable,['-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false',...args],{cwd,env,input,timeout:20_000,maxBuffer:32*1024*1024});
  if(p.error || p.status!==0)throw new Error(`${args.join(' ')}: ${p.error?.message ?? p.stderr.toString()}`);
  return p.stdout;
}
const text=(cwd,args)=>run(cwd,args).toString('utf8').trim();
const cases=[];
try {
  equal(text(root,['--version']),version,'Git version');
  for(const format of ['sha1','sha256'])for(const scenario of ['linear','original-empty','drop-redundant','keep-redundant']) {
    const cwd=join(root,format+'-'+scenario);mkdirSync(cwd);
    run(cwd,['init','-q','--object-format='+format,'--initial-branch=main']);
    const blob=(s)=>Buffer.from('\0'+s+'\r\n','utf8');
    writeFileSync(join(cwd,'source.bin'),blob('base'));writeFileSync(join(cwd,'target.bin'),blob('base'));
    const rawPath=Buffer.concat([Buffer.from(cwd+'/'),Buffer.from([102,105,108,101,255])]);writeFileSync(rawPath,blob('untouched'));
    run(cwd,['add','--all']);run(cwd,['commit','-q','-m','base']);const upstream=text(cwd,['rev-parse','HEAD']);
    run(cwd,['checkout','-q','-b','topic']);
    const originals=[];
    function commit(message,value) {if(value!==null){writeFileSync(join(cwd,'source.bin'),blob(value));run(cwd,['add','source.bin']);}
      run(cwd,['commit','-q','--allow-empty','-m',message]);originals.push(text(cwd,['rev-parse','HEAD']));}
    commit('step-one','one');if(scenario==='original-empty')commit('original-empty',null);commit('step-two','two');
    const source=originals.at(-1),sourceTree=text(cwd,['rev-parse',source+'^{tree}']);
    run(cwd,['checkout','-q','main']);writeFileSync(join(cwd,'target.bin'),blob('onto'));
    if(scenario.endsWith('redundant'))writeFileSync(join(cwd,'source.bin'),blob('one'));
    run(cwd,['add','--all']);run(cwd,['commit','-q','-m','onto']);const onto=text(cwd,['rev-parse','HEAD']);
    const empty=scenario==='drop-redundant'?'drop':'keep';
    run(cwd,['rebase','--force-rebase','--keep-empty','--reapply-cherry-picks','--empty='+empty,'--onto',onto,upstream,'topic']);
    const candidate=text(cwd,['rev-parse','HEAD']),tree=id=>text(cwd,['rev-parse',id+'^{tree}']);
    const rewritten=text(cwd,['rev-list','--reverse',onto+'..'+candidate]).split('\n').filter(Boolean);
    equal(rewritten.length,originals.length-(scenario==='drop-redundant'?1:0),'rewritten count');
    equal(run(cwd,['show',candidate+':target.bin']),blob('onto'),'onto content preserved');
    equal(run(cwd,['show',candidate+':source.bin']),blob('two'),'source content replayed');
    equal(readFileSync(rawPath),blob('untouched'),'raw-path sibling preserved');
    const common={schema_version:1,tenant_id:'1'.repeat(32),repository_id:'2'.repeat(32),repository_incarnation:'3'.repeat(32),object_format:format};
    const snapshot='alg:2:'+'4'.repeat(64),sourceHead='oracle-synthetic-authority-not-native';
    const command={profile:'linear-v1',object_format:format,source_ref:'refs/heads/topic',onto_ref:'refs/heads/main',expected_source:source,
      expected_onto:onto,upstream,expected_head:snapshot,empty,committer:'Rebaser <r@example.invalid>',timestamp:1000,max_commits:32};
    const hex=s=>Buffer.from(s).toString('hex'),sourceHex=hex(command.source_ref);
    const scope={tenant:common.tenant_id,repository:common.repository_id,incarnation:common.repository_incarnation,format};
    const selection={scope,head:snapshot,sourceHead,source:{ref:command.source_ref,commit:source,tree:sourceTree},onto:{ref:command.onto_ref,commit:onto,tree:tree(onto)}};
    function change(before,after) {
      const chunks=run(cwd,['diff-tree','--no-commit-id','-r','--raw','-z','--no-abbrev','--no-renames',before,after]).toString('latin1').split('\0');
      const entries=[];
      for(let i=0;i<chunks.length-1;i+=2){const [oldMode,newMode,oldId,newId]=chunks[i].slice(1).split(' '),path=Buffer.from(chunks[i+1],'latin1');
        const identity=(mode,id)=>mode==='000000'?null:{mode,object_id:id};
        const old=identity(oldMode,oldId),next=identity(newMode,newId);
        const bytes=id=>run(cwd,['cat-file','blob',id]).length;
        entries.push({path_hex:path.toString('hex'),kind:!old?'added':!next?'deleted':oldMode!==newMode?'mode_changed':'modified',before:old,after:next,
          content:old&&next&&oldId===newId?{kind:'identical'}:{kind:'binary',before_bytes:old?bytes(oldId):0,after_bytes:next?bytes(newId):0}});}
      return {...common,type:'source_diff',profile:'native-tree-review-v1',source_head:sourceHead,snapshot_token:snapshot,mode:'direct',pull_request:null,
        read_only:true,transaction_created:false,published:false,approval_created:false,complete:true,line_origin:0,context_lines:3,
        before_ref_hex:sourceHex,after_ref_hex:sourceHex,requested_before:before,compared_before:before,requested_after:after,
        before_tree:tree(before),after_tree:tree(after),path_prefixes_hex:[],entry_count:entries.length,entries};
    }
    const steps=[],commits=[];let parent=onto,at=0;
    for(let i=0;i<originals.length;i++) {
      if(i===0&&scenario==='drop-redundant'){steps.push({original:originals[i],rewritten:parent,tree:tree(parent),kind:'dropped_empty'});continue;}
      const id=rewritten[at++],body=run(cwd,['cat-file','commit',id]),oldBody=run(cwd,['cat-file','commit',originals[i]]);
      const headers=body.toString('latin1').split('\n\n')[0].split('\n');
      equal(headers.filter(s=>s.startsWith('parent ')),['parent '+parent],'actual linear parent');
      equal(headers.find(s=>s.startsWith('author ')),oldBody.toString('latin1').split('\n').find(s=>s.startsWith('author ')),'original author preserved by Git');
      equal(body.subarray(body.indexOf('\n\n')+2),oldBody.subarray(oldBody.indexOf('\n\n')+2),'original message preserved by Git');
      steps.push({original:originals[i],rewritten:id,tree:tree(id),kind:tree(id)===tree(parent)?'preserved_empty':'replayed'});
      commits.push({index:commits.length,commit:id,parent,tree:tree(id),body_hex:body.toString('hex'),diff:change(parent,id)});parent=id;
    }
    const bundlePath=join(cwd,'candidate.bundle');run(cwd,['bundle','create',bundlePath,'refs/heads/topic','^'+onto]);run(cwd,['bundle','verify',bundlePath]);
    const bundle=new Uint8Array(readFileSync(bundlePath)),packStart=Buffer.from(bundle).indexOf('\n\nPACK')+2;
    assert(packStart>=2);const packCount=Buffer.from(bundle).readUInt32BE(packStart+8),sha256=await digest(bundle,webcrypto);
    const flags={read_only:true,objects_staged:false,transaction_created:false,published:false,publication_authorized:false};
    const metadata={...common,...flags,type:'rebase_preparation',profile:'linear-v1',source_head:sourceHead,snapshot_token:snapshot,
      source_ref:command.source_ref,onto_ref:command.onto_ref,source_ref_hex:sourceHex,onto_ref_hex:hex(command.onto_ref),
      expected_source:source,upstream,onto,empty,committer:command.committer,timestamp:1000,original_authors_preserved:true,
      original_messages_preserved:true,original_signatures_copied:false,author_identity_verified:false,state:'clean',series_complete:true,
      provisional_steps:false,candidate_commit:candidate,root_tree:tree(candidate),generated_objects:packCount,pack_objects:packCount,borrowed_objects:0,
      bundle:{bytes:bundle.length,sha256},stopped_commit:null,conflicts:[],step_count:steps.length,steps};
    const envelope=multipart(metadata,bundle,sha256);
    const {artifact}=await prepared({status:200,type:envelope.type,value:envelope.value},selection,command,[],webcrypto,()=>{});checks++;
    const report={...common,...flags,type:'rebase_inspection',profile:'linear-v1',source_head:sourceHead,snapshot_token:snapshot,
      expected_source:source,onto,candidate_commit:candidate,approval_created:false,replay_equivalence_verified:false,complete:true,
      all_changed_paths:true,all_rewritten_commits:true,binary_bodies_included:false,source_ref_hex:sourceHex,onto_ref_hex:hex(command.onto_ref),
      bundle:{bytes:bundle.length,pack_bytes:bundle.length-packStart,pack_objects:packCount,expanded_bytes:0,closure_objects:packCount,transport_only_objects:0,sha256},
      commit_count:commits.length,net_change:change(source,candidate),commits};
    await inspectReply(report,artifact,selection,webcrypto,()=>{});checks++;
    const corrupt=structuredClone(report);corrupt.commits.at(-1).body_hex+='00';await assert.rejects(inspectReply(corrupt,artifact,selection,webcrypto,()=>{}));checks++;
    run(cwd,['fsck','--strict']);checks++;
    cases.push({object_format:format,scenario,original_commits:originals.length,rewritten_commits:commits.length,candidate,tree:tree(candidate),git_fsck:true});
  }
  console.log(JSON.stringify({profile:'browser-rebase-git-compatibility-v1',git_version:version,git_sha256:sha,cases,checks_passed:checks,
    native_rust_executed:false,native_authority_tested:false,protocol_reports:'Constructed from real Git objects; not native server replies.'},null,2));
} finally { rmSync(root,{recursive:true,force:true}); }
