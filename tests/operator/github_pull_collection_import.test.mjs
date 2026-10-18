// Downstream compatibility through the complete unchanged native request compiler
// and codec. These checks do not run the Rust server or publish destination state.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, unlink } from 'node:fs/promises';
import { collectGithubPulls, selectGithubPullCollectionBatch } from '../../scripts/lib/github-pull-collection.mjs';
import { captureGithubPullBatch } from '../../scripts/lib/github-pull-inventory.mjs';
import { parseGithubPullCapture } from '../../scripts/lib/github-pull-source.mjs';
import { compileGithubPullImport } from '../../scripts/lib/github-pull-import-plan.mjs';
import { preparePull, validatePullIntent, pullTokenFingerprint } from '../../scripts/operator/pull_command.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { collectionFixture } from './github-pull-collection-fixture.mjs';
import { AT } from './github-pull-fixture.mjs';
const destination={endpoint:'https://destination.example/repo',scope:{tenant_id:'11'.repeat(16),repository_id:'22'.repeat(16),
  repository_incarnation:'33'.repeat(16),principal_id:'44'.repeat(16),object_format:'sha1'},namespace:'refs/heads/import/github/'};

test('finished collection compiles disjoint exact-u64 PR plans with unchanged source bodies and tips',async t=>{
  const f=await collectionFixture(t,{pulls:[9,17,23],records:1,alter:s=>{
    if(s.kind==='pull'&&s.n===17)Object.assign(s.value,{state:'closed',closed_at:AT,merged:true,merged_at:AT,merge_commit_sha:'e'.repeat(40)});
    if(s.kind==='pull'&&s.n===23){s.value.draft=true;s.value.head.sha='c'.repeat(40);}
  }},{batchSize:2});
  const done=await collectGithubPulls(f.run),numbers=[],branches=[];
  for(let batch=1;batch<=done.total_batches;batch++) {
    const selected=await selectGithubPullCollectionBatch({...f.status,completeConfirm:done.complete_sha256,batch,numberStart:'18446744073709551613'});
    const bytes=await readFile(selected.capture_file);assert.equal(recordDigest(bytes),selected.capture_sha256);
    const capture=parseGithubPullCapture(bytes),selection={...destination,number_start:selected.destination_number_start,merged:'as-closed',drafts:'as-ordinary'};
    const plan=compileGithubPullImport(capture,selection);
    const direct=await captureGithubPullBatch({inventory:f.inventory.inventory,confirm:f.inventory.sha256,batch,fetchImpl:f.fetchImpl});
    assert(bytes.equals(direct.bytes));assert.deepEqual(plan,compileGithubPullImport(direct.capture,selection));
    numbers.push(...plan.mapping.map(r=>r.destination));branches.push(...plan.refs.map(r=>r.ref));
    assert(plan.steps.every(s=>['open','comment','close'].includes(s.action)));
    for(const entry of capture.pulls) {
      const open=plan.steps.find(s=>s.source_number===entry.pull.number&&s.action==='open');
      assert.equal(open.fields.title,entry.pull.title);assert.equal(open.fields.body,entry.pull.body);
      assert.equal(open.fields.source_tip,entry.pull.head.sha);assert.equal(open.fields.target_tip,entry.pull.base.sha);
    }
    // Saved native intents still use only the original codec and independent
    // destination credential. No imported author can enter the principal field.
    for(const step of plan.steps) {
      const intent=preparePull({endpoint:selection.endpoint,scope:selection.scope,number:step.number,action:step.action,fields:step.fields},'aa'.repeat(32));
      assert.deepEqual(validatePullIntent(intent),intent);assert.equal(intent.credential_fingerprint,pullTokenFingerprint('aa'.repeat(32)));
      assert.equal(intent.scope.principal_id,destination.scope.principal_id);
    }
  }
  assert.deepEqual(numbers,['18446744073709551613','18446744073709551614','18446744073709551615']);
  assert.equal(new Set(branches).size,6);
});
test('collection completion does not waive native limits or merged/draft consent',async t=>{
  const f=await collectionFixture(t,{pulls:[9],alter:s=>{if(s.kind==='pull'){s.value.draft=true;s.value.title='x'.repeat(257);}}});
  const done=await collectGithubPulls(f.run);await f.close();await unlink(f.tokenFile);await unlink(f.inventoryFile);
  const selected=await selectGithubPullCollectionBatch({...f.status,completeConfirm:done.complete_sha256,batch:1,numberStart:'1'});
  const capture=parseGithubPullCapture(await readFile(selected.capture_file));
  assert.throws(()=>compileGithubPullImport(capture,{...destination,number_start:'1'}),/draft_requires_consent/);
  assert.throws(()=>compileGithubPullImport(capture,{...destination,number_start:'1',drafts:'as-ordinary'}),/invalid_pull_text/);
});
