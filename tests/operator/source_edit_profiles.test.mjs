// Protocol-adversary fixtures, not evidence of native Rust engine execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { captureSourceEdit, validateSourceEdit, editInput, editCoordinates, canonical, EDIT_PROFILE_CAPTURE } from '../../scripts/operator/source_edit_candidate.mjs';
import { peer, TOKEN } from './source_edit_fixture.mjs';
const select = (f, pin = true, profile = 'exact-tree-binary-v1') => ({ ...structuredClone(f.request),
  ...(pin ? { expected_result_tree: f.tree } : {}), patch_profile: profile });
function echoes(f, input) {
  f.control.mutate = (reply, call) => {
    if (call.operation !== 'prepare') return;
    reply.patch_profile = input.patch_profile;
    if (Object.hasOwn(input, 'expected_result_tree')) reply.expected_result_tree = input.expected_result_tree;
  };
}
for (const format of ['sha1','sha256']) {
  for (const profile of ['exact-tree-v1','exact-tree-binary-v1']) for (const pin of [false,true]) {
    test(`${format}/${profile}/${pin}: opt-in reaches preparation only and survives offline replay`, async t => {
      const f = await peer(t,format), input = select(f,pin,profile); echoes(f,input);
      const result = await captureSourceEdit(input,f.patch,TOKEN);
      assert.equal(result.capture.schema,EDIT_PROFILE_CAPTURE);
      assert.deepEqual(result.capture.request,editInput(input));
      assert.deepEqual(validateSourceEdit(result.capture,result.bundle).capture,result.capture);
      assert.deepEqual(f.calls.map(c=>c.operation),['prepare','inspect']);
      assert.ok(f.calls[0].body.includes(Buffer.from(`patch_profile=${profile}`)));
      assert.equal(f.calls[0].body.includes(Buffer.from('expected_result_tree=')),pin);
      assert.ok(!f.calls[1].body.includes(Buffer.from('patch_profile')));
      assert.ok(!f.calls[1].body.includes(Buffer.from('expected_result_tree')));
      assert.deepEqual(editCoordinates(result.capture.request,f.candidate),editCoordinates(f.request,f.candidate));
      assert.ok(f.calls.every(c=>!c.headers['idempotency-key']));
    });
  }
  test(`${format}: ignored or downgraded profile refuses before inspection and never falls back`, async t => {
    for (const value of [undefined,'exact-tree-v1','exact-tree-binary-v2',null]) {
      const f = await peer(t,format), input = select(f); echoes(f,input); const echo = f.control.mutate;
      f.control.mutate = (reply,call) => { echo(reply,call); if (value === undefined) delete reply.patch_profile; else reply.patch_profile=value; };
      await assert.rejects(captureSourceEdit(input,f.patch,TOKEN));
      assert.deepEqual(f.calls.map(c=>c.operation),['prepare']);
    }
  });
  test(`${format}: root echo and actual root are independent requirements`, async t => {
    for (const alter of [r=>delete r.expected_result_tree,r=>r.expected_result_tree='f'.repeat(format==='sha1'?40:64),r=>r.root_tree='f'.repeat(format==='sha1'?40:64)]) {
      const f = await peer(t,format), input=select(f); echoes(f,input); const echo=f.control.mutate;
      f.control.mutate=(r,c)=>{echo(r,c);alter(r);};
      await assert.rejects(captureSourceEdit(input,f.patch,TOKEN));
      assert.equal(f.calls.length,1);
    }
  });
  test(`${format}: stripping or reinterpreting retained profile cannot validate v3`, async t => {
    const f=await peer(t,format), input=select(f); echoes(f,input);
    const result=await captureSourceEdit(input,f.patch,TOKEN);
    for (const alter of [c=>delete c.request.patch_profile,c=>delete c.preparation.patch_profile,c=>c.request.patch_profile='exact-tree-v1',c=>c.schema='frankengit-source-edit-capture-v2',c=>c.schema='frankengit-source-edit-capture-v1',c=>delete c.request.expected_result_tree]) {
      const changed=structuredClone(result.capture);alter(changed);
      assert.throws(()=>validateSourceEdit(changed,result.bundle));
      assert.notDeepEqual(canonical(changed),canonical(result.capture));
    }
  });
  test(`${format}: ordinary uploads retain v1 and v2 semantics, unsolicited profile refuses`, async t => {
    for (const pin of [false,true]) {
      const f=await peer(t,format), input={...f.request,...(pin?{expected_result_tree:f.tree}:{})};
      const result=await captureSourceEdit(input,f.patch,TOKEN);
      assert.equal(result.capture.schema,`frankengit-source-edit-capture-v${pin?2:1}`);
      assert.ok(f.calls.every(c=>!c.body.includes(Buffer.from('patch_profile'))&&!c.body.includes(Buffer.from('expected_result_tree'))));
      f.control.mutate=r=>r.patch_profile='exact-tree-v1';
      await assert.rejects(captureSourceEdit(input,f.patch,TOKEN));
    }
  });
  test(`${format}: caller mutation after acquisition starts cannot alter selected grammar`, async t => {
    const f=await peer(t,format), input=select(f), original=structuredClone(input);echoes(f,original);
    const task=captureSourceEdit(input,f.patch,TOKEN);input.patch_profile='exact-tree-v1';delete input.expected_result_tree;
    const result=await task;assert.deepEqual(result.capture.request,editInput(original));
  });
}
for (const [name,profile] of [['undefined',undefined],['null',null],['empty',''],['unknown','exact-v1'],['object',{}],['array',[]],['case','Exact-tree-v1'],['space','exact-tree-v1 '],['boolean',true]]) {
  test(`invalid ${name} profile refuses before any network request`,async t=>{
    const f=await peer(t), input={...f.request,patch_profile:profile};
    assert.throws(()=>editInput(input));await assert.rejects(captureSourceEdit(input,f.patch,TOKEN));assert.equal(f.calls.length,0);
  });
}
test('profile acquisition honors unchanged wire budgets and cancellation without fallback',async t=>{
  const f=await peer(t),input=select(f);echoes(f,input);
  const first=await captureSourceEdit(input,f.patch,TOKEN);
  await captureSourceEdit(input,f.patch,TOKEN,{maxWireBytes:first.metrics.response_bytes});
  await assert.rejects(captureSourceEdit(input,f.patch,TOKEN,{maxWireBytes:first.metrics.response_bytes-1}));
  const stop=new AbortController();stop.abort();const count=f.calls.length;
  await assert.rejects(captureSourceEdit(input,f.patch,TOKEN,{signal:stop.signal}));assert.equal(f.calls.length,count);
});
