import test from 'node:test';
import assert from 'node:assert/strict';
import { preparePull, preparePullWithIdentity, validatePullIntent, pullCanonical, pullHash, pullTokenFingerprint,
  pullEnvelope } from '../../scripts/operator/pull_command.mjs';
const token='ab'.repeat(32),scope=format=>({tenant_id:'11'.repeat(16),repository_id:'22'.repeat(16),repository_incarnation:'33'.repeat(16),principal_id:'44'.repeat(16),object_format:format});
function input(format,action){
 const oid=c=>c.repeat(format==='sha1'?40:64),coordinates={source_ref:'refs/heads/topic',target_ref:'refs/heads/main',source_tip:oid('a'),target_tip:oid('b')};
 let fields;
 if(action==='comment')fields={expected_version:'18446744073709551614',body:'\ufeff雪\r\ncomment'};
 else if(action==='fast-forward')fields={pull_request_version:'2',...coordinates};
 else if(['approve','request-changes','withdraw','merge'].includes(action))fields={pull_request_version:'2',policy_epoch:'1',...coordinates,merge_base:oid('c'),candidate_commit:oid('d'),
  ...(action==='merge'?{required_reviewers:['55'.repeat(16)],method:'squash'}:{expected_version:action==='withdraw'?'1':'0',reason:'review'})};
 else fields={expected_version:action==='open'?'0':'2',...coordinates,title:'Title',body:'\ufeff雪\r\nbody'};
 return {endpoint:'https://forge.example/repo',scope:scope(format),number:'18446744073709551615',action,fields};
}
for(const format of ['sha1','sha256'])for(const action of ['open','update','close','reopen','comment','fast-forward','approve','request-changes','withdraw','merge'])
 test(`retained identity reproduces ordinary ${format} ${action} exactly`,()=>{
  const request=input(format,action),bundle=['approve','request-changes','merge'].includes(action)?Buffer.from('opaque transport fixture; not native Git'):null;
  const original=preparePull(request,token,bundle);
  const rebuilt=preparePullWithIdentity(request,{nonce:original.nonce,credential_fingerprint:original.credential_fingerprint},bundle);
  assert.equal(pullCanonical(rebuilt),pullCanonical(original));assert.deepEqual(validatePullIntent(rebuilt),original);
  assert.deepEqual(pullEnvelope(rebuilt,bundle),pullEnvelope(original,bundle));
  const {key,...basis}=rebuilt;assert.equal(key,`${['approve','request-changes','withdraw','merge'].includes(action)?'fgpc1':'fgp1'}-${rebuilt.nonce}-${pullHash(JSON.stringify(basis))}`);
 });
test('retained identity is a closed offline input, not a credential or nonce override',()=>{
 const r=input('sha1','open'),id={nonce:'1'.repeat(32),credential_fingerprint:pullTokenFingerprint(token)};
 for(const v of [{...id,nonce:'1'.repeat(31)},{...id,nonce:'g'.repeat(32)},{...id,credential_fingerprint:token.toUpperCase()},
  {...id,force:true},{nonce:id.nonce},null])assert.throws(()=>preparePullWithIdentity(r,v));
 assert.notEqual(preparePull(r,token).key,preparePull(r,token).key);
});
test('candidate boundary validation remains in the common preparation path',()=>{
 const r=input('sha1','approve'),identity={nonce:'1'.repeat(32),credential_fingerprint:pullTokenFingerprint(token)};
 assert.throws(()=>preparePullWithIdentity(r,identity,Buffer.from('--fg-pull-candidate-'+identity.nonce)),/boundary_collision/);
});
