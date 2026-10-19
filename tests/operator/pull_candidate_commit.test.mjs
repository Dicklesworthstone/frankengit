import test from 'node:test';
import assert from 'node:assert/strict';
import { candidateCommitMatches } from '../../scripts/operator/pull_candidate_commit.mjs';

const sha1 = {
  format: 'sha1', tree: '1'.repeat(40), targetTip: '2'.repeat(40), sourceTip: '3'.repeat(40),
  metadata: { author: 'Alice <alice@example.invalid>', committer: 'Bob <bob@example.invalid>', timestamp: '1700000000', message: 'Merge exact bytes\n🦀\n' },
};
function body(input, method) {
  const incoming = method === 'merge-commit' ? `parent ${input.sourceTip}\n` : '';
  return Buffer.from(`tree ${input.tree}\nparent ${input.targetTip}\n${incoming}author ${input.metadata.author} ${input.metadata.timestamp} +0000\ncommitter ${input.metadata.committer} ${input.metadata.timestamp} +0000\n\n${input.metadata.message}`).toString('hex');
}
for (const method of ['merge-commit', 'squash']) test(`${method} exact construction matches`, () => {
  assert.equal(candidateCommitMatches({ ...sha1, method, bodyHex: body(sha1, method) }), true);
});
for (const [name, mutate] of [
  ['tree', x => x.tree = '4'.repeat(40)], ['target', x => x.targetTip = '4'.repeat(40)], ['source', x => x.sourceTip = '4'.repeat(40)],
  ['author', x => x.metadata.author = 'Mallory <m@example.invalid>'], ['committer', x => x.metadata.committer = 'Mallory <m@example.invalid>'],
  ['timestamp', x => x.metadata.timestamp = '1700000001'], ['message', x => x.metadata.message += 'changed'],
]) test(`retained ${name} mismatch refuses`, () => {
  const original = structuredClone(sha1), bodyHex = body(original, 'merge-commit'), changed = structuredClone(original); mutate(changed);
  assert.equal(candidateCommitMatches({ ...changed, method: 'merge-commit', bodyHex }), false);
});
test('method mismatch refuses', () => {
  assert.equal(candidateCommitMatches({ ...sha1, method: 'squash', bodyHex: body(sha1, 'merge-commit') }), false);
  assert.equal(candidateCommitMatches({ ...sha1, method: 'merge-commit', bodyHex: body(sha1, 'squash') }), false);
});
test('sha256 and empty final newline semantics are exact', () => {
  const x = { ...sha1, format: 'sha256', tree:'1'.repeat(64), targetTip:'2'.repeat(64), sourceTip:'3'.repeat(64), metadata:{...sha1.metadata,message:'no final newline'} };
  assert.equal(candidateCommitMatches({ ...x, method:'squash', bodyHex: body(x,'squash') }), true);
});
for (const bad of ['', '0', 'zz', '00']) test(`invalid body hex ${JSON.stringify(bad)} refuses`, () => {
  assert.equal(candidateCommitMatches({ ...sha1, method:'merge-commit', bodyHex: bad }), false);
});
