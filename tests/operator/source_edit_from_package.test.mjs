import test from 'node:test';
import assert from 'node:assert/strict';
import { repository, definitions, expectedFor, packageFor, hex } from '../browser/search-context-package-fixture.mjs';
import { bindVerifiedEditSource } from '../../scripts/operator/source_edit_from_package.mjs';

function selection(repo, paths = [hex('src/main.rs')]) {
  return {
    endpoint: 'http://127.0.0.1:31337/repo.git',
    scope: {
      tenant_id: repo.scope.tenant_id,
      repository_id: repo.scope.repository_id,
      repository_incarnation: repo.scope.repository_incarnation,
      object_format: repo.format,
    },
    ref: 'refs/heads/main',
    expected_commit: repo.commit,
    metadata: {
      author: 'Agent <agent@example.invalid>',
      committer: 'Agent <agent@example.invalid>',
      timestamp: 1791910800,
      message: 'Package-bound edit\n',
    },
    paths_hex: paths,
  };
}
const bytes = value => Buffer.from(JSON.stringify(value));

for (const format of ['sha1', 'sha256']) test(`verified source package binds edit base and paths (${format})`, async () => {
  const repo = repository(format, definitions), expected = expectedFor(repo);
  const result = await bindVerifiedEditSource(bytes(packageFor(repo)), expected, selection(repo));
  assert.equal(result.source_package_verified, true);
  assert.equal(result.authority_verified, false);
  assert.equal(result.publication_authorized, false);
  assert.equal(result.verified_commit, repo.commit);
  assert.equal(result.request.expected_commit, repo.commit);
  assert.deepEqual(result.request.paths_hex, [hex('src/main.rs')]);
  assert.equal(result.verified_paths[0].blob, repo.files.get(hex('src/main.rs')).id);
  assert.equal(result.verified_paths[0].kind, 'executable');
});

test('edit cannot name a path outside the independently selected package', async () => {
  const repo = repository('sha1', definitions), expected = expectedFor(repo);
  await assert.rejects(bindVerifiedEditSource(bytes(packageFor(repo)), expected,
    selection(repo, [hex('unused/secret')])), /source_edit_package_path/);
});

test('edit base cannot differ from the verified native commit', async () => {
  const repo = repository('sha1', definitions), expected = expectedFor(repo), input = selection(repo);
  input.expected_commit = 'f'.repeat(40);
  await assert.rejects(bindVerifiedEditSource(bytes(packageFor(repo)), expected, input), /source_edit_package_commit/);
});

test('package corruption and changed independent selection refuse before edit use', async () => {
  const repo = repository('sha1', definitions), expected = expectedFor(repo);
  const corrupt = packageFor(repo); corrupt.blobs[0].bytesHex = '00' + corrupt.blobs[0].bytesHex.slice(2);
  await assert.rejects(bindVerifiedEditSource(bytes(corrupt), expected, selection(repo)));
  const changed = structuredClone(expected); changed.commit = 'f'.repeat(40);
  await assert.rejects(bindVerifiedEditSource(bytes(packageFor(repo)), changed, selection(repo)));
});

test('caller mutation after invocation cannot widen the checked edit selection', async () => {
  const repo = repository('sha1', definitions), expected = expectedFor(repo), input = selection(repo);
  const pending = bindVerifiedEditSource(bytes(packageFor(repo)), expected, input);
  input.paths_hex.push(hex('unused/secret')); input.expected_commit = 'f'.repeat(40);
  expected.files.length = 0;
  const result = await pending;
  assert.deepEqual(result.request.paths_hex, [hex('src/main.rs')]);
  assert.equal(result.verified_commit, repo.commit);
});
