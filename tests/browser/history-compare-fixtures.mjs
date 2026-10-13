// Native source/log/diff/historical response contracts, not a running Rust node.
import { createHash, webcrypto } from 'node:crypto';
import { HistoryClient } from '../../crates/fgit-node/src/smart_http/server/browser/history.mjs';
export { webcrypto };
export const hex = value => Buffer.from(value).toString('hex');
export const token = '1'.repeat(64);
export const clone = value => structuredClone(value);
export const jsonResponse = (value, status = 200, headers = {}) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json', ...headers },
});
export function gitHash(kind, value, algorithm) {
  const body = Buffer.from(value);
  return createHash(algorithm).update(`${kind} ${body.length}\0`).update(body).digest('hex');
}
export function fixture(algorithm = 'sha1') {
  const width = algorithm === 'sha1' ? 40 : 64, tag = id => `${algorithm}:${id}`;
  const beforeTree = 'b'.repeat(width), afterTree = 'c'.repeat(width);
  const commit = (tree, message) => {
    const body = `tree ${tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n${message}\n`;
    const id = gitHash('commit', body, algorithm);
    return { id, row: { object_id: tag(id), tree: tag(tree), parents: [], body_hex: hex(body) } };
  };
  const beforeCommit = commit(beforeTree, 'before'), afterCommit = commit(afterTree, 'after'), baseCommit = commit(beforeTree, 'base');
  const beforeRef = 'refs/heads/main', afterRef = 'refs/heads/topic';
  const beforeBody = Buffer.from('before\r\n'), afterBody = Buffer.from('after\n');
  const beforeBlob = gitHash('blob', beforeBody, algorithm), afterBlob = gitHash('blob', afterBody, algorithm);
  const scope = { tenant_id: 'tenant-fixture', repository_id: 'repo-fixture', repository_incarnation: 'incarnation-fixture', object_format: algorithm };
  const common = { schema_version: 1, ...scope, source_head: 'fixture-authority-head', snapshot_token: `alg:2:${'a'.repeat(64)}`,
    read_only: true, transaction_created: false, published: false };
  const lineSpan = bytes => ({ byte_start: 0, byte_end: bytes.length, line_start: 0,
    line_count: [...bytes].filter(b => b === 10).length + Number(bytes.length > 0 && bytes.at(-1) !== 10) });
  function entry(path = 'src/file.txt') {
    return { path_hex: hex(path), kind: 'modified', before: { object_id: tag(beforeBlob), mode: '100644' },
      after: { object_id: tag(afterBlob), mode: '100644' }, content: { kind: 'text', algorithm: 'Myers', additions: 1, deletions: 1,
        before_bytes: beforeBody.length, after_bytes: afterBody.length, hunks: [{ old: lineSpan(beforeBody), new: lineSpan(afterBody),
          before_hex: hex(beforeBody), after_hex: hex(afterBody) }] } };
  }
  const log = () => ({ ...common, type: 'source_log', ref_hex: hex(afterRef), source_commit: tag(afterCommit.id),
    author_identity_verified: false, ordering: 'child-before-parent-native-id-v1', page_complete: true,
    after: 0, limit: 20, total_commits: 1, next_after: null, commits: [clone(afterCommit.row)] });
  const diff = (patch = {}) => ({ ...common, type: 'source_diff', profile: 'native-tree-review-v1', mode: 'direct',
    pull_request: null, approval_created: false, complete: true, line_origin: 0, context_lines: 3,
    before_ref_hex: hex(beforeRef), after_ref_hex: hex(afterRef), requested_before: tag(beforeCommit.id), requested_after: tag(afterCommit.id),
    compared_before: tag(beforeCommit.id), before_tree: tag(beforeTree), after_tree: tag(afterTree), entry_count: 1,
    path_prefixes_hex: [], entries: [entry()], ...patch });
  function historical(form) {
    const isBefore = form.get('ref') === beforeRef, body = isBefore ? beforeBody : afterBody;
    const offset = Number(form.get('offset')), limit = Number(form.get('limit')), value = body.subarray(offset, offset + limit);
    return { type: 'historical_source', schema_version: 1, read_only: true, transaction_created: false, published: false,
      selection: 'visible-ref-ancestor-v1', source_ref_tip: tag(form.get('expected_ref_tip')), at_commit: tag(form.get('at_commit')),
      source: { ...common, type: 'source_blob', ref_hex: hex(form.get('ref')), source_commit: tag(form.get('at_commit')),
        path_hex: form.get('path_hex'), object_id: tag(isBefore ? beforeBlob : afterBlob), root_tree: tag(isBefore ? beforeTree : afterTree),
        source_rcr: 'fixture-commit-record', offset, total_bytes: body.length, returned_bytes: value.length,
        next_offset: offset + value.length < body.length ? offset + value.length : null,
        content_hex: hex(value), symlink_followed: false, kind: 'file' } };
  }
  return { algorithm, width, tag, common, beforeRef, afterRef, before: beforeCommit.id, after: afterCommit.id, base: baseCommit.id,
    beforeTree, afterTree, beforeBody, afterBody, beforeBlob, afterBlob, entry, log, diff, historical, lineSpan };
}
export function harness(f = fixture(), respond = null, options = {}) {
  const calls = [];
  const client = new HistoryClient({ href: 'https://forge.example/team/repo.git/ui/history/', cryptoImpl: webcrypto,
    ...options, fetchImpl: async function (url, request) {
      const call = { url: String(url), ...request, form: new URLSearchParams(request.body) }; calls.push(call);
      const result = await respond?.(call, client); if (result !== undefined && result !== null) return result;
      const endpoint = new URL(url).pathname.split('/').at(-1);
      if (endpoint === 'log') return jsonResponse(f.log());
      if (endpoint === 'diff') return jsonResponse(f.diff({ mode: call.form.get('mode'),
        compared_before: f.tag(call.form.get('mode') === 'merge-base' ? f.base : f.before),
        path_prefixes_hex: call.form.getAll('path_prefix_hex') }));
      if (endpoint === 'historical-blob') return jsonResponse(f.historical(call.form));
      throw new Error(`Unexpected fixture endpoint ${endpoint}`);
    } });
  const open = async () => { client.connect(token); return client.open(f.afterRef, f.algorithm); };
  return { client, calls, open, f };
}
