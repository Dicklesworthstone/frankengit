// Explicit non-production Git-object interoperability lane. This runs stock
// Git in isolated disposable repositories, NOT the native Rust replay engine.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, webcrypto } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { replayInspected } from '../../crates/fgit-node/src/smart_http/server/browser/replay-protocol.mjs';
const [git, expectedVersion, expectedHash] = process.argv.slice(2);
assert(git?.startsWith('/') && expectedVersion && /^[0-9a-f]{64}$/.test(expectedHash ?? ''), 'Usage: node replay-git-oracle.mjs /absolute/git "git version X" binary-sha256');
assert.equal(createHash('sha256').update(readFileSync(git)).digest('hex'), expectedHash, 'Git executable differs from the pinned binary');
const root = mkdtempSync(join(tmpdir(), 'fg-replay-oracle-'));
const who = 'Replay Oracle <oracle@example.invalid>', timestamp = 1700000000;
const env = { PATH: '/usr/bin:/bin', HOME: root, XDG_CONFIG_HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_TERMINAL_PROMPT: '0', GIT_AUTHOR_NAME: 'Replay Oracle', GIT_AUTHOR_EMAIL: 'oracle@example.invalid',
  GIT_COMMITTER_NAME: 'Replay Oracle', GIT_COMMITTER_EMAIL: 'oracle@example.invalid',
  GIT_AUTHOR_DATE: `${timestamp} +0000`, GIT_COMMITTER_DATE: `${timestamp} +0000`, LC_ALL: 'C' };
const command = (args, cwd) => execFileSync(git, ['-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgSign=false', '-c', 'core.autocrlf=false', ...args],
  { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000, maxBuffer: 16 * 1024 * 1024 });
const text = (args, cwd) => command(args, cwd).toString('utf8').trim();
let checks = 0; const cells = [];
try {
  assert.equal(text(['--version'], root), expectedVersion);
  for (const algorithm of ['sha1', 'sha256']) {
    const dir = join(root, algorithm); mkdirSync(dir); command(['init', '-q', '-b', 'main', `--object-format=${algorithm}`], dir);
    const commit = message => { command(['add', '--all'], dir); command(['commit', '-q', '-m', message], dir); return text(['rev-parse', 'HEAD'], dir); };
    writeFileSync(join(dir, 'file'), 'base\r\n'); const base = commit('base');
    command(['checkout', '-q', '-b', 'topic'], dir); writeFileSync(join(dir, 'file'), 'topic with no final newline');
    const source = commit('one exact change'); command(['checkout', '-q', 'main'], dir);
    writeFileSync(join(dir, 'destination-only'), 'destination\n'); const target = commit('destination change');
    async function inspect(label, before) {
      const candidate = text(['rev-parse', 'HEAD'], dir), tree = text(['rev-parse', 'HEAD^{tree}'], dir), beforeTree = text(['rev-parse', `${before}^{tree}`], dir);
      const bytes = command(['cat-file', 'commit', candidate], dir), separator = bytes.indexOf('\n\n'); assert(separator > 0);
      const message = bytes.subarray(separator + 2).toString('utf8'), ref = 'refs/heads/main';
      const packPath = join(root, `${algorithm}-${cells.length}.bundle`); command(['bundle', 'create', packPath, ref], dir);
      const bundle = new Uint8Array(readFileSync(packPath)), sha256 = createHash('sha256').update(bundle).digest('hex');
      const entries = [], records = command(['diff-tree', '-r', '--no-commit-id', '--raw', '-z', '--no-renames', before, candidate], dir);
      let offset = 0;
      while (offset < records.length) {
        let end = records.indexOf(0, offset); assert(end >= 0); const fields = records.subarray(offset, end).toString('ascii').split(' '); offset = end + 1;
        end = records.indexOf(0, offset); assert(end >= 0); const path = records.subarray(offset, end); offset = end + 1;
        const [oldMode, newMode, oldId, newId, state] = fields;
        const side = (mode, oid) => /^0+$/.test(oid) ? null : { mode: Number.parseInt(mode.replace(':', ''), 8), oid };
        entries.push({ path_hex: path.toString('hex'), kind: state === 'A' ? 'added' : state === 'D' ? 'deleted' : 'modified',
          before: side(oldMode, oldId), after: side(newMode, newId), content: { type: 'object_only', content_read: false } });
      }
      entries.sort((a, b) => a.path_hex < b.path_hex ? -1 : 1);
      const scope = { tenant: '1'.repeat(32), repository: '2'.repeat(32), incarnation: '3'.repeat(32), format: algorithm }, head = `alg:1:${'4'.repeat(64)}`;
      const fields = { ref, object_format: algorithm, expected_commit: before, candidate_commit: candidate };
      const artifact = { fields, scope, bundle, sha256, tree, choices: null, command: { expected_head: head, author: who, committer: who, timestamp, message } };
      const reply = { ...fields, type: 'source_inspection', schema_version: 1, tenant_id: scope.tenant, repository_id: scope.repository,
        repository_incarnation: scope.incarnation, source_head: 'synthetic-authority-not-native-proof', snapshot_token: head,
        ref_hex: Buffer.from(ref).toString('hex'), all_changed_paths: true, binary_bodies_included: false,
        read_only: true, objects_staged: false, transaction_created: false, published: false, publication_authorized: false,
        bundle_bytes: bundle.length, bundle_sha256: sha256, parents: [before], candidate_commit_body_hex: bytes.toString('hex'),
        comparison: { mode: 'direct', before_tree: beforeTree, after_tree: tree, entries, entry_count: entries.length } };
      await replayInspected(reply, artifact, beforeTree, webcrypto); checks++;
      await assert.rejects(replayInspected(reply, { ...artifact, command: { ...artifact.command, message: `${message}changed` } }, beforeTree, webcrypto)); checks++;
      await assert.rejects(replayInspected({ ...reply, parents: [] }, artifact, beforeTree, webcrypto)); checks++;
      command(['fsck', '--strict'], dir); checks++;
      cells.push({ algorithm, operation: label, parent: before, candidate, tree, paths: entries.length });
      return candidate;
    }
    command(['cherry-pick', source], dir); const picked = await inspect('cherry-pick', target);
    command(['revert', '--no-edit', picked], dir); await inspect('revert', picked);
    assert.equal(readFileSync(join(dir, 'file'), 'utf8'), 'base\r\n'); checks++;
    // Root replay into an independent history creates no synthetic source parent.
    command(['checkout', '-q', '--orphan', 'other'], dir); command(['rm', '-q', '-rf', '.'], dir);
    writeFileSync(join(dir, 'root-only'), 'root contents'); const rootCommit = commit('independent root');
    command(['checkout', '-q', 'main'], dir); const beforeRoot = text(['rev-parse', 'HEAD'], dir);
    command(['cherry-pick', rootCommit], dir); await inspect('root-cherry-pick', beforeRoot);
    // Merge-parent selection is deliberate: apply the merge delta relative to
    // parent 1. The Rust algorithm is not run or claimed by this Git lane.
    command(['checkout', '-q', '-b', 'left', base], dir); writeFileSync(join(dir, 'left'), 'left'); const left = commit('left');
    command(['checkout', '-q', '-b', 'right', base], dir); writeFileSync(join(dir, 'right'), 'right'); commit('right');
    command(['checkout', '-q', 'left'], dir); command(['merge', '--no-ff', '-m', 'two-parent merge', 'right'], dir);
    const merged = text(['rev-parse', 'HEAD'], dir); command(['checkout', '-q', 'main'], dir);
    command(['reset', '--hard', left], dir); command(['cherry-pick', '-m', '1', merged], dir); const mergePick = await inspect('mainline-cherry-pick', left);
    command(['revert', '--no-edit', mergePick], dir); await inspect('revert-mainline-result', mergePick);
    assert.equal(text(['rev-parse', 'HEAD^{tree}'], dir), text(['rev-parse', `${left}^{tree}`], dir)); checks++;
  }
  console.log(JSON.stringify({ profile: 'replay-browser-git-object-interoperability-v1', git_version: expectedVersion, git_sha256: expectedHash,
    checks, passed: checks, scenarios: cells, native_replay_executed: false, synthetic_authority_envelopes: true, production_git_invocation: false }, null, 2));
} finally { rmSync(root, { recursive: true, force: true }); }
