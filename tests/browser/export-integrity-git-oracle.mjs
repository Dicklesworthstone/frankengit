// Explicit NON-PRODUCTION interoperability lane. Git is a pinned independent
// oracle only. It never implements a browser request or native node operation.
// Usage: node export-integrity-git-oracle.mjs /absolute/git "git version X" binary-sha256
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, webcrypto } from 'node:crypto';
import { TransferClient } from '../../crates/fgit-node/src/smart_http/server/browser/transfers.mjs';
import { verifyExportManifest } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';

const [git, expectedVersion, expectedHash] = process.argv.slice(2);
assert(git?.startsWith('/') && expectedVersion && /^[0-9a-f]{64}$/.test(expectedHash ?? ''), 'Supply an absolute Git binary, exact version, and binary SHA-256.');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha256(readFileSync(git)), expectedHash, 'Pinned Git binary changed');
const root = mkdtempSync(join(tmpdir(), 'fg-export-integrity-oracle-'));
const env = { PATH: process.env.PATH, HOME: root, XDG_CONFIG_HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C', GIT_AUTHOR_NAME: 'Export Oracle', GIT_AUTHOR_EMAIL: 'oracle@example.invalid',
  GIT_COMMITTER_NAME: 'Export Oracle', GIT_COMMITTER_EMAIL: 'oracle@example.invalid',
  GIT_AUTHOR_DATE: '2001-01-01T00:00:00+00:00', GIT_COMMITTER_DATE: '2001-01-01T00:00:00+00:00' };
const run = (args, cwd, input) => execFileSync(git, args, { cwd, env, input, stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000, maxBuffer: 8 * 1024 * 1024 });
const text = (args, cwd) => run(args, cwd).toString('utf8').trim();
const checks = [];
function check(name, action) { action(); checks.push(name); }
async function checkAsync(name, action) { await action(); checks.push(name); }
function inventory(dir) {
  // Parse Git's own raw output, independently of the browser bundle parser.
  const raw = run(['for-each-ref', '--sort=refname', '--format=%(objectname) %(refname)'], dir);
  return raw.subarray(0, -1).toString('latin1').split('\n').map(line => {
    const at = line.indexOf(' '), bytes = Buffer.from(line.slice(at + 1), 'latin1'); let name = null;
    try { name = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch {}
    return { ref: name, ref_hex: bytes.toString('hex'), object_id: line.slice(0, at) };
  });
}
try {
  assert.equal(text(['--version'], root), expectedVersion);
  for (const algorithm of ['sha1', 'sha256']) {
    const dir = join(root, algorithm); mkdirSync(dir);
    run(['init', '-q', '--initial-branch=main', `--object-format=${algorithm}`], dir);
    run(['config', 'core.autocrlf', 'false'], dir);
    const content = Buffer.from([0, 255, 13, 10, 3, 128]);
    writeFileSync(join(dir, 'binary.dat'), content); writeFileSync(join(dir, 'README'), 'exact\r\nno final newline');
    writeFileSync(Buffer.concat([Buffer.from(dir + '/raw-'), Buffer.from([255])]), 'byte path\n');
    run(['add', '--all'], dir); run(['commit', '-q', '-m', 'first'], dir);
    run(['tag', '-a', 'v1', '-m', 'Annotated object, not the peeled commit'], dir);
    run(['branch', 'topic'], dir);
    // A second page exercises the real complete-snapshot read, not a one-row twin.
    for (let i = 0; i < 101; i++) run(['update-ref', `refs/tags/export-${String(i).padStart(3, '0')}`, 'HEAD'], dir);
    const path = join(dir, 'export.bundle'); run(['bundle', 'create', path, '--all'], dir);
    const input = new Uint8Array(readFileSync(path)), rows = inventory(dir), calls = [], head = `alg:1:${'1'.repeat(64)}`;
    const common = { schema_version: 1, tenant_id: 'oracle-tenant', repository_id: 'oracle-repo', repository_incarnation: 'oracle-incarnation', object_format: algorithm };
    let replacement = null;
    const client = new TransferClient({ href: 'https://oracle.invalid/repo.git/ui/transfers/', cryptoImpl: webcrypto,
      fetchImpl: async (url, init) => {
        const endpoint = new URL(url).pathname.split('/api/v1/')[1], fields = new URLSearchParams(init.body); calls.push({ endpoint, url: String(url), init, fields });
        if (endpoint === 'source/refs') {
          const after = fields.get('after'), limit = Number(fields.get('limit'));
          const selected = rows.filter(r => after === null || r.ref_hex > Buffer.from(after).toString('hex'));
          const refs = selected.slice(0, limit), next_after = selected.length > limit ? refs.at(-1).ref : null;
          return new Response(JSON.stringify({ ...common, type: 'source_refs', namespace: 'all', after, limit, next_after,
            source_head: 'oracle-head', snapshot_token: head, read_only: true, transaction_created: false,
            published: false, direct_refs_only: true, refs }), { headers: { 'Content-Type': 'application/json' } });
        }
        assert.equal(endpoint, 'source/bundle/export', 'No writes in audit workflow');
        const bytes = replacement ?? input;
        return new Response(bytes, { headers: { 'Content-Type': 'application/x-git-bundle', 'Content-Length': String(bytes.length),
          'X-Fgit-Bundle-Profile': 'full-v1', 'X-Fgit-Object-Format': algorithm, 'X-Fgit-Tenant': common.tenant_id,
          'X-Fgit-Repository': common.repository_id, 'X-Fgit-Repository-Incarnation': common.repository_incarnation,
          'X-Fgit-Source-Head': 'oracle-head', 'X-Fgit-Snapshot': head, 'X-Fgit-Artifact-Sha256': sha256(bytes), 'X-Fgit-Read-Only': 'true' } });
      }
    });
    await client.connect('ab'.repeat(32)); await client.select(algorithm); await client.exportBundle({ verifyInventory: true });
    check(`${algorithm}: all real Git refs match pinned inventory`, () => assert.deepEqual(client.exported.refs, rows.map(({ ref_hex, object_id }) => ({ ref_hex, object_id }))));
    check(`${algorithm}: multiple inventory pages stay pinned`, () => {
      assert(calls.filter(c => c.endpoint === 'source/refs' && c.fields.get('limit') === '100').length > 1);
      for (const call of calls.slice(1)) assert.equal(call.fields.get('expected_head'), head);
    });
    check(`${algorithm}: downloaded bytes are exactly Git's bundle`, () => assert.deepEqual(client.exportBytes(), input));
    const manifest = client.exportManifest();
    await checkAsync(`${algorithm}: offline manifest verifies real pack`, async () => {
      const result = await verifyExportManifest(input, manifest, webcrypto);
      assert.equal(result.objects_verified, false); assert.equal(result.live_snapshot_rechecked, false);
    });
    const saved = join(root, `${algorithm}.bundle`); writeFileSync(saved, client.exportBytes());
    const mirror = join(root, `${algorithm}-mirror.git`); run(['clone', '--quiet', '--mirror', saved, mirror], root);
    check(`${algorithm}: downloaded bundle clones and passes strict fsck`, () => run(['fsck', '--strict', '--no-reflogs'], mirror));
    check(`${algorithm}: clone preserves all exact reference targets`, () => assert.deepEqual(inventory(mirror), rows));
    check(`${algorithm}: binary contents remain exact`, () => assert.deepEqual(run(['show', 'refs/heads/main:binary.dat'], mirror), content));
    check(`${algorithm}: annotated tag remains a tag object`, () => assert.equal(text(['cat-file', '-t', 'refs/tags/v1'], mirror), 'tag'));
    check(`${algorithm}: non-UTF-8 tree paths survive`, () => assert(run(['ls-tree', '-rz', 'refs/heads/main'], mirror).includes(Buffer.from([114, 97, 119, 45, 255]))));
    check(`${algorithm}: token never enters manifest or request URL`, () => { assert(!manifest.includes('ab'.repeat(32))); assert(calls.every(c => !c.url.includes('ab'.repeat(32)))); });
    const corrupted = input.slice(); corrupted[corrupted.length - 1] ^= 1;
    await checkAsync(`${algorithm}: offline pack corruption refuses`, () => assert.rejects(verifyExportManifest(corrupted, manifest, webcrypto)));
    // Delete one advertised tag; leave a still-valid native pack/trailer and
    // recompute the transport SHA-256. Inventory matching must catch omission.
    const newline = Buffer.from(input).indexOf(Buffer.from('\n\n')), header = Buffer.from(input).subarray(0, newline + 2).toString('latin1');
    const omitted = header.split('\n').filter(line => !line.endsWith(' refs/tags/v1')).join('\n');
    replacement = new Uint8Array(Buffer.concat([Buffer.from(omitted, 'latin1'), Buffer.from(input).subarray(newline + 2)]));
    await checkAsync(`${algorithm}: checksum-valid omitted ref refuses before save`, () => assert.rejects(client.exportBundle({ verifyInventory: true })));
    check(`${algorithm}: failed replacement cannot leave an old artifact`, () => { assert.equal(client.exported, null); assert.throws(() => client.exportBytes()); });
    check(`${algorithm}: reads create no idempotency key or command upload`, () => assert(calls.every(c => c.init.method === 'POST' && c.init.headers['Idempotency-Key'] === undefined)));
  }
  console.log(JSON.stringify({ profile: 'full-export-manifest-git-oracle-v1', git_version: expectedVersion, git_sha256: expectedHash,
    object_formats: ['sha1', 'sha256'], passed: checks.length, checks, production_git_invocation: false,
    native_rust_interoperability: false, transport: 'HTTP test double over real Git-generated artifacts' }, null, 2));
} finally { rmSync(root, { recursive: true, force: true }); }
