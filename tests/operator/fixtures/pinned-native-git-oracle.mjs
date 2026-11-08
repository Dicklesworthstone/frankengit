// Test-only upstream oracle. Production recovery never invokes Git.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../../../scripts/e2e/oracle/oracle.sh', import.meta.url));
const pin = 'git-2.47.3';
export function pinnedNativeGitOracle(t, label) {
  const invoke = args => spawnSync('bash', [script, ...args], {
    encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024,
    // Tests use the checked-in manifest, never a caller-supplied replacement.
    env: { ...process.env, FGIT_ORACLE_PIN_MANIFEST: undefined },
  });
  const verified = invoke(['verify', pin]);
  if (verified.status === 69 && verified.stderr.trim() ===
      `FGIT_ORACLE_UNAVAILABLE: oracle ${pin} has no local binary receipt`) {
    t.skip('exact pinned Git 2.47.3 sandbox oracle unavailable'); return null;
  }
  assert.equal(verified.status, 0, verified.error?.message ?? verified.stderr);
  const created = invoke(['create-run', pin, label]);
  assert.equal(created.status, 0, created.error?.message ?? created.stderr);
  const root = created.stdout.trim(); let sequence = 0;
  t.diagnostic(`exact pinned Git 2.47.3 oracle transcripts: ${root}`);
  const capture = (args, workdir = '.') => {
    const name = `check-${++sequence}`, transcript = join(root, 'transcripts', name);
    const result = invoke(['capture', pin, root, workdir, name, '--', ...args]);
    assert.ifError(result.error);
    assert.equal(result.signal, null, result.stderr);
    const receipt = new Map(readFileSync(join(transcript, 'receipt.tsv'), 'utf8').trim().split('\n')
      .map(line => { const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)]; }));
    const stdout = readFileSync(join(transcript, 'stdout.bin'));
    const stderr = readFileSync(join(transcript, 'stderr.bin'));
    assert.equal(receipt.get('schema_version'), '1');
    assert.equal(receipt.get('oracle_id'), pin);
    assert.equal(receipt.get('exit_code'), String(result.status));
    for (const [name, bytes] of [['stdout', stdout], ['stderr', stderr]]) {
      assert.equal(receipt.get(`${name}_sha256`), createHash('sha256').update(bytes).digest('hex'));
    }
    return { status: result.status, stdout, stderr };
  };
  return { work: join(root, 'work'), capture, run(args, workdir = '.') {
    const result = capture(args, workdir);
    assert.equal(result.status, 0, result.stderr.toString());
    return result.stdout.toString('utf8');
  } };
}
