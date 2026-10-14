// Real files, Ed25519 and TLS; recoveryFixture's executable is NOT Rust fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, unlink, symlink, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { recoverRepositoryBackup } from '../lib/repository-backup-recovery.mjs';
import { withRepositoryBackupWitness } from '../lib/repository-backup-witness.mjs';
import { recoveryFixture, DATA } from './backup-recovery-fixture.mjs';

async function setup(t, format, viaParent = false) {
  const f = await recoveryFixture(t, format);
  const origin = join(f.root, 'independent'), alias = join(f.root, 'approval-parent');
  await mkdir(origin, { mode: 0o700 });
  if (viaParent) await symlink(origin, alias);
  const low = join(viaParent ? alias : origin, 'old.approval');
  const lowBytes = (await f.sign(DATA, { head_generation: '1' })).envelope;
  await writeFile(low, lowBytes);
  const high = join(f.root, 'high.approval');
  await writeFile(high, (await f.sign(DATA, { head_generation: '2' })).envelope);
  const { approval, sourceFile, caFile, ...common } = f.options;
  const options = { ...common, candidates: [
    // Losing payload paths are deliberately unreachable; they are not intake.
    { approval: low, sourceFile: join(f.root, 'missing-parent', 'sources.json') },
    { approval: high, sourceFile, caFile },
  ] };
  return { f, low, lowBytes, high, alias, options };
}

for (const format of ['sha1', 'sha256']) {
  for (const phase of ['checkpoint_pinned', 'acquisition_complete', 'preflight_verified', 'restore_starting']) {
    for (const viaParent of [false, true]) {
      test(`${format}: protect losing approval at ${phase}, parent alias=${viaParent}`, async t => {
        const { f, low, lowBytes, alias, options } = await setup(t, format, viaParent);
        let redirected = false;
        await assert.rejects(recoverRepositoryBackup({ ...options, async onProgress(event) {
          if (event.phase !== phase || redirected) return;
          redirected = true;
          const inside = join(f.destination, 'old.approval');
          await writeFile(inside, lowBytes);
          await unlink(viaParent ? alias : low);
          await symlink(viaParent ? f.destination : inside, viaParent ? alias : low);
        } }), { code: 'backup_recovery_separate_paths_required' });
        assert.equal(redirected, true);
        assert.deepEqual((await f.events()).map(e => e.operation),
          ['preflight_verified', 'restore_starting'].includes(phase) ? ['verify'] : []);
        assert.equal(f.requests.length, phase === 'checkpoint_pinned' ? 0 : 1);
        await assert.rejects(lstat(f.options.destination), { code: 'ENOENT' });
        const witness = await withRepositoryBackupWitness(f.witness, f.trustKey, f.options.policy, {}, w => w.snapshot());
        assert.equal(witness.highest_observed_generation, '2');
      });
    }
  }

  test(`${format}: independent losing approvals and absent losing payload parents stay permitted`, async t => {
    const { f, options } = await setup(t, format, true);
    const result = await recoverRepositoryBackup(options);
    assert.equal(result.state, 'complete');
    assert.equal(result.checkpoint_selection.selected_index, 1);
    assert.equal(String(result.native.native.head_generation), '2');
    assert.equal(f.requests.length, 1);
    assert.deepEqual((await f.events()).map(e => e.operation), ['verify', 'restore']);
  });

  test(`${format}: replacing a losing alias with another separate identical control is permitted`, async t => {
    const { f, low, lowBytes, options } = await setup(t, format);
    const separate = join(f.root, 'other.approval'); await writeFile(separate, lowBytes);
    const result = await recoverRepositoryBackup({ ...options, async onProgress(event) {
      if (event.phase === 'acquisition_complete') { await unlink(low); await symlink(separate, low); }
    } });
    assert.equal(result.state, 'complete');
    assert.equal(f.requests.length, 1);
    assert.deepEqual((await f.events()).map(e => e.operation), ['verify', 'restore']);
    assert.deepEqual(await readFile(separate), lowBytes);
  });
}
