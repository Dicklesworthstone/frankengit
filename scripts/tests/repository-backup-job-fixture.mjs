import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, rm, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { sealRepositoryBackupJob, runRepositoryBackupJob } from '../lib/repository-backup-job.mjs';

export const DATA = Buffer.alloc(65553, 0x53);
export const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export const instant = ms => new Date(ms).toISOString().replace('.000Z', 'Z');
export async function jobFixture(t, format = 'sha256', count = 2) {
  const root = await mkdtemp(join(tmpdir(), 'fg-backup-job-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const pair = generateKeyPairSync('ed25519'), trustKey = join(root, 'trust.pem');
  const privatePem = Buffer.from(pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  await writeFile(trustKey, pair.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
  const now = Math.floor(Date.now() / 1000) * 1000;
  const identity = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), incarnation_id: '3'.repeat(32), object_format: format };
  const policy = { ...identity, minimum_head_generation: '2' };
  async function sign(name, data = DATA, generation = '9007199254740993', times = {}) {
    const input = join(root, name), approval = `${input}.approval`;
    await writeFile(input, data, { mode: 0o600 });
    const result = await signRepositoryBackupFile(input, privatePem, {
      ...identity, head_generation: generation, issued_at: instant(now - 60000), expires_at: instant(now + 86400000), ...times,
    }, { now });
    await writeFile(approval, result.envelope, { mode: 0o600 }); return { input, approval };
  }
  const source = await sign('z-original');
  const destinations = Array.from({ length: count }, (_, i) => join(root, `replica-${String(i).padStart(2, '0')}`));
  const jobDirectory = join(root, 'jobs');
  for (const dir of [jobDirectory, ...destinations]) await mkdir(dir, { mode: 0o700 });
  const options = { candidates: [source], destinations, jobDirectory, trustKey, policy, maximumBytes: DATA.length, now };
  return { root, now, source, destinations, jobDirectory, trustKey, policy, identity, options, sign,
    seal: (extra = {}, witness = null) => sealRepositoryBackupJob({ ...options, ...extra }, witness),
    run: (intent, extra = {}, witness = null) => runRepositoryBackupJob({ intent, trustKey, policy,
      maximumBytes: DATA.length, now, ...extra }, witness) };
}
export async function rewriteIntent(intent, transform) {
  const record = JSON.parse(await readFile(intent, 'utf8')); transform(record);
  const bytes = Buffer.from(JSON.stringify(record) + '\n');
  const updated = join(dirname(intent), `job-sha256-${digest(bytes)}.json`);
  await writeFile(updated, bytes, { mode: 0o600 }); return updated;
}
export async function replaceDirectory(path) {
  await rename(path, `${path}-old`); await mkdir(path, { mode: 0o700 });
}
