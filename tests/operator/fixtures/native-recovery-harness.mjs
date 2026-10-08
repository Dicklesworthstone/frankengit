import { mkdtemp, readFile, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { inflateSync } from 'node:zlib';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
export const fixtures = fileURLToPath(new URL('../../fixtures/native_bundle_recovery/', import.meta.url));
export const head = Buffer.from('refs/heads/main').toString('hex');
export async function readFixture(format, extension = 'bundle') {
  const compressed = format === 'sha256' && extension === 'idx';
  const bytes = Buffer.from((await readFile(join(fixtures, `${format}.${extension}${compressed ? '.zlib' : ''}.hex`), 'utf8')).trim(), 'hex');
  return compressed ? inflateSync(bytes) : bytes;
}
export async function harness(t, format = 'sha1', extra = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-native-recovery-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const fg = join(root, 'fg');
  const source = await readFile(new URL('native-recovery-fake.mjs', import.meta.url), 'utf8');
  await writeFile(fg, `#!${process.execPath}\n${source}`, { mode: 0o700 });
  const settings = { fixtures, format, ...extra };
  const configure = async update => { Object.assign(settings, update); await writeFile(join(root, 'settings.json'), JSON.stringify(settings)); };
  await configure({});
  return { root, fg, configure, bytes: await readFixture(format), destination: join(root, 'restored.git'),
    options: { nativeFg: fg }, request: { head_ref_hex: head },
    calls: async () => { try { return (await readFile(join(root, 'calls.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse); }
      catch (error) { if (error.code === 'ENOENT') return []; throw error; } } };
}
