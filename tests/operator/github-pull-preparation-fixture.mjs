import { mkdtemp, chmod, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { captureGithubPulls } from '../../scripts/lib/github-pull-source.mjs';
import { beginGithubPullPreparation } from '../../scripts/lib/github-pull-preparation.mjs';
import { githubPeer } from './github-pull-fixture.mjs';
export const TOKEN = 'aa'.repeat(32);
export const selection = () => ({ endpoint: 'http://127.0.0.1:1/repo',
  scope: { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16),
    repository_incarnation: '33'.repeat(16), principal_id: '44'.repeat(16), object_format: 'sha1' },
  number_start: '100', namespace: 'refs/heads/import/github/' });
export async function preparationFixture(t, { source = {}, select = {}, begin = true } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-pull-preparation-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const peer = await githubPeer(t, source), capture = await captureGithubPulls(peer.options); await peer.close();
  const captureFile = join(root, 'capture.json'), tokenFile = join(root, 'token'), workdir = join(root, 'draft');
  await writeFile(captureFile, capture.bytes, { mode: 0o600 }); await writeFile(tokenFile, TOKEN, { mode: 0o600 });
  const input = { workdir, captureFile, captureConfirm: capture.sha256, tokenFile, selection: { ...selection(), ...select } };
  const prepared = begin ? await beginGithubPullPreparation(input) : null;
  return { root, workdir, captureFile, tokenFile, capture, input, prepared,
    options: { workdir, confirm: prepared?.preparation_sha256 } };
}
