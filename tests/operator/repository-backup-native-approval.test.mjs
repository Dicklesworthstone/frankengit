// Opt-in native process evidence. The existing JS issuer only creates detached
// signatures; every fg invocation runs with an empty executable search path.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readFile, writeFile, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { signRepositoryBackupFile } from '../../scripts/lib/repository-backup-approval.mjs';

const enabled = process.env.FG_NATIVE_BIN;
const tenant = '11'.repeat(16), repository = '22'.repeat(16), principal = '33'.repeat(16);
const hex = bytes => createHash('sha256').update(bytes).digest('hex');
async function exists(path) {
  try { await access(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}

for (const format of ['sha1', 'sha256']) {
  test(`real fg natively authenticates, verifies and restores signed ${format} source after source loss`,
    { skip: !enabled && 'FG_NATIVE_BIN required; no substituted native process' }, async t => {
      const root = await mkdtemp(join(tmpdir(), 'fg-native-signed-backup-'));
      t.after(() => rm(root, { recursive: true, force: true }));
      const fg = resolve(enabled), source = join(root, 'source'), archive = join(root, 'archive.fgit');
      const invoke = args => spawnSync(fg, args, {
        cwd: root, encoding: 'utf8', timeout: 300000, maxBuffer: 65536,
        env: { ...process.env, PATH: '' },
      });
      const run = args => {
        const result = invoke(args);
        assert.equal(result.status, 0, result.stderr || String(result.error));
        return result.stdout;
      };
      const refused = args => {
        const result = invoke(args);
        assert.equal(result.status, 2, result.stdout || result.stderr || String(result.error));
        assert.equal(result.stdout, '');
        return result.stderr;
      };
      const input = join(root, 'seed.bundle');
      const encoded = await readFile(resolve(`tests/fixtures/native_bundle_recovery/${format}.bundle.hex`), 'utf8');
      await writeFile(input, Buffer.from(encoded.trim(), 'hex'));
      run(['init', source, tenant, repository, format]);
      run(['bundle', 'import', source, tenant, repository, input, '--trusted-local',
        '--object-format', format, '--principal', principal, '--idempotency-key', 'signed-backup-fixture']);
      const exported = JSON.parse(run(['backup', 'export', source, archive, tenant, repository,
        '--trusted-local', '--object-format', format]));
      const pin = hex(await readFile(archive));
      assert.equal(exported.sha256, pin);
      assert.ok(exported.objects >= 5);
      const data = Object.fromEntries(['tenant_id', 'repository_id', 'incarnation_id', 'object_format']
        .map(key => [key, exported[key]]));
      data.head_generation = String(exported.head_generation);
      const pair = generateKeyPairSync('ed25519');
      const secret = Buffer.from(pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
      const approval = join(root, 'approval.dsse.json'), trust = join(root, 'trusted.pem');
      const signed = await signRepositoryBackupFile(archive, secret, data);
      await writeFile(approval, signed.envelope, { mode: 0o600 });
      await writeFile(trust, pair.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
      const policy = ['--approval', approval, '--trust-key', trust, '--tenant-id', data.tenant_id,
        '--repository-id', data.repository_id, '--incarnation-id', data.incarnation_id,
        '--object-format', format, '--minimum-head-generation', data.head_generation];
      const command = (operation, destination, flags = policy) => [
        'backup', operation, archive, destination, '--trusted-local', '--expected-sha256', pin,
        operation === 'verify' ? '--verification-instance' : '--destination-instance',
        operation === 'verify' ? '900000001' : '900000002', ...flags,
      ];
      await rm(source, { recursive: true });
      await rm(input);
      const scratch = join(root, 'verification');
      const verified = JSON.parse(run(command('verify', scratch)));
      assert.equal(verified.signature_verified, true);
      assert.equal(verified.object_graph_verified, true);
      assert.equal(verified.scratch_removed, true);
      assert.equal(verified.approval.statement.artifact.sha256, pin);
      assert.equal(await exists(scratch), false);
      for (const operation of ['verify', 'restore']) {
        const timed = join(root, `global-timeout-${operation}`);
        const error = refused(['--timeout-secs', '0.000000001',
          ...command(operation, timed), '--timeout-secs', '600']);
        assert.match(error, /deadline exceeded/);
        assert.equal(await exists(timed), false);
      }
      const restored = join(root, 'restored');
      const receipt = JSON.parse(run(command('restore', restored)));
      assert.equal(receipt.signature_verified, true);
      assert.equal(receipt.reopened_and_verified, true);
      assert.equal(receipt.node_closed, true);
      const intent = await readFile(join(restored, '.restore-intent'));
      assert.equal(intent.subarray(0, 8).toString(), 'FGRES002');
      assert.equal(intent.length, 80);
      run(['doctor', restored, tenant, repository]);
      assert.equal(JSON.parse(run([...command('restore', restored), '--resume'])).already_published, true);
      const omitted = refused([...command('restore', restored, []), '--resume']);
      assert.match(omitted, /prior attempt may already have published/);

      await writeFile(approval, Buffer.concat([signed.envelope, Buffer.from('\n')]));
      assert.match(refused([...command('restore', restored), '--resume']), /intent does not match/);
      assert.deepEqual(await readFile(join(restored, '.restore-intent')), intent);
      await writeFile(approval, signed.envelope);
      const wrongTrust = join(root, 'other-trusted.pem');
      await writeFile(wrongTrust, generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }));
      for (const [label, index, value] of [
        ['wrong-key', 3, wrongTrust], ['wrong-tenant', 5, 'ff'.repeat(16)],
        ['wrong-floor', 13, '18446744073709551615'],
      ]) {
        const changed = [...policy]; changed[index] = value;
        const output = join(root, label);
        refused(command('verify', output, changed));
        assert.equal(await exists(output), false);
      }
      const altered = JSON.parse(signed.envelope), payload = Buffer.from(altered.payload, 'base64');
      payload[0] ^= 1; altered.payload = payload.toString('base64');
      await writeFile(approval, JSON.stringify(altered));
      const bad = join(root, 'altered-payload');
      refused(command('restore', bad));
      assert.equal(await exists(bad), false);
      const expired = await signRepositoryBackupFile(archive, Buffer.from(secret), {
        ...data, issued_at: '2020-01-01T00:00:00Z', expires_at: '2020-01-01T00:01:00Z',
      }, { now: Date.parse('2020-01-01T00:00:00Z') });
      await writeFile(approval, expired.envelope);
      const expiredRoot = join(root, 'expired');
      assert.match(refused(command('restore', expiredRoot)), /expired/);
      assert.equal(await exists(expiredRoot), false);
      assert.match(refused([...command('restore', restored), '--resume']), /prior attempt may already have published/);
      assert.equal(await exists(join(restored, 'authority.fsqlite')), true);
      assert.deepEqual(await readFile(join(restored, '.restore-intent')), intent);
      const timedExport = join(root, 'global-timeout-export.fgit');
      assert.match(refused(['--timeout-secs', '0.000000001', 'backup', 'export', restored,
        timedExport, tenant, repository, '--trusted-local', '--object-format', format,
        '--timeout-secs', '600']), /deadline exceeded/);
      assert.equal(await exists(timedExport), false);
    });
}
