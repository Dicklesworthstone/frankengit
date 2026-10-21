// Test-only native-schema executable peer. It is NOT fg, an archive parser,
// repository authority, or evidence of native Git/forge restoration.
import { writeFile, readFile, appendFile, mkdir, lstat, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { tlsFixture, DATA, ID, digest } from './backup-download-fixture.mjs';
import { initializeRepositoryBackupWitness } from '../lib/repository-backup-witness.mjs';
import { verifyRepositoryBackupApproval } from '../lib/repository-backup-approval.mjs';
import { nativeBackupApprovalBinding } from '../lib/repository-backup-native-approval.mjs';

export { DATA, ID, digest };
const stringify = value => JSON.stringify(value, (_, x) => typeof x === 'bigint' ? `~u64:${x}` : x).replace(/"~u64:([0-9]+)"/g, '$1');
const time = value => new Date(Math.floor(value / 1000) * 1000).toISOString().replace('.000Z', 'Z');
export async function recoveryFixture(t, format = 'sha256') {
  const f = await tlsFixture(t);
  const sign = (data = DATA, meta = {}) => f.sign(data, { object_format: format,
    issued_at: time(Date.now() - 60000), expires_at: time(Date.now() + 3600000), ...meta },
    // Produce formerly valid signatures at their signing time, not by weakening verification.
    meta.expires_at && Date.parse(meta.expires_at) < Date.now() ? Date.parse(meta.issued_at) + 1000 : Date.now());
  await sign();
  const witness = join(f.root, 'witness'), sourceFile = join(f.root, 'sources.json'), config = join(f.root, 'peer-config.json');
  const log = join(f.root, 'peer-events.jsonl'), fg = join(f.root, 'fg-schema-peer');
  const policy = { ...ID, object_format: format, minimum_head_generation: '1' };
  await initializeRepositoryBackupWitness(witness, f.trustKey, policy);
  await writeFile(sourceFile, JSON.stringify([f.url]), { mode: 0o600 });
  const configure = extra => writeFile(config, JSON.stringify({ log, witness, mode: 'normal', ...extra }));
  await configure({});
  await writeFile(fg, `#!${process.execPath}\nimport { runNativeRecoveryPeer } from ${JSON.stringify(import.meta.url)};\nawait runNativeRecoveryPeer(${JSON.stringify(config)}, process.argv.slice(2));\n`, { mode: 0o700 });
  const options = { operation: 'restore', cacheDirectory: f.destination, sourceFile, caFile: f.caFile,
    approval: f.approval, trustKey: f.trustKey, policy, witness, fg, verificationInstance: '11',
    destination: join(f.root, 'restored'), destinationInstance: '12', approvalRecord: join(f.root, 'restore-approval.json'),
    trustedLocal: true, maximumBytes: DATA.length, maximumAcquisitionBytes: DATA.length * 4, timeoutMs: 10000 };
  const events = async () => { try { return (await readFile(log, 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); }
    catch (e) { if (e.code === 'ENOENT') return []; throw e; } };
  return { ...f, sign, witness, sourceFile, config, fg, log, configure, events, options,
    verifyOptions: () => { const { destination, destinationInstance, approvalRecord, ...rest } = options; return { ...rest, operation: 'verify' }; } };
}

export async function runNativeRecoveryPeer(configPath, args) {
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  if (args[0] !== 'backup' || !['verify', 'restore'].includes(args[1])) process.exit(90);
  const operation = args[1], input = args[2], output = args[3], flags = {};
  for (let at = 4; at < args.length; at++) {
    const name = args[at]; flags[name] = ['--resume', '--trusted-local'].includes(name) ? true : args[++at];
  }
  const policy = Object.fromEntries(['tenant_id', 'repository_id', 'incarnation_id', 'object_format', 'minimum_head_generation']
    .map(k => [k, flags['--' + k.replaceAll('_', '-')]]));
  const envelope = await readFile(flags['--approval']), key = await readFile(flags['--trust-key']);
  const authentication = (await verifyRepositoryBackupApproval(envelope, key, policy)).authentication;
  const statement = authentication.statement, bytes = await readFile(input);
  if (digest(bytes) !== statement.artifact.sha256 || String(bytes.length) !== statement.artifact.bytes) process.exit(91);
  await lstat(join(config.witness, '.witness-lock')); // must be held through BOTH native commands
  const record = { operation, input, output, pid: process.pid, resume: Boolean(flags['--resume']),
    approval: flags['--approval'], trustKey: flags['--trust-key'], envelope_sha256: digest(envelope) };
  // Publishing the entered-operation record lets the parent send SIGTERM.
  // Own that signal before exposing readiness, including while append drains.
  const stopped = config.mode === `hold_${operation}` ? new Promise(resolve => {
    const timer = setInterval(() => {}, 1000);
    process.once('SIGTERM', () => { clearInterval(timer);resolve(); });
  }) : null;
  await appendFile(config.log, JSON.stringify(record) + '\n');
  if (stopped) {
    await stopped;
    await appendFile(config.log, JSON.stringify({ stopped: operation, pid: process.pid }) + '\n');
    process.exit(92);
  }
  if (config.mode === `refuse_${operation}`) process.exit(93);
  let already = false;
  if (operation === 'restore') {
    try { await mkdir(output, { mode: 0o700 }); await writeFile(join(output, 'TEST_ONLY_NOT_A_NATIVE_REPOSITORY'), envelope); }
    catch (e) {
      if (e.code !== 'EEXIST' || !flags['--resume'] || !(await readFile(join(output, 'TEST_ONLY_NOT_A_NATIVE_REPOSITORY'))).equals(envelope)) process.exit(94);
      already = true;
    }
    if (config.mode === 'lose_restore_response' && !already) process.exit(95);
  }
  if (operation === 'restore' && config.mode === 'move_witness_lock') await rename(join(config.witness, '.witness-lock'), join(config.witness, '.moved-test-lock'));
  if (operation === 'restore' && config.mode === 'fail_approval_cleanup') await writeFile(join(flags['--approval'], '..', 'TEST_ONLY_EXTRA_CHILD'), 'diagnostic');
  if (config.mode === 'delay_verify' && operation === 'verify') await delay(config.delay ?? 100);
  const pins = nativeBackupApprovalBinding(envelope, key, policy);
  const v = { type: `repository_source_backup_${operation}`, schema_version: 1, sha256: statement.artifact.sha256,
    ...Object.fromEntries(['tenant_id', 'repository_id', 'incarnation_id', 'object_format'].map(k => [k, statement[k]])),
    head_generation: BigInt(statement.head_generation), objects: 2, references: 1, payload_bytes: bytes.length - 9,
    complete: true, scope: 'authority_and_selected_git_objects', object_graph_verified: true,
    original_payload_commitments_verified: true, node_closed: true, signature_verified: true, routing_published: false,
    archive_bytes: bytes.length,
    ...(operation === 'verify' ? { local_edges: 1, external_gitlinks: 0, verification_instance: BigInt(flags['--verification-instance']),
      authority_import_verified: true, git_payloads_written: false, destination_authority_published: false,
      scratch_removed: true, destination_readback_verified: false, newest_checkpoint_verified: false, external_artifacts_verified: false }
      : { destination_instance: BigInt(flags['--destination-instance']), source_tokens_preserved: false,
        reopened_and_verified: true, external_artifacts_restored: false, streaming: true,
        resume_requested: Boolean(flags['--resume']), already_published: already }),
    approval: { type: 'repository_backup_approval_authentication', signature_verified: true, ...pins,
      minimum_head_generation: policy.minimum_head_generation, statement, newest_checkpoint_verified: false, complete_capsule_verified: false } };
  if (config.mode === `wrong_digest_${operation}`) v.sha256 = '0'.repeat(64);
  if (config.mode === 'wrong_restore_counts' && operation === 'restore') v.objects++;
  process.stdout.write(stringify(v) + '\n');
}
