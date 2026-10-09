// DELIBERATELY FAKE fg backup contract process. Opaque JSON archive fixtures,
// not the native FGSRC001 decoder, authority backend, graph or durable restore.
import { readFile, writeFile, appendFile, mkdir, rm, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
const json = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? String(v) : v)
  .replace(/"(head_generation|verification_instance|destination_instance)":"([0-9]+)"/g, '"$1":$2');
export async function fakeRepositoryBackup(configPath) {
  const config = JSON.parse(await readFile(configPath)), args = process.argv.slice(2);
  await appendFile(config.log, JSON.stringify({ args, pid: process.pid }) + '\n');
  try {
    if (args[0] !== 'backup' || !['verify', 'restore'].includes(args[1])) throw Error('wrong command');
    const operation = args[1], input = args[2], output = args[3], flags = new Map();
    for (let at = 4; at < args.length; at++) {
      const flag = args[at]; if (flags.has(flag)) throw Error('duplicate');
      if (['--trusted-local', '--resume'].includes(flag)) flags.set(flag, true);
      else flags.set(flag, args[++at]);
    }
    const allowed = ['--trusted-local', '--resume', '--expected-sha256', '--max-archive-bytes', '--timeout-secs',
      operation === 'verify' ? '--verification-instance' : '--destination-instance'];
    if (!flags.get('--trusted-local') || [...flags.keys()].some(k => !allowed.includes(k)) || (operation === 'verify' && flags.has('--resume'))) throw Error('wrong grammar');
    const bytes = await readFile(input), sha256 = createHash('sha256').update(bytes).digest('hex');
    if (sha256 !== flags.get('--expected-sha256') || bytes.length > Number(flags.get('--max-archive-bytes'))) throw Error('wrong bytes');
    const source = JSON.parse(bytes), instance = flags.get(operation === 'verify' ? '--verification-instance' : '--destination-instance');
    if (!/^[1-9][0-9]*$/.test(instance) || BigInt(instance) > 9223372036854775807n) throw Error('wrong instance');
    const base = { schema_version: 1, sha256, tenant_id: source.tenant_id, repository_id: source.repository_id, incarnation_id: source.incarnation_id,
      object_format: source.object_format, head_generation: BigInt(source.head_generation), objects: 2, references: 1, payload_bytes: 8,
      complete: true, scope: 'authority_and_selected_git_objects', object_graph_verified: true,
      original_payload_commitments_verified: true, node_closed: true, signature_verified: false, routing_published: false, archive_bytes: bytes.length };
    let result;
    if (operation === 'verify') {
      await mkdir(output, { mode: 0o700 }); await writeFile(join(output, 'evidence'), 'fake preflight');
      if (config.mode === 'verify-refuse') throw Error('native preflight refusal');
      if (config.mode === 'verify-flood') { process.stdout.write('x'.repeat(100000)); return; }
      await rm(output, { recursive: true });
      result = { type: 'repository_source_backup_verify', ...base, local_edges: 1, external_gitlinks: 0,
        verification_instance: BigInt(instance), authority_import_verified: true, git_payloads_written: false,
        destination_authority_published: false, scratch_removed: true, destination_readback_verified: false,
        newest_checkpoint_verified: false, external_artifacts_verified: false };
      if (config.mismatch) result[config.mismatch] = config.wrong;
    } else {
      let already = false;
      if (flags.get('--resume')) {
        await stat(output);
        if (await readFile(join(output, 'authority-visible'), 'utf8') !== sha256) throw Error('different restored archive');
        already = true;
      } else { await mkdir(output, { mode: 0o700 }); await writeFile(join(output, 'authority-visible'), sha256); }
      if (config.mode === 'restore-lost-reply') throw Error('lost native receipt');
      if (config.mode === 'restore-wait') {
        process.on('SIGTERM', () => {}); await writeFile(join(output, 'started'), String(process.pid));
        await new Promise(() => { setInterval(() => {}, 1000); });
      }
      result = { type: 'repository_source_backup_restore', ...base, destination_instance: BigInt(instance), source_tokens_preserved: false,
        reopened_and_verified: true, external_artifacts_restored: false, streaming: true,
        resume_requested: Boolean(flags.get('--resume')), already_published: already };
      if (config.mode === 'restore-bad-report') result.signature_verified = true;
    }
    const text = json(result);
    process.stdout.write(config.mode === 'duplicate-report' ? text.replace('{', '{"complete":true,') : text);
  } catch (error) { process.stderr.write(JSON.stringify({ fake: true, error: error.message })); process.exitCode = 2; }
}
