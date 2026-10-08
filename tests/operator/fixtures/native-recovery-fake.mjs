// DELIBERATELY FAKE native verifier. Emits known fixture layouts for adapter
// tests; never evidence that Rust parsing, validation or index construction ran.
import { createHash } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = dirname(fileURLToPath(import.meta.url));
const settings = JSON.parse(readFileSync(join(root, 'settings.json')));
const args = process.argv.slice(2), value = flag => args[args.indexOf(flag) + 1];
appendFileSync(join(root, 'calls.jsonl'), JSON.stringify(args) + '\n');
writeFileSync(join(root, 'pid'), String(process.pid));
if (settings.mode === 'hang') { process.on('SIGTERM', () => {}); setInterval(() => {}, 1000); }
else if (settings.mode === 'refuse') process.exitCode = 2;
else {
  if (args[0] !== 'bundle' || args[1] !== 'verify' || args.at(-2) !== '--') throw Error('non_native_arguments');
  const bytes = readFileSync(args.at(-1)), format = settings.format;
  const bundle = Buffer.from(readFileSync(join(settings.fixtures, `${format}.bundle.hex`), 'utf8').trim(), 'hex');
  const index = format === 'sha256'
    ? inflateSync(Buffer.from(readFileSync(join(settings.fixtures, 'sha256.idx.zlib.hex'), 'utf8').trim(), 'hex')).toString('hex')
    : readFileSync(join(settings.fixtures, `${format}.idx.hex`), 'utf8').trim();
  const hash = bytes => createHash('sha256').update(bytes).digest('hex');
  if (hash(bundle) !== hash(bytes) || value('--expect-sha256') !== hash(bytes)) throw Error('fake_fixture_only');
  const packOffset = format === 'sha1' ? 128 : 198, width = format === 'sha1' ? 20 : 32;
  const commit = format === 'sha1' ? '8e66527465821b289d8ad275784255bc8825617a' : 'c2a1cfc79b851e01921198e44377712b8ce0593cafe564873b9de729af20ec78';
  const tag = format === 'sha1' ? 'fdf36c252d4e297cc62a161ba48176f6dcafa08a' : '91cf791e6e424d4f8449c7f57012ce46de9c7053ed326b0c34744d522c9da04d';
  const hex = text => Buffer.from(text).toString('hex');
  const refs = [{ ref_hex: hex('refs/heads/main'), object_id: commit }, { ref_hex: hex('refs/tags/v1'), object_id: tag }];
  if (settings.rawHead) refs[0].ref_hex = settings.rawHead;
  const pins = [];
  for (let i = 0; i < args.length; i++) if (args[i] === '--expect-ref-hex') {
    const [ref_hex, object_id] = args[++i].split('='); pins.push({ ref_hex, object_id });
  }
  const report = { type: 'git_bundle_verification', schema_version: 1, profile: 'native-full-bundle-graph-v1',
    object_format: format, bundle_bytes: bytes.length, artifact_sha256: hash(bytes), pack_bytes: bytes.length - packOffset,
    pack_checksum: bytes.subarray(-width).toString('hex'), object_count: 5, reference_count: 2, payload_bytes: 512,
    local_edges: 3, external_gitlinks: 0, delta_objects: 1, resolution_passes: 2, advertised_head: null,
    references: refs, pack_checksum_verified: true, objects_verified: true, object_graph_verified: true,
    graph_scope: 'all-included-objects-and-advertised-direct-refs', gitlink_targets_verified: false,
    signatures_verified: false, origin_authenticated: false, current_branch_verified: false,
    strict_fsck_equivalent: false, repository_opened: false, repository_changed: false, forge_state_verified: false,
    caller_expectations_matched: true, expectations: { artifact_sha256: value('--expect-sha256'),
      object_format: args.includes('--expect-format') ? value('--expect-format') : null,
      ref_set: pins.length ? args.includes('--exact-refs') ? 'exact' : 'contains' : null, references: pins } };
  if (args.includes('--recovery-head-hex')) {
    const head = value('--recovery-head-hex');
    report.recovery = { profile: 'native-bare-source-layout-v1', pack_offset: packOffset, head_ref_hex: head,
      index_hex: index, packed_refs_hex: Buffer.concat([Buffer.from('# pack-refs with: sorted\n'),
        ...refs.flatMap(row => [Buffer.from(`${row.object_id} `), Buffer.from(row.ref_hex, 'hex'), Buffer.from('\n')])]).toString('hex'),
      config_hex: hex(format === 'sha1' ? '[core]\n\trepositoryformatversion = 0\n\tbare = true\n'
        : '[core]\n\trepositoryformatversion = 1\n\tbare = true\n[extensions]\n\tobjectformat = sha256\n'),
      head_hex: Buffer.concat([Buffer.from('ref: '), Buffer.from(head, 'hex'), Buffer.from('\n')]).toString('hex') };
  }
  Object.assign(report, settings.report ?? {});
  if (settings.layout) Object.assign(report.recovery, settings.layout);
  if (settings.mode === 'missing-layout') delete report.recovery;
  if (settings.mode === 'huge') process.stdout.write('x'.repeat(17 * 1024 * 1024));
  else process.stdout.write(JSON.stringify(report) + '\n');
}
