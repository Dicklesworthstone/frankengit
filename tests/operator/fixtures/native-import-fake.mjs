// DELIBERATELY FAKE fg. Tests process/filesystem/recovery composition ONLY.
// It does not parse Git, authenticate authority heads, or prove native atomicity.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, appendFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = dirname(fileURLToPath(import.meta.url));
const mode = JSON.parse(readFileSync(join(root, 'mode.json')));
const args = process.argv.slice(2);
appendFileSync(join(root, 'calls.jsonl'), JSON.stringify(args) + '\n');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const value = flag => args[args.indexOf(flag) + 1];
const emit = result => process.stdout.write(JSON.stringify(result) + '\n');
const wait = () => { process.on('SIGTERM', () => {}); setInterval(() => {}, 1000); };
if (args[0] === 'bundle' && args[1] === 'verify') {
  const bytes = readFileSync(args.at(-1));
  const format = mode.format ?? 'sha1', width = format === 'sha1' ? 40 : 64;
  const pins = [];
  for (let at = 0; at < args.length; at++) if (args[at] === '--expect-ref-hex') {
    const [ref_hex, object_id] = args[++at].split('='); pins.push({ ref_hex, object_id });
  }
  const refs = [{ ref_hex: Buffer.from('refs/heads/main').toString('hex'), object_id: 'a'.repeat(width) }];
  const report = { type: 'git_bundle_verification', schema_version: 1, profile: 'native-full-bundle-graph-v1',
    object_format: format, bundle_bytes: bytes.length, artifact_sha256: hash(bytes), pack_bytes: bytes.length,
    pack_checksum: 'b'.repeat(width), object_count: 1, reference_count: 1, payload_bytes: bytes.length,
    local_edges: 0, external_gitlinks: 0, delta_objects: 0, resolution_passes: 1, advertised_head: refs[0].object_id,
    references: refs, pack_checksum_verified: true, objects_verified: true, object_graph_verified: true,
    graph_scope: 'all-included-objects-and-advertised-direct-refs', gitlink_targets_verified: false,
    signatures_verified: false, origin_authenticated: false, current_branch_verified: false,
    strict_fsck_equivalent: false, repository_opened: false, repository_changed: false, forge_state_verified: false,
    caller_expectations_matched: true, expectations: { artifact_sha256: value('--expect-sha256'),
      object_format: args.includes('--expect-format') ? value('--expect-format') : null,
      ref_set: pins.length ? (args.includes('--exact-refs') ? 'exact' : 'contains') : null, references: pins } };
  if (mode.mutateSource) writeFileSync(mode.mutateSource, 'changed after owned source read');
  if (mode.mutateSnapshot) writeFileSync(mode.mutateSnapshot, 'changed during native verification');
  if (mode.mutateIntent) appendFileSync(mode.mutateIntent, ' ');
  if (mode.verifyGate) {
    while (!existsSync(mode.verifyGate)) await new Promise(resolve => setTimeout(resolve, 5));
  }
  if (mode.verify === 'refuse') process.exitCode = 2;
  else if (mode.verify === 'hang') wait();
  else emit(report);
} else if ((args[0] === 'bundle' && args[1] === 'import') || args[0] === 'outcome') {
  const importing = args[0] === 'bundle', action = importing ? 'import' : 'outcome';
  // Deliberately mirror the READ native CLI grammar, not the caller's adapter.
  // These positions/flags come from bundle.rs::USAGE and outcome.rs::USAGE.
  const fixed = ['--trusted-local', '--principal', '--key-stdin', '--object-format'];
  if (importing ? args.length !== 12 || args[6] !== fixed[0] || args[7] !== fixed[1] || args[9] !== fixed[2] || args[10] !== fixed[3]
    : args.length !== 10 || args[4] !== fixed[0] || args[5] !== fixed[1] || args[7] !== fixed[2] || args[8] !== fixed[3]) {
    throw new Error('fake_rejects_non_native_cli_grammar');
  }
  const storage = args[importing ? 2 : 1], tenant = args[importing ? 3 : 2], repository = args[importing ? 4 : 3];
  const principal = value('--principal'), key = readFileSync(0, 'utf8');
  if (importing) writeFileSync(join(root, 'import-child.pid'), String(process.pid));
  if (!/^fg-source-import-[0-9a-f]{64}$/.test(key)) throw new Error('fake_requires_exact_key_stdin');
  const transaction = `tx:${hash([tenant, repository, principal, key].join(':'))}`;
  const keyDigest = { algorithm: 1, hex: hash(key) }; // FAKE digest, not native derivation.
  const saved = join(storage, `${hash(key)}.fake-outcome.json`);
  let decision = existsSync(saved) ? JSON.parse(readFileSync(saved)) : null;
  if (importing) appendFileSync(join(root, 'attempts.jsonl'), JSON.stringify({ key, path: args[5] }) + '\n');
  if (decision === null && importing && !['pending', 'hang-before', 'fail-before'].includes(mode.import)) {
    const bytes = readFileSync(args[5]);
    appendFileSync(join(root, 'submissions.jsonl'), JSON.stringify({ key, digest: hash(bytes), storage, transaction }) + '\n');
    decision = { outcome: mode.import === 'refuse' ? 'refused' : 'committed', transaction,
      rcr: `rcr:${hash(bytes)}`, sequence: mode.sequence ?? '1', count: 1 };
    try { writeFileSync(saved, JSON.stringify(decision), { flag: 'wx', mode: 0o600 }); }
    catch (error) { if (error.code !== 'EEXIST') throw error; decision = JSON.parse(readFileSync(saved)); }
  }
  if (importing && ['hang-before', 'hang-after'].includes(mode.import)) wait();
  else if (importing && ['lose-commit', 'fail-before', 'pending'].includes(mode.import)) process.exitCode = 2;
  else {
    const committed = decision?.outcome === 'committed', refused = decision?.outcome === 'refused';
    let result;
    if (importing) result = { type: 'git_bundle_import', schema_version: 1, outcome: decision.outcome,
      command_committed: committed, atomic: true, tx_id: decision.transaction, decision_sequence: 'SEQUENCE_NUMBER',
      repository_commit_id: committed ? decision.rcr : null, refusal_code: refused ? 'TargetRefMoved' : null,
      refusal_record_id: refused ? 'refusal:1' : null, principal_id: principal, delivery_acknowledged: null,
      tenant_id: tenant, repository_id: repository, object_format: value('--object-format'), reference_count: decision.count,
      node_closed: true, cleanup_error: null, includes_forge_metadata: false };
    else result = { type: 'transaction_outcome', schema_version: 1, tenant_id: tenant, repository_id: repository,
      principal_id: principal, object_format: value('--object-format'), key_digest: keyDigest, selector: 'transaction', command_index: null,
      state: decision?.outcome ?? 'key_not_observed', terminal: decision !== null,
      transaction: decision === null ? null : { tx_id: decision.transaction, seal_id: 'seal:1',
        canonical_request_digest: { algorithm: 1, hex: 'd'.repeat(64) }, request_schema: 'test-fake-schema' },
      decision: decision === null ? null : committed
        ? { kind: 'committed', decision_sequence: 'SEQUENCE_NUMBER', repository_commit_id: decision.rcr }
        : { kind: 'refused', decision_sequence: 'SEQUENCE_NUMBER', code: 'TargetRefMoved', code_point: 1, refusal_record_id: 'refusal:1' },
      read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
      node_closed: true, cleanup_error: null };
    if (mode.badReceipt === action) { if (importing) result.tx_id = 'tx:foreign'; else if (result.transaction) result.transaction.tx_id = 'tx:foreign'; }
    if (mode.wrongNamespace === action) result.tenant_id = '9'.repeat(32);
    if (mode.wrongFormat === action) result.object_format = 'invalid';
    if (mode.wrongCount === action) result.reference_count = 2;
    if (mode.unknownField === action) result.surprise = true;
    if (mode.cleanup === action) { result.node_closed = false; result.cleanup_error = 'fake native shutdown failed'; }
    let encoded = JSON.stringify(result).replace('"SEQUENCE_NUMBER"', decision?.sequence ?? '1');
    if (mode.duplicate === action) encoded = encoded.replace('{', '{"type":"wrong",');
    if (mode.overflow === action) process.stdout.write('x'.repeat(70000));
    else process.stdout.write(encoded + '\n');
    process.exitCode = mode.cleanup === action ? 2 : mode.wrongExit === action ? 17 : refused ? 3 : decision === null ? 4 : 0;
  }
} else throw new Error('fake_unsupported_command');
