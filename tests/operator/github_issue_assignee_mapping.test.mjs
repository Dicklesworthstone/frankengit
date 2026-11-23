// Real source compiler, custody and CLI. No live GitHub or native authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, readdir, realpath, rm, chmod, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { captureBytes, parseCapture, issueImportSteps, mapGithubIssueAssignees,
  createGithubIssueCaptureSession, CAPTURE_SCHEMA, CAPTURE_SCHEMA_V2, CAPTURE_SCHEMA_V3,
  ASSIGNEE_MAP_SCHEMA, ASSIGNEE_MAP_LIMIT, CAPTURE_LIMIT,
} from '../../scripts/lib/github-issue-source.mjs';
import { prepareGithubIssueImport, inspectPreparedGithubIssueImport } from '../../scripts/lib/github-issue-import.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { importArguments, runGithubImportCommand } from '../../scripts/import_github_issues.mjs';

const frozen = JSON.parse(await readFile(new URL('./fixtures/github_issue_capture_v2.json', import.meta.url)));
const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
const principal = n => BigInt(n).toString(16).padStart(32, '0');
function source(ids = [['11'], ['11']]) {
  const capture = structuredClone(frozen.capture);
  capture.issues.forEach((issue, index) => {
    issue.assignees = ids[index].map(id => ({ id, login: `source-user-${id}` })).sort((a, b) => a.id < b.id ? -1 : 1);
  });
  return captureBytes(capture);
}
function mapping(bytes) {
  const ids = [...new Set(parseCapture(bytes).issues.flatMap(issue => issue.assignees.map(actor => actor.id)))];
  return { schema: ASSIGNEE_MAP_SCHEMA, capture_sha256: recordDigest(bytes), mappings: ids.map((id, i) => ({
    source_user_id: id, destination_principal_id: principal(i + 1),
  })) };
}
async function directory(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'fg-assignee-map-')));
  t.after(() => rm(root, { recursive: true, force: true })); return root;
}
const absent = path => assert.rejects(lstat(path), { code: 'ENOENT' });

test('mapping is explicit, deterministic, full-width and preserves exact source bodies and event order', () => {
  const bytes = source([['2', '10', '18446744073709551615'], ['2']]);
  const selected = mapping(bytes), original = Buffer.from(bytes), savedMap = encode(selected);
  const mapped = mapGithubIssueAssignees(bytes, savedMap);
  const alternate = { ...selected, mappings: [...selected.mappings].reverse() };
  assert.deepEqual(mapGithubIssueAssignees(bytes, Buffer.from(JSON.stringify(alternate, null, 2))).bytes, mapped.bytes);
  assert.deepEqual(bytes, original); assert.deepEqual(savedMap, encode(selected));
  assert.equal(mapped.capture.schema, CAPTURE_SCHEMA_V3);
  assert.deepEqual(mapped.capture.issues, parseCapture(bytes).issues);
  assert.deepEqual(mapped.capture.assignee_map.mappings.map(row => row.source_user_id), ['2', '10', '18446744073709551615']);
  assert.equal(mapped.assignmentCommands, 2);
  assert.deepEqual(parseCapture(mapped.bytes), mapped.capture);
  const steps = issueImportSteps(mapped.capture, 100), previous = issueImportSteps(parseCapture(bytes), 100);
  for (const issue of mapped.capture.issues) {
    const current = steps.filter(step => step.number === issue.number + 100);
    assert.deepEqual(current.map(step => step.expected_version), current.map((_, index) => index));
    assert.equal(current[0].action, 'open'); assert.equal(current[1].action, 'assign');
    assert.deepEqual(current[1].fields.assignees, [...current[1].fields.assignees].sort());
    assert.equal(current.at(-1).action, 'lock');
    if (issue.state === 'closed') assert.equal(current.at(-2).action, 'close');
    const withoutAssignments = current.filter(step => step.action !== 'assign').map(step => ({
      ...step, expected_version: step.expected_version === 0 ? 0 : step.expected_version - 1,
    }));
    assert.deepEqual(withoutAssignments, previous.filter(step => step.number === issue.number + 100));
  }
});

test('empty mapping is permitted only for an unassigned population and source reads cannot opt into V3', () => {
  const bytes = source([[], []]), result = mapGithubIssueAssignees(bytes, encode(mapping(bytes)));
  assert.equal(result.assignmentCommands, 0);
  assert.deepEqual(issueImportSteps(result.capture), issueImportSteps(parseCapture(bytes)));
  assert.throws(() => createGithubIssueCaptureSession({ captureSchema: CAPTURE_SCHEMA_V3 }), /capture_schema/);
});

for (const [name, change, code] of [
  ['missing source', map => { map.mappings.pop(); }, 'assignee_map_population'],
  ['unselected source', map => { map.mappings[0].source_user_id = '999'; }, 'assignee_map_population'],
  ['duplicate source', map => { map.mappings[1].source_user_id = map.mappings[0].source_user_id; }, 'assignee_map_duplicate'],
  ['duplicate destination', map => { map.mappings[1].destination_principal_id = map.mappings[0].destination_principal_id; }, 'assignee_map_duplicate'],
  ['numeric source', map => { map.mappings[0].source_user_id = 11; }, 'assignee_map_source_id'],
  ['login source', map => { map.mappings[0].source_user_id = 'source-user-11'; }, 'identity'],
  ['noncanonical source', map => { map.mappings[0].source_user_id = '011'; }, 'identity'],
  ['overflow source', map => { map.mappings[0].source_user_id = '18446744073709551616'; }, 'identity'],
  ['uppercase destination', map => { map.mappings[0].destination_principal_id = 'A'.repeat(32); }, 'assignee_map_principal'],
  ['wrong-width destination', map => { map.mappings[0].destination_principal_id = 'a'.repeat(64); }, 'assignee_map_principal'],
  ['extra mapping field', map => { map.mappings[0].login = 'guess'; }, 'assignee_map_fields'],
  ['extra map field', map => { map.enroll = true; }, 'assignee_map_fields'],
  ['unknown map schema', map => { map.schema += '-unknown'; }, 'assignee_map_schema'],
  ['stale capture hash', map => { map.capture_sha256 = '0'.repeat(64); }, 'assignee_map_capture_changed'],
  ['missing capture hash', map => { delete map.capture_sha256; }, 'assignee_map_fields'],
]) test(`${name} refuses without silently dropping or guessing an assignment`, () => {
  const bytes = source([['11', '12'], []]), map = mapping(bytes); change(map);
  assert.throws(() => mapGithubIssueAssignees(bytes, encode(map)), { code: `github_import_${code}` });
});

test('duplicate decoded JSON keys, malformed private JSON and non-UTF8 map input have a redacted refusal', () => {
  const bytes = source(), good = encode(mapping(bytes)).toString();
  const inputs = [
    good.replace('"destination_principal_id":', '"destination_principal_id":"' + principal(9) + '","destination_principal_id":'),
    good.replace('"destination_principal_id":', '"destination_principal_\\u0069d":"' + principal(9) + '","destination_principal_id":'),
    '{"private":SECRET_MUST_NOT_APPEAR}', Buffer.from([0xff]),
  ];
  for (const input of inputs) assert.throws(() => mapGithubIssueAssignees(bytes, Buffer.from(input)), error =>
    error.code === 'github_import_assignee_map_json' && !error.message.includes('SECRET_MUST_NOT_APPEAR') && error.cause === undefined);
});

test('mapping consent cannot move to different source data, or be inferred by relabeling legacy captures', () => {
  const bytes = source(), map = encode(mapping(bytes)), changed = parseCapture(bytes);
  changed.issues[0].comments[0].body += 'later edit';
  assert.throws(() => mapGithubIssueAssignees(captureBytes(changed), map), /assignee_map_capture_changed/);
  const mapped = mapGithubIssueAssignees(bytes, map), altered = structuredClone(mapped.capture);
  altered.issues[0].body += 'substituted';
  assert.throws(() => parseCapture(encode(altered)), /assignee_map_capture_changed/);
  const legacy = parseCapture(bytes); legacy.schema = CAPTURE_SCHEMA;
  assert.throws(() => mapGithubIssueAssignees(captureBytes(legacy), map), /assignee_map_requires_v2/);
  assert.throws(() => mapGithubIssueAssignees(mapped.bytes, map), /assignee_map_requires_v2/);
  assert.throws(() => captureBytes({ ...parseCapture(bytes), schema: CAPTURE_SCHEMA_V3 }), /capture_schema/);
});

test('native 16-principal boundary is enforced only for mapped captures, including all-zero native IDs', () => {
  const ids = Array.from({ length: 17 }, (_, i) => String(i + 1));
  const exact = source([ids.slice(0, 16), []]), map = mapping(exact);
  map.mappings[0].destination_principal_id = principal(0);
  const result = mapGithubIssueAssignees(exact, encode(map));
  assert.equal(issueImportSteps(result.capture).find(step => step.action === 'assign').fields.assignees.length, 16);
  const oversized = source([ids, []]);
  assert.equal(issueImportSteps(parseCapture(oversized)).some(step => step.action === 'assign'), false);
  assert.throws(() => mapGithubIssueAssignees(oversized, encode(mapping(oversized))), /native_assignee_limit/);
  assert.throws(() => mapGithubIssueAssignees(exact, Buffer.alloc(ASSIGNEE_MAP_LIMIT + 1, 32)), /assignee_map_limit/);
  assert.throws(() => mapGithubIssueAssignees(Buffer.alloc(CAPTURE_LIMIT + 1), encode(map)), /capture_bytes/);
});

test('mapping validates native provenance-expanded body limits before returning a usable capture', () => {
  const capture = parseCapture(source()); capture.issues[0].body = 'x'.repeat(65536);
  const bytes = captureBytes(capture);
  assert.throws(() => mapGithubIssueAssignees(bytes, encode(mapping(bytes))), /oversized body/);
});

test('frozen V2 compilation and every saved request key/body/plan byte remain unchanged', async t => {
  const bytes = captureBytes(frozen.capture), steps = issueImportSteps(frozen.capture, 40), golden = frozen.golden;
  assert.equal(recordDigest(bytes), golden.capture_sha256); assert.equal(recordDigest(encode(steps)), golden.steps_sha256);
  const root = await directory(t), captureFile = join(root, 'capture.json'), tokenFile = join(root, 'token');
  await writeFile(captureFile, bytes, { mode: 0o600 });
  await writeFile(tokenFile, createHash('sha256').update('FrankenGit GitHub-v1 public regression token, never a real credential').digest('hex'), { mode: 0o600 });
  const options = { captureFile, tokenFile, workdir: join(root, 'plan'),
    href: 'https://fixture.invalid/destination/ui/issues/', tenant: '4'.repeat(32), repository: '5'.repeat(32), offset: 40 };
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto'), oldFetch = globalThis.fetch;
  let nonce = 0, finished = false;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: {
    subtle: webcrypto.subtle, getRandomValues(value) { assert.equal(finished, false); value.fill(++nonce); return value; },
  } });
  globalThis.fetch = () => assert.fail('preparation and inspection must remain offline');
  try {
    const plan = await prepareGithubIssueImport(options); finished = true;
    assert.equal(plan.plan_sha256, golden.plan_sha256); assert.equal(nonce, golden.nonce_count);
    const hashes = {};
    for (const name of (await readdir(options.workdir)).sort()) hashes[name] = recordDigest(await readFile(join(options.workdir, name)));
    assert.deepEqual(hashes, golden.hashes);
    const { captureFile: _capture, offset: _offset, ...inspect } = options;
    await rm(captureFile);
    assert.equal((await inspectPreparedGithubIssueImport({ ...inspect, confirm: plan.plan_sha256 })).steps, steps.length);
    assert.equal(nonce, golden.nonce_count);
  } finally { Object.defineProperty(globalThis, 'crypto', descriptor); globalThis.fetch = oldFetch; }
});

async function cliFixture(t) {
  const root = await directory(t), input = join(root, 'source.json'), mapFile = join(root, 'map.json'), out = join(root, 'mapped.json');
  const bytes = source(); await writeFile(input, bytes, { mode: 0o600 });
  await writeFile(mapFile, JSON.stringify(mapping(bytes), null, 2), { mode: 0o600 });
  const preload = join(root, 'no-network.mjs');
  await writeFile(preload, "globalThis.fetch = () => { throw new Error('unexpected network access'); };\n", { mode: 0o600 });
  const args = ['map-assignees', '--capture', input, '--map', mapFile, '--out', out];
  async function child(extra) {
    const cli = fileURLToPath(new URL('../../scripts/import_github_issues.mjs', import.meta.url));
    return new Promise((resolve, reject) => {
      const proc = spawn(process.execPath, ['--max-old-space-size=128', '--import', pathToFileURL(preload).href, cli, ...extra], { stdio: ['ignore', 'pipe', 'pipe'] });
      const stdout = [], stderr = [], timer = setTimeout(() => { proc.kill('SIGKILL'); reject(new Error('mapping CLI deadline')); }, 10000);
      proc.stdout.on('data', bytes => stdout.push(bytes)); proc.stderr.on('data', bytes => stderr.push(bytes));
      proc.once('error', error => { clearTimeout(timer); reject(error); });
      proc.once('close', code => { clearTimeout(timer); resolve({ code, out: Buffer.concat(stdout).toString(), err: Buffer.concat(stderr).toString() }); });
    });
  }
  return { root, input, mapFile, out, bytes, args, child };
}

test('real CLI maps, inspects and prepares a V3 capture offline without altering source or existing output', async t => {
  const f = await cliFixture(t), mapped = await f.child(f.args);
  assert.equal(mapped.code, 0, mapped.err); const receipt = JSON.parse(mapped.out);
  assert.equal(receipt.type, 'github_issue_assignee_mapping'); assert.equal(receipt.network_accessed, false);
  assert.equal(receipt.source_capture_sha256, recordDigest(f.bytes));
  const bytes = await readFile(f.out); assert.equal(recordDigest(bytes), receipt.sha256);
  assert.equal(parseCapture(bytes).schema, CAPTURE_SCHEMA_V3);
  assert.equal((await lstat(f.out)).mode & 0o777, 0o600); assert.deepEqual(await readFile(f.input), f.bytes);
  const inspect = await f.child(['inspect', '--capture', f.out, '--offset', '100']);
  assert.equal(inspect.code, 0, inspect.err); assert.equal(JSON.parse(inspect.out).steps.filter(s => s.action === 'assign').length, 2);
  const tokenFile = join(f.root, 'token'); await writeFile(tokenFile, 'c'.repeat(64), { mode: 0o600 });
  const prepared = await f.child(['prepare', '--capture', f.out, '--workdir', join(f.root, 'plan'),
    '--url', 'https://fixture.invalid/destination/ui/issues/', '--tenant-id', '4'.repeat(32), '--repository-id', '5'.repeat(32),
    '--token-file', tokenFile, '--offset', '100']);
  assert.equal(prepared.code, 0, prepared.err); assert.equal(JSON.parse(prepared.out).steps, receipt.steps);
  const again = await f.child(f.args); assert.equal(again.code, 2);
  assert.equal(JSON.parse(again.err).code, 'operator_record_exists'); assert.deepEqual(await readFile(f.out), bytes);
});

test('CLI rejects stale/public mapping inputs and cancellation without creating output', async t => {
  const f = await cliFixture(t), value = mapping(f.bytes); value.capture_sha256 = '0'.repeat(64);
  await writeFile(f.mapFile, encode(value));
  await assert.rejects(runGithubImportCommand(f.args), /assignee_map_capture_changed/); await absent(f.out);
  await writeFile(f.mapFile, encode(mapping(f.bytes))); await chmod(f.mapFile, 0o644);
  await assert.rejects(runGithubImportCommand(f.args), /private_owner/); await absent(f.out);
  await chmod(f.mapFile, 0o600); const stop = new AbortController(); stop.abort();
  await assert.rejects(runGithubImportCommand(f.args, stop.signal), { name: 'AbortError' }); await absent(f.out);
  for (const extra of [['--token-file', f.input], ['--url', 'https://unexpected.invalid'], ['--map', f.mapFile], ['--offset', '100']]) {
    assert.throws(() => importArguments([...f.args, ...extra]), /github_import_option/);
  }
});
