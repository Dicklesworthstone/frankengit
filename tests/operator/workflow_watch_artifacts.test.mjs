// Actual operator/custody/argv tests. The subprocess is a native-schema fixture,
// not fg; native binary pipeline coverage lives in fgit-cli/tests/workflow_run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, readdir, rename, chmod, symlink, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { configuration, dispatchReport, once, reconcile, serve, status } from '../../scripts/operator/workflow_watch.mjs';
import { configuration as publisherConfiguration } from '../../scripts/operator/workflow_check_publish.mjs';
import { createController } from '../../scripts/operator/workflow_supervisor.mjs';

const hex = value => Buffer.from(value).toString('hex');
const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
const sha256 = value => createHash('sha256').update(value).digest('hex');
const workflow = hex('.github/workflows/ci.yml');
const peer = await readFile(new URL('./fixtures/workflow_watch_native.mjs', import.meta.url), 'utf8');
function captures() {
  return [{ workflow_path_hex: workflow, job_id: 'build', output_path_hex: hex('dist/result') }];
}
function delivery(destination = 'build/result') {
  return [{ workflow_path_hex: workflow, consumer_job_id: 'test', producer_job_id: 'build',
    output_path_hex: hex('dist/result'), destination_hex: hex(destination) }];
}
function base(root, format = 'sha1') {
  return { schema: 'frankengit-workflow-watch-v1', fg: join(root, 'fg'), storage_root: join(root, 'store'),
    tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: format,
    ref_hex: hex('refs/heads/main'), workflow_directory_hex: hex('.github/workflows'), input_prefixes_hex: [hex('.github'), hex('src')],
    event: 'push', state_directory: join(root, 'state'), run_parent: join(root, 'runs'), max_runs: 16,
    trust: 'selected-branch-host-execution' };
}
function configured(root, format = 'sha1', artifactPatch = {}) {
  return configuration({ ...base(root, format), artifacts: { root: join(root, 'artifacts'), selections: captures(), inputs: delivery(), ...artifactPatch } });
}
async function fixture(t, format = 'sha1', controlPatch = {}, artifactPatch = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-watch-artifacts-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const name of ['store', 'state', 'runs', 'artifacts']) await mkdir(join(root, name), { mode: 0o700 });
  const config = configured(root, format, artifactPatch);
  await writeFile(config.fg, `#!${process.execPath}\n${peer}`, { mode: 0o700 });
  let control = { tenant: config.tenant_id, repository: config.repository_id, incarnation: config.repository_incarnation,
    format, ref_hex: config.ref_hex, commit: 'a'.repeat(format === 'sha1' ? 40 : 64),
    source_head: 'fixture-head', snapshot: `alg:2:${'4'.repeat(64)}`, ...controlPatch };
  const set = async patch => { control = { ...control, ...patch }; await writeFile(join(config.storage_root, 'control.json'), encode(control), { mode: 0o600 }); };
  await set({});
  const lines = async name => {
    try { return (await readFile(join(root, 'store', name), 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  };
  const saved = async () => {
    const row = (await status(config)).records[0];
    return { row, intent: JSON.parse(await readFile(join(config.state_directory, `intent-${row.id}.json`))),
      report: JSON.parse(await readFile(join(row.native_directory, 'report.json'))) };
  };
  return { root, config, lines, saved, set };
}

test('legacy configurations keep their exact serialized field order and no artifact defaults', () => {
  const value = base('/fixture');
  assert.equal(JSON.stringify(configuration(value)), JSON.stringify(value));
  assert.equal(Object.hasOwn(configuration(value), 'artifacts'), false);
  const normalized = configured('/fixture');
  assert.deepEqual(configuration(structuredClone(normalized)), normalized);
  assert.equal(normalized.artifacts.maximum_file_mib, 16);
  assert.equal(normalized.artifacts.total_payload_mib, 64);
  assert.equal(normalized.artifacts.total_delivery_mib, 64);
  assert.ok(Object.isFrozen(normalized.artifacts) && Object.isFrozen(normalized.artifacts.inputs[0]));
  const captureOnly = configured('/fixture', 'sha1', { inputs: [] });
  assert.equal(Object.hasOwn(captureOnly.artifacts, 'inputs'), false);
  assert.equal(Object.hasOwn(captureOnly.artifacts, 'total_delivery_mib'), false);
});

test('artifact selectors canonicalize raw bytes and order without command or path interpolation', () => {
  const raw = { ...captures()[0], output_path_hex: `${hex('dist/')}ff3a` };
  const input = { ...delivery()[0], output_path_hex: raw.output_path_hex, destination_hex: `${hex('incoming/')}fe3a` };
  const value = configured('/fixture', 'sha1', { selections: [raw, ...captures()], inputs: [input, ...delivery()] });
  const reverse = configured('/fixture', 'sha1', { selections: [...value.artifacts.selections].reverse(), inputs: [...value.artifacts.inputs].reverse() });
  assert.deepEqual(value, reverse);
  assert.equal(value.artifacts.inputs.some(row => row.destination_hex === input.destination_hex), true);
});

test('invalid, duplicate, uncaptured and overlapping artifact contracts refuse with permitted twins', () => {
  const permitted = () => configured('/fixture');
  for (const mutate of [
    a => { a.root = 'relative'; }, a => { a.root = '/fixture/state/outputs'; }, a => { a.root = '/fixture/fg'; },
    a => { a.root = '/fixture'; }, a => { a.root = '/fixture/artifacts/../alias'; },
    a => { a.maximum_file_mib = 65; }, a => { a.total_payload_mib = 0; }, a => { a.total_delivery_mib = 513; },
    a => { a.total_delivery_mib = 1.5; }, a => { a.total_payload_mib = null; }, a => { a.extra = true; },
    a => { a.selections = []; }, a => { a.selections.push(a.selections[0]); },
    a => { a.inputs[0].producer_job_id = 'other'; }, a => { a.inputs[0].consumer_job_id = 'build'; },
    a => { a.inputs[0].consumer_job_id = 'bad job'; }, a => { a.inputs[0].destination_hex = hex('../outside'); },
    a => { a.inputs[0].destination_hex = hex('.fgit-host-receipt'); }, a => { a.inputs[0].destination_hex = hex('a'.repeat(4001)); },
    a => { a.selections[0].workflow_path_hex = hex('elsewhere/ci.yml'); },
    a => { a.selections[0].output_path_hex = hex('.git/config'); },
    a => { a.inputs.push({ ...a.inputs[0], destination_hex: hex('build') }); },
    a => { a.inputs.push({ ...a.inputs[0] }); },
    a => { a.inputs = []; a.total_delivery_mib = 1; },
  ]) {
    const config = structuredClone(permitted()); mutate(config.artifacts);
    assert.throws(() => configuration(config), undefined, mutate.toString());
    assert.ok(permitted().artifacts.inputs.length);
  }
  const sixtyFour = Array.from({ length: 64 }, (_, i) => ({ ...delivery()[0], destination_hex: hex(`copy/${i}`) }));
  assert.equal(configured('/fixture', 'sha1', { inputs: sixtyFour }).artifacts.inputs.length, 64);
  assert.throws(() => configured('/fixture', 'sha1', { inputs: [...sixtyFour, { ...delivery()[0], destination_hex: hex('last') }] }));
  const paths = Array.from({ length: 64 }, (_, i) => ({ ...captures()[0], output_path_hex: hex(`${Array(5).fill('a'.repeat(210)).join('/')}/${i}`) }));
  assert.throws(() => configured('/fixture', 'sha1', { selections: paths, inputs: [] }), /64 KiB/);
});

test('artifact paths obey native component and metadata rules while retaining raw repository bytes', () => {
  const capture = path => configured('/fixture', 'sha1', { selections: [{ ...captures()[0], output_path_hex: hex(path) }], inputs: [] });
  assert.ok(capture('a'.repeat(255)));
  assert.throws(() => capture('a'.repeat(256)), /native component/);
  assert.ok(capture(Array(64).fill('a').join('/')));
  assert.throws(() => capture(Array(65).fill('a').join('/')), /native component/);
  assert.ok(configured('/fixture', 'sha1', { inputs: delivery(Array(63).fill('a').join('/')) }));
  assert.throws(() => configured('/fixture', 'sha1', { inputs: delivery(Array(64).fill('a').join('/')) }), /native component/);
  for (const path of ['a/\x01', 'a/\n', '.GiT/config', 'GiT~1/config', '.git. /config', '.fgit-host-receipt/child']) {
    assert.throws(() => capture(path)); assert.ok(capture('valid/result'));
  }
  for (const raw of [Buffer.from('a\\b'), Buffer.from([0x61, 0x7f, 0xff, 0xfe]), Buffer.from('valid:result')]) {
    const result = capture(raw);
    assert.equal(result.artifacts.selections[0].output_path_hex, hex(raw));
  }
});

for (const format of ['sha1', 'sha256']) {
  test(`${format}: watched artifact pipeline forwards the canonical contract and deduplicates the commit`, async t => {
    const f = await fixture(t, format, {}, { maximum_file_mib: 2, total_payload_mib: 3, total_delivery_mib: 4 });
    const result = await once(f.config), saved = await f.saved();
    assert.equal(result.outcome, 'observed_succeeded');
    const calls = await f.lines('calls.ndjson'), args = calls[1], get = key => args[args.indexOf(key) + 1];
    assert.equal(get('--artifact-root'), f.config.artifacts.root);
    assert.equal(get('--artifact-hex'), `${workflow}:build:${hex('dist/result')}`);
    assert.equal(get('--artifact-input-hex'), `${workflow}:test:build:${hex('dist/result')}:${hex('build/result')}`);
    assert.equal(get('--max-artifact-mib'), '2'); assert.equal(get('--max-artifact-total-mib'), '3');
    assert.equal(get('--max-artifact-input-total-mib'), '4');
    const contract = saved.report.plan.artifact_contract;
    assert.equal(contract.root_hex, hex(f.config.artifacts.root));
    assert.equal(contract.maximum_file_bytes, 2 * 1048576);
    assert.equal(contract.total_payload_bytes, 3 * 1048576);
    assert.equal(contract.input_delivery.total_delivery_bytes, 4 * 1048576);
    assert.deepEqual(saved.report.runs[0].artifact_contract, contract);
    assert.equal(saved.intent.configuration_sha256, sha256(encode(f.config)));
    assert.equal(await readFile(join(f.config.state_directory, 'binding.json'), 'utf8'), encode(f.config).toString());
    assert.equal((await once(f.config)).reason, 'commit_already_observed');
    assert.equal((await f.lines('effects.ndjson')).length, 1);
    const before = (await f.lines('calls.ndjson')).length;
    for (const patch of [{ root: join(f.root, 'other-artifacts') }, { inputs: delivery('other/result') }, { total_delivery_mib: 5 }]) {
      if (patch.root) await mkdir(patch.root, { mode: 0o700 });
      await assert.rejects(once({ ...f.config, artifacts: { ...f.config.artifacts, ...patch } }), /configuration changed/);
    }
    assert.equal((await f.lines('calls.ndjson')).length, before);
    assert.equal(result.authoritative_check, false);
  });

  test(`${format}: lost reply reconciles artifact custody offline without a second dispatch`, async t => {
    const f = await fixture(t, format, { drop_stdout: true });
    await assert.rejects(once(f.config), /Dispatch unresolved/);
    const saved = await f.saved(), marker = await readFile(join(saved.row.native_directory, 'dispatch.json'));
    const result = join(f.config.state_directory, `result-${saved.row.id}.json`);
    await rename(f.config.storage_root, `${f.config.storage_root}-offline`);
    await rename(f.config.artifacts.root, `${f.config.artifacts.root}-offline`);
    await unlink(f.config.fg);
    assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
    assert.equal((await reconcile(f.config)).records[0].state, 'observed_succeeded');
    const completed = await readFile(result);
    await reconcile(f.config);
    assert.deepEqual(await readFile(result), completed);
    assert.deepEqual(await readFile(join(saved.row.native_directory, 'dispatch.json')), marker);
    assert.equal((await readdir(f.config.run_parent)).length, 1);
  });
}

test('capture-only watchers forward output flags without granting an input delivery contract', async t => {
  const f = await fixture(t, 'sha1', {}, { inputs: [] }); await once(f.config);
  const args = (await f.lines('calls.ndjson'))[1], saved = await f.saved();
  assert.equal(args.includes('--artifact-input-hex'), false);
  assert.equal(args.includes('--max-artifact-input-total-mib'), false);
  assert.equal(Object.hasOwn(saved.report.plan.artifact_contract, 'input_delivery'), false);
});

test('changed native output and input contracts remain unresolved, with exact permitted twins', async t => {
  const f = await fixture(t); await once(f.config); const saved = await f.saved();
  for (const mutate of [
    r => { delete r.plan.artifact_contract; }, r => { r.plan.artifact_contract.root_hex = hex('/other'); },
    r => { r.plan.artifact_contract.trust_domain = 'untrusted'; }, r => { r.plan.artifact_contract.total_payload_bytes++; },
    r => { r.plan.artifact_contract.retention_ttl_seconds++; },
    r => { r.plan.artifact_contract.input_delivery.total_delivery_bytes++; },
    r => { r.plan.artifact_contract.input_delivery.selections[0].destination_hex = hex('different'); },
    r => { r.plan.artifact_contract.input_delivery.selections[0].producer_job_id_hex = hex('other'); },
    r => { r.plan.artifact_contract.selections[0].output_path_hex = hex('other'); },
    r => { r.plan.artifact_contract.extra = true; }, r => { delete r.runs[0].artifact_contract; },
    r => { r.runs[0].artifact_contract.maximum_file_bytes++; },
    r => { r.plan.workflows[0].selected = false; r.matched_count = 0; r.executed_count = 0; r.runs = []; },
  ]) {
    const report = structuredClone(saved.report); mutate(report);
    assert.throws(() => dispatchReport(f.config, saved.intent, report), /artifact/i, mutate.toString());
    assert.equal(dispatchReport(f.config, saved.intent, structuredClone(saved.report)).outcome, 'observed_succeeded');
  }
  const noArtifacts = { ...f.config }; delete noArtifacts.artifacts;
  assert.throws(() => dispatchReport(noArtifacts, saved.intent, saved.report), /unrequested artifact/);
});

test('native contract omission blocks replay and reconciliation instead of recording a successful run', async t => {
  const f = await fixture(t, 'sha1', { plan_patch: { artifact_contract: null } });
  await assert.rejects(once(f.config), /artifact contract differs/);
  assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
  await assert.rejects(reconcile(f.config), /artifact contract differs/);
  await assert.rejects(once(f.config), /unresolved/);
  assert.equal((await f.lines('effects.ndjson')).length, 1);
});

test('artifact roots are validated before custody or native effects and offline status stays available', async t => {
  const f = await fixture(t);
  await chmod(f.config.artifacts.root, 0o755);
  await assert.rejects(once(f.config), /private/);
  assert.deepEqual(await readdir(f.config.state_directory), []);
  assert.deepEqual(await f.lines('calls.ndjson'), []);
  await chmod(f.config.artifacts.root, 0o700);
  const original = f.config.artifacts.root;
  await rename(original, `${original}-real`); await symlink(`${original}-real`, original);
  await assert.rejects(once(f.config), /symlink/);
  assert.deepEqual(await readdir(f.config.state_directory), []);
  await unlink(original); await rename(`${original}-real`, original);
  assert.equal((await once(f.config)).outcome, 'observed_succeeded');
});

test('combined native argument bounds refuse before recording a started dispatch', async t => {
  const f = await fixture(t), prefixes = [hex('.github'), ...Array.from({ length: 1023 }, (_, i) => hex(`input-${i}`))];
  const inputs = Array.from({ length: 64 }, (_, i) => ({ ...delivery()[0], destination_hex: hex(`copy-${i}`) }));
  const config = configuration({ ...f.config, input_prefixes_hex: prefixes, artifacts: { ...f.config.artifacts, inputs } });
  await assert.rejects(once(config), /native dispatch envelope/);
  assert.equal((await f.lines('calls.ndjson')).length, 1, 'only refs ran');
  assert.equal((await readdir(config.state_directory)).some(name => name.startsWith('started-')), false);
  assert.equal((await status(config)).records[0].state, 'queued');
});

test('continuous artifact watchers drain a stopped dispatch and retain its original contract', async t => {
  const f = await fixture(t, 'sha1', { dispatch_delay: 100 }), stop = new AbortController();
  const running = serve(f.config, { signal: stop.signal, pollMs: 100, maxPolls: 2, onObservation: () => stop.abort() });
  const result = await running;
  assert.equal(result.runs, 1); assert.equal(result.stopped, true);
  assert.equal((await f.lines('effects.ndjson')).length, 1);
  assert.equal((await status(f.config)).records[0].state, 'observed_succeeded');
});

test('publisher and supervisor custody stay disjoint while exact shared artifact roots remain valid', () => {
  const watch = configured('/fixture');
  const publisher = { schema: 'frankengit-workflow-check-publisher-v1', watch, state_directory: '/fixture/publication', principal_id: '5'.repeat(32) };
  assert.ok(publisherConfiguration(publisher));
  for (const state of [watch.artifacts.root, `${watch.artifacts.root}/publisher`, '/fixture']) {
    assert.throws(() => publisherConfiguration({ ...publisher, state_directory: state }), /disjoint/);
  }
  const backend = { configuration: publisherConfiguration, execute() {}, publish() {}, watchStatus() {}, publicationStatus() {} };
  const controller = createController(backend);
  const second = { ...publisher, state_directory: '/fixture/second-publication', watch: { ...watch,
    ref_hex: hex('refs/heads/other'), state_directory: '/fixture/second-state', run_parent: '/fixture/second-runs', artifacts: structuredClone(watch.artifacts) } };
  const value = { schema: 'frankengit-workflow-supervisor-v1', state_directory: '/fixture/supervisor',
    lanes: [{ name: 'first', publisher }, { name: 'second', publisher: second }] };
  assert.equal(controller.configuration(value).lanes.length, 2);
  for (const root of ['/fixture/supervisor', '/fixture/second-state', '/fixture/second-runs', '/fixture/second-publication', '/fixture/store', '/fixture/artifacts/nested']) {
    const changed = structuredClone(value); changed.lanes[0].publisher.watch.artifacts.root = root;
    assert.throws(() => controller.configuration(changed), /disjoint|separate|Artifact roots/);
    assert.equal(controller.configuration(value).lanes.length, 2);
  }
});
