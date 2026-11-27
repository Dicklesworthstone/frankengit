// CLI/read integration with the existing HTTP response-schema peer, not a Rust authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { milestoneArguments, runMilestoneCommand } from '../../scripts/forge_milestones.mjs';
import { milestoneReadOptions } from '../../scripts/lib/forge-milestone-reader.mjs';
import { runNativeProcess } from '../../scripts/lib/native-process-owner.mjs';
import { milestonePeer, milestoneSnapshot, tenant, repository, actor }
  from './native_milestone_transfer_helper.mjs';

const mutations = peer => peer.calls.filter(call => call.method === 'POST' && !call.path.endsWith('/outcomes'));
const cli = fileURLToPath(new URL('../../scripts/forge_milestones.mjs', import.meta.url));
const command = args => runNativeProcess(process.execPath, [cli, ...args], { timeoutMs: 15000, stdoutLimit: 1024 * 1024 });
async function fixture(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-milestone-cli-')), f = {};
  const peer = await milestonePeer(options);
  const tokenFile = join(root, 'token'); await writeFile(tokenFile, peer.token, { mode: 0o600 });
  f.root = root; f.peer = peer; f.tokenFile = tokenFile;
  f.href = peer.href.replace('/ui/issues/', '/ui/milestones/');
  f.connection = { href: f.href, tenant, repository, tokenFile };
  f.flags = (operation, record = null, href = f.href) => [operation, '--url', href, '--tenant-id', tenant,
    '--repository-id', repository, '--token-file', tokenFile, ...(record === null ? [] : ['--record', record])];
  t.after(async () => { await peer.close(); await rm(root, { recursive: true, force: true }); });
  return f;
}

test('milestone CLI has a closed lifecycle grammar, explicit due-date clearing and pinned read bounds', async t => {
  const f = await fixture(t), record = join(f.root, 'request.json');
  const open = [...f.flags('open', record), '--number', '7', '--expected-version', '0', '--title', 'Release'];
  for (const value of ['0', '253402300799']) {
    assert.equal(milestoneArguments([...open, '--due-at', value]).options.fields.due_at, Number(value));
  }
  assert.deepEqual(milestoneArguments(open).options.fields, { title: 'Release', body: '', due_at: null });
  assert.equal(milestoneArguments([...f.flags('open', record, f.peer.href), '--number', '7',
    '--expected-version', '0', '--title', 'Legacy selector']).options.href, f.peer.href);
  const edit = [...f.flags('edit', record), '--number', '7', '--expected-version', '1'];
  assert.deepEqual(milestoneArguments([...edit, '--clear-due-at']).options.fields, { due_at: null });
  assert.deepEqual(milestoneArguments([...edit, '--title', 'Renamed']).options.fields, { title: 'Renamed' });
  const invalid = [
    [...open, '--clear-due-at'], [...open, '--due-at', '253402300800'], [...open, '--due-at', '-1'],
    [...open, '--due-at', '01'], [...open, '--due-at', '0', '--due-at', '1'],
    [...edit], [...edit, '--clear-due-at', '--clear-due-at'], [...edit, '--due-at', '0', '--clear-due-at'],
    [...edit, '--body', 'x', '--body-file', '/private/body'], [...edit, '--label', 'unsupported'],
    [...f.flags('close', record), '--number', '7', '--expected-version', '1', '--due-at', '0'],
    [...f.flags('comment', record), '--number', '7', '--expected-version', '1', '--body', 'x'],
    [...f.flags('retry', record), '--number', '7'], [...f.flags('status', record), '--title', 'x'],
    [...f.flags('list'), '--record', record], [...f.flags('list'), '--clear-due-at'],
    [...f.flags('show'), '--number', '01'], [...f.flags('list'), '--limit'],
  ];
  for (const args of invalid) assert.throws(() => milestoneArguments(args));
  for (const patch of [{ after: 1 }, { number: 1 }, { limit: 101 }, { maxPages: 101 },
      { maxOutputBytes: 8388609 }, { operation: 'search' }, { record }]) {
    assert.throws(() => milestoneReadOptions({ ...f.connection, operation: 'list', ...patch }));
  }
  assert.equal(f.peer.calls.length, 0);
});

test('CLI creates and updates release plans with literal private bodies, optional dates and independent lifecycle', async t => {
  const f = await fixture(t), bodyFile = join(f.root, 'body.txt'), record = join(f.root, 'open.json');
  const literal = 'Release 雪\n<script>literal</script> & text';
  await writeFile(bodyFile, literal, { mode: 0o600 });
  const opened = await runMilestoneCommand([...f.flags('open', record), '--number', '7', '--expected-version', '0',
    '--title', 'Release plan', '--body-file', bodyFile, '--due-at', '0']);
  assert.equal(opened.exitCode, 0); assert.equal(JSON.parse(opened.text).result.outcome, 'committed');
  const receipt = JSON.parse(await readFile(record));
  assert.equal(receipt.href, f.href); assert.equal(receipt.schema, 'frankengit-milestone-operator-v1');
  assert.equal(receipt.receipt.request.fields.body, literal); assert.equal(receipt.receipt.request.fields.due_at, 0);
  let state = milestoneSnapshot(f.peer.milestoneSource.get(7));
  assert.equal(state.body, literal); assert.equal(state.due_at, 0);
  const edit = await runMilestoneCommand([...f.flags('edit', join(f.root, 'edit.json')), '--number', '7',
    '--expected-version', '1', '--title', 'Renamed']);
  assert.equal(edit.exitCode, 0); assert.equal(milestoneSnapshot(f.peer.milestoneSource.get(7)).due_at, 0);
  await writeFile(bodyFile, '');
  const cleared = await runMilestoneCommand([...f.flags('edit', join(f.root, 'clear.json')), '--number', '7',
    '--expected-version', '2', '--body-file', bodyFile, '--clear-due-at']);
  assert.equal(cleared.exitCode, 0);
  const clearForm = new URLSearchParams(mutations(f.peer).at(-1).body);
  assert.equal(clearForm.get('body'), ''); assert.equal(clearForm.get('clear_due_at'), 'true');
  assert.equal(clearForm.has('due_at'), false);
  assert.equal(milestoneSnapshot(f.peer.milestoneSource.get(7)).due_at, null);
  for (const [operation, version, fields] of [['close', 3, []], ['edit', 4, ['--due-at', '253402300799']], ['reopen', 5, []]]) {
    const result = await runMilestoneCommand([...f.flags(operation, join(f.root, operation + '-' + version + '.json')),
      '--number', '7', '--expected-version', String(version), ...fields]);
    assert.equal(result.exitCode, 0);
  }
  state = milestoneSnapshot(f.peer.milestoneSource.get(7));
  assert.deepEqual([state.version, state.title, state.body, state.due_at, state.state], [6, 'Renamed', '', 253402300799, 'open']);
  assert.equal(f.peer.source.size, 0);
  assert.ok(mutations(f.peer).every(call => call.path.includes('/api/v1/milestones/7/')));
  const before = f.peer.calls.length;
  await writeFile(bodyFile, Buffer.from([0xff, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65]));
  await assert.rejects(runMilestoneCommand([...f.flags('edit', join(f.root, 'invalid.json')), '--number', '7',
    '--expected-version', '6', '--body-file', bodyFile]));
  assert.equal(f.peer.calls.length, before); assert.equal((await readdir(f.root)).includes('invalid.json'), false);
});

test('fresh-process CLI recovers the original sponsored request after response loss and later edits', async t => {
  const token = 'fgagent_' + 'c'.repeat(64); let lose = true;
  const f = await fixture(t, { token, afterMutation({ res }) {
    if (lose) { lose = false; res.destroy(); return true; }
  } });
  const record = join(f.root, 'original.json');
  const lost = await command([...f.flags('open', record), '--number', '7', '--expected-version', '0',
    '--title', 'Release', '--body', 'Original private body']);
  assert.equal(lost.code, 2); assert.equal(lost.stdout.length, 0);
  assert.equal(JSON.parse(lost.stderr).state, 'submitted_unknown'); assert.equal(lost.stderr.includes('Original private body'), false);
  const bytes = await readFile(record), request = JSON.parse(bytes).receipt.request;
  assert.equal(request.credential_fingerprint, createHash('sha256').update(token).digest('hex'));
  assert.equal(bytes.includes(token), false);
  f.peer.milestoneSource.get(7).events.push({ version: 2, actor, action: { name: 'edit', title: 'Later title' } },
    { version: 3, actor, action: { name: 'close' } });
  for (const operation of ['status', 'retry']) {
    const result = await command(f.flags(operation, record));
    assert.equal(result.code, 0, result.stderr.toString());
    const value = JSON.parse(result.stdout);
    assert.equal(value.mutation_submitted, false); assert.equal(value.result.tx, f.peer.decisions.get(request.key).tx_id);
    assert.equal(result.stdout.includes(token), false);
  }
  assert.equal(mutations(f.peer).length, 1); assert.deepEqual(await readFile(record), bytes);
  assert.equal(milestoneSnapshot(f.peer.milestoneSource.get(7)).title, 'Later title');
  const refused = await command([...f.flags('close', join(f.root, 'refused.json')), '--number', '7', '--expected-version', '3']);
  assert.equal(refused.code, 3, refused.stderr.toString());
  assert.equal(JSON.parse(refused.stdout).result.refusal, 'ProtectedRefTransitionDenied');
  const before = f.peer.calls.length; await writeFile(f.tokenFile, token.slice(8));
  await assert.rejects(runMilestoneCommand(f.flags('retry', record)), /does not belong/);
  assert.equal(f.peer.calls.length, before);
});

