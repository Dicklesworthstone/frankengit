// Real HTTP/files/process tests against a response-schema peer, not a Rust
// authority or proof of native publication. The shipped TagClient is unchanged
// on the operator path; object IDs use the independent Node fixture hash.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { chmodSync } from 'node:fs';
import { mkdtemp, readFile, writeFile, chmod, stat, rm, symlink, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { runTagOperation, tagOperatorOptions } from '../../scripts/lib/forge-tag-operator.mjs';
import { tagArguments, runTagCommand } from '../../scripts/forge_tags.mjs';
import { fixture, token, hex, source, existing, destination, head, objectBody, objectId } from '../browser/tags-fixtures.mjs';
import { listenForFetch } from './fetch_listener_helper.mjs';

async function peer(t, algorithm = 'sha1') {
  const f = fixture(algorithm), root = await mkdtemp(join(tmpdir(), 'fg-tag-operator-'));
  const calls = [], faults = {}, tokenFile = join(root, 'token'), record = join(root, 'release.json');
  await writeFile(tokenFile, token + '\n', { mode: 0o600 });
  f.config.list = (page, call) => {
    const fields = Object.fromEntries(new URLSearchParams(call.body));
    const rows = f.refs.filter(row => fields.after === undefined || row.ref_hex > fields.after);
    page.cursor_encoding = fields.cursor_encoding; page.after = fields.after ?? null;
    page.refs = structuredClone(rows.slice(0, Number(fields.limit)));
    page.next_after = rows.length > page.refs.length ? page.refs.at(-1).ref_hex : null;
    faults.page?.(page, call);
  };
  const server = createServer(async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks).toString(), path = req.url.split('/api/v1/')[1];
      const call = { path, body, fields: Object.fromEntries(new URLSearchParams(body)), headers: req.headers };
      calls.push(call);
      if (req.headers.authorization !== `Bearer ${token}`) { res.writeHead(401); return res.end('{}'); }
      if (await faults.before?.(call, req, res)) return;
      const response = await f.fetchImpl(`http://127.0.0.1${req.url}`, { method: req.method, headers: req.headers,
        ...(body ? { body } : {}) });
      const bytes = await response.text();
      if (/^source\/tags\/(?:lightweight|annotated|delete)$/.test(path)) {
        f.config.outcome = f.config.refuse ? 'refused' : 'committed';
        if (await faults.afterMutation?.(call, req, res)) return;
      }
      res.writeHead(response.status, { 'Content-Type': 'application/json' }); res.end(bytes);
    } catch { res.destroy(); }
  });
  const port = await listenForFetch(server);
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true }); });
  const base = { href: `http://127.0.0.1:${port}/repo.git/ui/tags/`, tenant: f.common.tenant_id,
    repository: f.common.repository_id, tokenFile, timeoutMs: 5000 };
  const fresh = { ...base, operation: 'lightweight', objectFormat: algorithm, record,
    refHex: destination, sourceRefHex: source, target: f.commit };
  const reading = { ...base, operation: 'list', objectFormat: algorithm };
  const recovery = operation => ({ ...base, record, operation });
  const cli = operation => [operation, '--url', base.href, '--tenant-id', base.tenant,
    '--repository-id', base.repository, '--token-file', tokenFile];
  return { f, faults, calls, root, record, tokenFile, base, fresh, reading, recovery, cli };
}
const writes = calls => calls.filter(call => /^source\/tags\/(?:lightweight|annotated|delete)$/.test(call.path));
async function exists(path) { try { await stat(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } }
async function command(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL('../../scripts/forge_tags.mjs', import.meta.url)), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = ''; const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('tag CLI deadline')); }, 15000);
    child.stdout.on('data', bytes => { stdout += bytes; }); child.stderr.on('data', bytes => { stderr += bytes; });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
  });
}

for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: a raw-byte tag publishes only after the exact token-free record exists`, async t => {
    const p = await peer(t, algorithm), refHex = hex('refs/tags/release-') + 'ff';
    let observedRecord;
    p.faults.afterMutation = async call => {
      const bytes = await readFile(p.record); observedRecord = JSON.parse(bytes);
      assert(!bytes.includes(Buffer.from(token))); assert.equal((await stat(p.record)).mode & 0o777, 0o600);
      assert.equal(observedRecord.receipt.key, call.headers['idempotency-key']);
      assert.equal(observedRecord.receipt.fields.ref_hex, refHex);
      assert.equal(observedRecord.receipt.fields.target, p.f.commit);
      return false;
    };
    const result = await runTagOperation({ ...p.fresh, refHex });
    assert.equal(result.state, 'terminal_observed'); assert.equal(result.result.outcome, 'committed');
    assert(observedRecord); assert.equal(writes(p.calls).length, 1);
    const sent = writes(p.calls)[0]; assert.equal(sent.fields.ref_hex, refHex); assert.equal(sent.fields.target, p.f.commit);
    assert.equal(sent.fields.expected_object, undefined); assert.equal(sent.fields.force, undefined);
    assert.match(sent.headers['user-agent'], /^frankengit-agent/);
    const before = p.calls.length;
    const status = await runTagOperation(p.recovery('status'));
    assert.equal(status.result.outcome, 'committed'); assert.equal(status.mutation_submitted, false);
    assert.equal(p.calls.length, before + 1); assert.equal(p.calls.at(-1).path, 'outcomes');
  });

  test(`${algorithm}: CLI preserves annotated bytes and records the derived native object`, async t => {
    const p = await peer(t, algorithm), messageFile = join(p.root, 'message');
    const bytes = Buffer.from([0xff, 0x0d, 0x0a, 0x78]); await writeFile(messageFile, bytes, { mode: 0o600 });
    const refHex = hex('refs/tags/release-') + 'fe';
    const args = [...p.cli('annotated'), '--record', p.record, '--object-format', algorithm,
      '--ref-hex', refHex, '--source-ref', 'refs/heads/main', '--target', p.f.commit,
      '--target-kind', 'commit', '--tagger', 'Release Author <release@example.invalid>', '--timestamp', '0', '--message-file', messageFile];
    const result = await command(args); assert.equal(result.code, 0, result.stderr);
    const saved = JSON.parse(await readFile(p.record)); assert.equal(saved.receipt.fields.message_hex, bytes.toString('hex'));
    assert.equal(saved.receipt.fields.ref_hex, refHex); assert.equal(saved.receipt.fields.timestamp, 0);
    const sent = writes(p.calls)[0], body = objectBody(sent.fields);
    assert.equal(sent.fields.message_hex, bytes.toString('hex'));
    assert.equal(objectId(body, algorithm), objectId(objectBody(saved.receipt.fields), algorithm));
    assert(!result.stdout.includes(token)); assert.equal(result.stderr, '');
  });
}

test('deletion compares the exact outer tag, never substitutes its peeled commit', async t => {
  const p = await peer(t), input = { ...p.base, operation: 'delete', objectFormat: 'sha1', refHex: existing, record: p.record };
  await assert.rejects(runTagOperation({ ...input, expectedObject: p.f.commit }), { code: 'tag_operator_object_moved' });
  assert.equal(writes(p.calls).length, 0); assert.equal(await exists(p.record), false);
  const result = await runTagOperation({ ...input, expectedObject: p.f.tag });
  assert.equal(result.result.outcome, 'committed'); assert.equal(writes(p.calls)[0].fields.expected_object, p.f.tag);
});

test('changed source tip, identity and insufficient selection budget fail before custody or mutation', async t => {
  const p = await peer(t);
  await assert.rejects(runTagOperation({ ...p.fresh, target: 'b'.repeat(40) }), { code: 'tag_operator_object_moved' });
  await assert.rejects(runTagOperation({ ...p.fresh, sourceRefHex: existing, target: p.f.tag, limit: 1, maxPages: 1 }), { code: 'tag_operator_reference_budget' });
  p.faults.page = page => { page.repository_id = '8'.repeat(32); };
  await assert.rejects(runTagOperation(p.fresh), { code: 'tag_operator_repository_mismatch' });
  assert.equal(await exists(p.record), false); assert.equal(writes(p.calls).length, 0);
});

test('native refusal remains terminal and is not replaced with an automatic retry', async t => {
  const p = await peer(t); p.f.config.refuse = true;
  const result = await runTagOperation(p.fresh); assert.equal(result.result.outcome, 'refused');
  const retry = await runTagOperation(p.recovery('retry'));
  assert.equal(retry.result.outcome, 'refused'); assert.equal(retry.mutation_submitted, false); assert.equal(writes(p.calls).length, 1);
});

test('lost acknowledgement recovers the original committed decision without re-reading or recreating a deleted tag', async t => {
  const p = await peer(t); p.faults.afterMutation = (_call, _req, res) => { res.destroy(); return true; };
  await assert.rejects(runTagOperation(p.fresh), error => error.operator_state === 'submitted_unknown');
  const first = writes(p.calls)[0]; p.f.refs.length = 0;
  const result = await command([...p.cli('retry'), '--record', p.record]);
  assert.equal(result.code, 0, result.stderr); assert.equal(JSON.parse(result.stdout).mutation_submitted, false);
  assert.equal(writes(p.calls).length, 1); assert.equal(p.calls.at(-1).headers['idempotency-key'], first.headers['idempotency-key']);
});

test('missing outcome is unresolved; explicit retry sends the identical saved body and key once', async t => {
  const p = await peer(t);
  p.faults.before = (call, _req, res) => {
    if (call.path === 'source/tags/lightweight') { res.destroy(); return true; }
    return false;
  };
  await assert.rejects(runTagOperation(p.fresh));
  const first = writes(p.calls)[0], bytes = await readFile(p.record);
  const status = await runTagOperation(p.recovery('status'));
  assert.equal(status.state, 'unresolved'); assert.equal(status.absence_proves_non_commit, false); assert.equal(writes(p.calls).length, 1);
  p.faults.before = null; p.f.refs.length = 0;
  const result = await runTagOperation(p.recovery('retry')); assert.equal(result.result.outcome, 'committed');
  const second = writes(p.calls)[1]; assert.equal(second.body, first.body);
  assert.equal(second.headers['idempotency-key'], first.headers['idempotency-key']);
  assert.deepEqual(await readFile(p.record), bytes); assert.equal(writes(p.calls).length, 2);
  assert.equal(p.calls.filter(call => call.path === 'source/refs').length, 1);
});

test('cancellation after custody retains a recoverable original request and retry rechecks custody before send', async t => {
  const p = await peer(t), stop = new AbortController();
  await assert.rejects(runTagOperation({ ...p.fresh, signal: stop.signal, onProgress: ({ phase }) => {
    if (phase === 'receipt_saved') stop.abort();
  } }), error => error.operator_state === 'recorded_unknown');
  assert.equal(writes(p.calls).length, 0); const original = await readFile(p.record);
  await assert.rejects(runTagOperation({ ...p.recovery('retry'), onProgress: ({ phase }) => {
    if (phase === 'recovery_observed') {
      // Invalidate this sender's own private-descriptor custody barrier after
      // outcome lookup, without replacing its original request bytes.
      chmodSync(p.record, 0o644);
    }
  } }), { code: 'operator_private_owner_required' });
  assert.equal(writes(p.calls).length, 0);
  assert.deepEqual(await readFile(p.record), original);
  await chmod(p.record, 0o600);
  const retry = await runTagOperation(p.recovery('retry')); assert.equal(retry.result.outcome, 'committed');
});

test('record family, semantic tampering and credential replacement cannot acquire a fresh request identity', async t => {
  const p = await peer(t), stop = new AbortController();
  await assert.rejects(runTagOperation({ ...p.fresh, signal: stop.signal, onProgress: ({ phase }) => { if (phase === 'receipt_saved') stop.abort(); } }));
  const original = await readFile(p.record), before = p.calls.length;
  const tampered = JSON.parse(original); tampered.schema = 'frankengit-issue-operator-v1';
  await writeFile(p.record, JSON.stringify(tampered) + '\n');
  await assert.rejects(runTagOperation(p.recovery('retry')), { code: 'tag_operator_record_mismatch' });
  tampered.schema = 'frankengit-tag-operator-v1'; tampered.receipt.fields.target = 'b'.repeat(40);
  await writeFile(p.record, JSON.stringify(tampered) + '\n'); await assert.rejects(runTagOperation(p.recovery('retry')));
  await writeFile(p.record, original); await writeFile(p.tokenFile, '8'.repeat(64));
  await assert.rejects(runTagOperation(p.recovery('retry'))); assert.equal(p.calls.length, before);
});

test('existing, nonprivate, linked and symlink custody/credentials fail before mutation', async t => {
  const p = await peer(t); await writeFile(p.record, 'do not overwrite', { mode: 0o600 });
  await assert.rejects(runTagOperation(p.fresh), { code: 'operator_record_exists' });
  assert.equal(await readFile(p.record, 'utf8'), 'do not overwrite');
  const fresh = { ...p.fresh, record: join(p.root, 'next.json') };
  await chmod(p.tokenFile, 0o644); await assert.rejects(runTagOperation(fresh), { code: 'operator_private_owner_required' });
  await chmod(p.tokenFile, 0o600);
  const symbolic = join(p.root, 'symbolic'); await symlink(p.tokenFile, symbolic);
  await assert.rejects(runTagOperation({ ...fresh, tokenFile: symbolic }));
  const hard = join(p.root, 'hard'); await link(p.tokenFile, hard);
  await assert.rejects(runTagOperation({ ...fresh, tokenFile: hard }), { code: 'operator_file_type_or_size' });
  assert.equal(p.calls.length, 0); assert.equal(await exists(fresh.record), false);
});

test('read inventory crosses byte-only intermediate refs, strips extensions and marks a bounded prefix', async t => {
  const p = await peer(t), raw = hex('refs/tags/raw') + 'ff';
  p.f.refs.splice(1, 0, { ref: null, ref_hex: raw, object_id: p.f.commit });
  p.faults.page = page => { page.rendered_html = '<script>not checked</script>'; for (const row of page.refs) row.secret_extension = token; };
  const prefix = await runTagOperation({ ...p.reading, limit: 1 });
  assert.equal(prefix.complete, false); assert.equal(prefix.restart_required, true); assert.deepEqual(prefix.pages[0].refs, []);
  const result = await runTagCommand([...p.cli('list'), '--object-format', 'sha1', '--limit', '1', '--max-pages', '3']);
  assert.equal(result.exitCode, 0); const report = JSON.parse(result.text);
  assert.equal(report.complete, true); assert.equal(report.pages[1].refs[0].ref, null); assert.equal(report.pages[1].refs[0].ref_hex, raw);
  assert(!result.text.includes('secret_extension')); assert(!result.text.includes('rendered_html')); assert(!result.text.includes(token));
  const continuation = p.calls.filter(call => call.path === 'source/refs').at(-1);
  assert.equal(continuation.fields.after, raw); assert.equal(continuation.fields.expected_head, head);
  assert.equal(continuation.headers['idempotency-key'], undefined); assert.equal(writes(p.calls).length, 0);
  const partial = await command([...p.cli('list'), '--object-format', 'sha1', '--limit', '1']);
  assert.equal(partial.code, 4, partial.stderr); assert.equal(JSON.parse(partial.stdout).complete, false);
});

test('reference-session cap returns an honest bounded inventory and prevents a selection beyond 2048 rows', async t => {
  const p = await peer(t);
  p.f.refs.length = 0;
  for (let i = 0; i < 2049; i++) {
    const name = `refs/tags/release-${String(i).padStart(4, '0')}`;
    p.f.refs.push({ ref: name, ref_hex: hex(name), object_id: p.f.commit });
  }
  const result = await runTagOperation({ ...p.reading, limit: 64, maxPages: 100 });
  assert.equal(result.complete, false); assert.equal(result.stop_reason, 'reference_budget');
  assert.equal(result.source_refs_scanned, 2048); assert.equal(result.page_count, 32);
  assert.equal(p.calls.length, 32); assert.equal(result.next_after_hex, p.f.refs[2047].ref_hex);
  await assert.rejects(runTagOperation({ ...p.fresh, sourceRefHex: p.f.refs[2048].ref_hex, limit: 64, maxPages: 100 }),
    { code: 'tag_operator_reference_budget' });
  assert.equal(writes(p.calls).length, 0); assert.equal(await exists(p.record), false);
});

test('show verifies original annotation bytes; complete inventory distinguishes absence from an exhausted budget', async t => {
  const p = await peer(t), input = { ...p.reading, operation: 'show', refHex: existing };
  p.f.config.inspect = reply => { reply.rendered_html = '<script>ignored</script>'; reply.annotations[0].private = token; };
  const result = await runTagOperation(input); assert.equal(result.found, true); assert.equal(result.inspection.peeled_object, p.f.commit);
  assert.equal(result.inspection.signature_verified, false); assert.equal(result.inspection.tagger_is_authenticated_principal, false);
  assert.equal(result.inspection.rendered_html, undefined); assert.equal(result.inspection.annotations[0].private, undefined);
  const inspect = p.calls.at(-1); assert.equal(inspect.fields.expected_object, p.f.tag); assert.equal(inspect.fields.expected_head, head);
  assert.equal((await runTagOperation({ ...input, refHex: destination })).found, false);
  await assert.rejects(runTagOperation({ ...input, limit: 1, maxPages: 1 }), { code: 'tag_operator_reference_budget' });
  p.f.config.inspect = reply => { reply.annotations[0].body_hex += 'ff'; reply.annotations[0].body_bytes++; };
  await assert.rejects(runTagOperation(input)); assert.equal(writes(p.calls).length, 0);
  p.f.config.inspect = reply => { reply.source_head = 'different-authority-head'; };
  await assert.rejects(runTagOperation(input), { code: 'tag_read_source_head_moved' });
});

for (const [name, change] of [
  ['moved head', page => { page.snapshot_token = `alg:1:${'8'.repeat(64)}`; }],
  ['changed source head', page => { page.source_head = 'different-authority-head'; }],
  ['nonprogress cursor', page => { page.next_after = page.after; }],
  ['changed encoding', page => { delete page.cursor_encoding; }],
  ['wrong object format', page => { page.object_format = 'sha256'; }],
]) test(`a later ${name} rejects the whole inventory rather than returning a successful prefix`, async t => {
  const p = await peer(t); p.faults.page = page => { if (page.after !== null) change(page); };
  await assert.rejects(runTagOperation({ ...p.reading, limit: 1, maxPages: 3 }), error => error.operator_state === 'read_incomplete');
  assert.equal(writes(p.calls).length, 0);
});

test('finite output, pre-cancellation and a stalled real response obey the invocation budget', async t => {
  const p = await peer(t);
  await assert.rejects(runTagOperation({ ...p.reading, maxOutputBytes: 1 }), { code: 'tag_read_output_limit' });
  const stop = new AbortController(); stop.abort(); const count = p.calls.length;
  await assert.rejects(runTagOperation({ ...p.reading, signal: stop.signal }), { code: 'tag_operator_cancelled_or_deadline' });
  assert.equal(p.calls.length, count);
  let stalled = false; p.faults.before = () => { stalled = true; return true; };
  await assert.rejects(runTagOperation({ ...p.reading, timeoutMs: 100 }));
  assert.equal(stalled, true); assert.equal(p.calls.length, count + 1);
});

test('empty annotation is preserved; NUL and oversized message files fail before publication', async t => {
  const p = await peer(t), messageFile = join(p.root, 'message');
  const args = [...p.cli('annotated'), '--record', p.record, '--object-format', 'sha1', '--ref', 'refs/tags/new',
    '--source-ref', 'refs/heads/main', '--target', p.f.commit, '--target-kind', 'commit',
    '--tagger', 'Author <a@b>', '--timestamp', '1', '--message-file', messageFile];
  await writeFile(messageFile, Buffer.from([0]), { mode: 0o600 }); await assert.rejects(runTagCommand(args));
  await writeFile(messageFile, Buffer.alloc(65537, 1)); await assert.rejects(runTagCommand(args));
  assert.equal(writes(p.calls).length, 0); assert.equal(await exists(p.record), false);
  await writeFile(messageFile, ''); assert.equal((await runTagCommand(args)).exitCode, 0);
  assert.equal(writes(p.calls)[0].fields.message_hex, '');
});

test('closed command grammar refuses force, ambiguous refs, recovery edits and overlong native writes', async t => {
  const p = await peer(t), args = [...p.cli('lightweight'), '--record', p.record, '--object-format', 'sha1',
    '--ref', 'refs/tags/new', '--source-ref', 'refs/heads/main', '--target', p.f.commit];
  assert.equal(tagArguments(args).options.refHex, destination);
  for (const extra of [['--force'], ['--target', p.f.commit], ['--ref-hex', destination], ['--after', source], ['--message-file', 'message']]) {
    assert.throws(() => tagArguments([...args, ...extra]));
  }
  assert.throws(() => tagArguments([...p.cli('status'), '--record', p.record, '--target', p.f.commit]));
  assert.throws(() => tagOperatorOptions({ ...p.fresh, refHex: hex('refs/tags/' + 'x'.repeat(1025)) }), { code: 'tag_operator_reference_limit' });
  assert.throws(() => tagOperatorOptions({ ...p.fresh, operation: 'annotated', targetKind: 'commit', tagger: 'A <a@b>', timestamp: 9007199254740992, messageHex: '' }));
  assert.equal(p.calls.length, 0);
});
