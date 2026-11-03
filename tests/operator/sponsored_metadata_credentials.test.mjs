// Production operators and real HTTP/processes; schema peers are not Rust fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { issueTokenFingerprint } from '../../scripts/operator/remote_issue.mjs';
import { readIssueToken, loadIssueIntent } from '../../scripts/operator/issue_files.mjs';
import { pullTokenFingerprint, preparePull } from '../../scripts/operator/pull_command.mjs';
import { readPullToken, loadPullIntent } from '../../scripts/operator/pull_files.mjs';
import { validateOutcomeReply, parseOutcomeJson } from '../../scripts/operator/transaction_outcome.mjs';
import { runNativeProcess } from '../../scripts/lib/native-process-owner.mjs';
import { listenForFetch } from './fetch_listener_helper.mjs';
import { input as pullInput, publication as pullPublication, outcome as pullOutcome } from './remote_pull_fixture.mjs';

const scope = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
  repository_incarnation: '3'.repeat(32), principal_id: '4'.repeat(32) };
const legacy = 'a'.repeat(64), agent = 'fgagent_' + legacy;
const sha = value => createHash('sha256').update(value).digest('hex');
const sequence = '18446744073709551615';
const clone = value => structuredClone(value);
function receipt(state = 'committed') {
  const terminal = ['committed', 'refused'].includes(state), present = !['key_not_observed', 'seal_not_observed'].includes(state);
  return { type: 'transaction_outcome', schema_version: 1, ...scope, selector: 'transaction', command_index: null,
    state, terminal, transaction: present ? { tx_id: 'native-transaction', seal_id: 'native-seal',
      request_schema: 'native-pr-schema-v1', canonical_request_digest: { algorithm: 1, hex: 'c'.repeat(64) } } : null,
    decision: !terminal ? null : { kind: state, decision_sequence: sequence,
      ...(state === 'committed' ? { repository_commit_id: 'native-rcr' }
        : { code: 'PolicyDenied', code_point: 17, refusal_record_id: 'native-refusal' }) },
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}
function provenance(authentication = 'agent_credential', token = agent) {
  return { state: authentication === null ? 'legacy_unknown' : 'recorded', principal_id: scope.principal_id,
    authentication, agent_provenance: authentication !== 'agent_credential' ? null : {
      agent: scope.principal_id, sponsor: '5'.repeat(32), sponsor_kind: 'human', credential_id: sha(token),
      grant_root: { algorithm: 2, hex: '6'.repeat(64) }, run_commitment: '7'.repeat(64),
      authenticated_at: '1000', expires_at: '1300',
    } };
}
const annotated = (value = receipt(), p = provenance(), error = null) => ({ ...value, principal_provenance: p, provenance_error: error });
const wire = value => JSON.stringify(value, (key, v) =>
  ['number', 'expected_version', 'decision_sequence', 'authenticated_at', 'expires_at'].includes(key)
    && typeof v === 'string' && /^(0|[1-9][0-9]*)$/.test(v) ? JSON.rawJSON(v) : v);
async function directory(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-sponsored-operator-'));
  t.after(() => rm(root, { recursive: true, force: true })); return root;
}
const issueInput = endpoint => ({ endpoint, scope, number: '7', expected_version: '0', action: 'open',
  fields: { title: 'Sponsored native metadata', body: 'Exact private body 雪', labels: [] } });

test('both metadata fingerprints hash every exact credential byte and retain legacy digests', () => {
  for (const fingerprint of [issueTokenFingerprint, pullTokenFingerprint]) {
    assert.equal(fingerprint(legacy), sha(legacy)); assert.equal(fingerprint(agent), sha(agent));
    assert.notEqual(fingerprint(agent), fingerprint(legacy));
  }
});
for (const [name, reader] of [['issue', readIssueToken], ['pull', readPullToken]]) {
  test(`${name} private token reader accepts both closed forms and one optional LF`, async t => {
    const root = await directory(t), file = join(root, 'token');
    for (const value of [legacy, agent]) for (const suffix of ['', '\n']) {
      await writeFile(file, value + suffix, { mode: 0o600 }); assert.equal(await reader(file), value);
    }
    for (const value of [agent + '\n\n', agent + '\r\n', agent + ' ', 'FGAGENT_' + legacy,
      'fgagent_' + 'A'.repeat(64), 'fgagent_' + 'a'.repeat(63), agent + 'a', 'fgagent_' + '雪'.repeat(32)]) {
      await writeFile(file, value); await assert.rejects(reader(file));
    }
  });
}
test('malformed bearer encodings still refuse before fingerprinting', () => {
  for (const value of ['', 'a'.repeat(63), 'a'.repeat(65), 'fgagent_' + 'a'.repeat(63), agent + 'a',
    'FGAGENT_' + legacy, 'fgagent_' + 'A'.repeat(64), agent + '\n', agent + '\0', null, {}]) {
    for (const fingerprint of [issueTokenFingerprint, pullTokenFingerprint]) assert.throws(() => fingerprint(value));
  }
});
for (const [name, value] of [
  ['ordinary HTTP', annotated(receipt(), provenance('http_token'))],
  ['SSH', annotated(receipt(), provenance('ssh_deploy_key'))],
  ['operator assertion', annotated(receipt(), provenance('operator_assertion'))],
  ['legacy unknown', annotated(receipt(), provenance(null))],
  ['agent', annotated()],
  ['nonterminal', annotated(receipt('undecided'), { state: 'not_terminal' })],
  ['unavailable', annotated(receipt(), { state: 'unavailable' }, 'original_principal_evidence_unavailable')],
  ['response limit', annotated(receipt(), { state: 'unavailable' }, 'response_limit')],
]) test(`native ${name} outcome provenance survives normalization`, () => {
  assert.deepEqual(validateOutcomeReply(parseOutcomeJson(Buffer.from(wire(value))), scope), value);
});
test('agent provenance retains every u64 time bit and never rounds a witness', () => {
  const value = annotated(); value.principal_provenance.agent_provenance.authenticated_at = '18446744073709551315';
  value.principal_provenance.agent_provenance.expires_at = '18446744073709551615';
  assert.deepEqual(validateOutcomeReply(parseOutcomeJson(Buffer.from(wire(value))), scope), value);
});
test('legacy retained outcomes gain provenance without changing original decisions', () => {
  const old = receipt(), current = annotated();
  assert.deepEqual(validateOutcomeReply(current, scope, old), current);
  assert.deepEqual(old, receipt(), 'the caller-owned original must remain untouched');
});
test('optional provenance unavailability cannot erase an established terminal decision', () => {
  const known = annotated(), current = annotated(receipt(), { state: 'unavailable' }, 'response_limit');
  assert.deepEqual(validateOutcomeReply(current, scope, known), current);
  assert.deepEqual(known, annotated());
});
test('malformed, mismatched and substituted original principal evidence refuses', () => {
  const good = annotated(); assert.deepEqual(validateOutcomeReply(good, scope), good);
  for (const mutate of [
    r => { delete r.provenance_error; }, r => { r.extra = true; },
    r => { r.principal_provenance.extra = true; }, r => { r.provenance_error = 'unexpected'; },
    r => { r.principal_provenance.principal_id = '8'.repeat(32); },
    r => { r.principal_provenance.authentication = 'invented'; },
    r => { r.principal_provenance.agent_provenance = null; },
    r => { r.principal_provenance.agent_provenance.agent = '8'.repeat(32); },
    r => { r.principal_provenance.agent_provenance.sponsor = scope.principal_id; },
    r => { r.principal_provenance.agent_provenance.sponsor_kind = 'agent'; },
    r => { r.principal_provenance.agent_provenance.credential_id = '0'.repeat(64); },
    r => { r.principal_provenance.agent_provenance.run_commitment = '0'.repeat(64); },
    r => { r.principal_provenance.agent_provenance.grant_root.hex = '0'.repeat(64); },
    r => { r.principal_provenance.agent_provenance.authenticated_at = '0'; },
    r => { r.principal_provenance.agent_provenance.expires_at = '999'; },
    r => { r.principal_provenance.agent_provenance.expires_at = '18446744073709551616'; },
  ]) { const bad = clone(good); mutate(bad); assert.throws(() => validateOutcomeReply(bad, scope)); }
  for (const field of ['sponsor', 'credential_id', 'run_commitment']) {
    const changed = clone(good); changed.principal_provenance.agent_provenance[field] = '8'.repeat(field === 'sponsor' ? 32 : 64);
    assert.throws(() => validateOutcomeReply(changed, scope, good), /provenance/);
  }
});
test('agent credentials cannot prepare a code-publication operation', () => {
  assert.throws(() => preparePull(pullInput('http://127.0.0.1:12345/repo.git', 'fast-forward'), agent),
    /agent_metadata_operation_unsupported/);
});
for (const family of ['issue', 'pull']) for (const credential of ['legacy', 'agent']) {
  test(`${family} CLI ${credential}: send exact bytes, rotate only for original-key recovery`, async t => {
    const root = await directory(t), token = credential === 'agent' ? agent : legacy;
    const rotated = (credential === 'agent' ? 'fgagent_' : '') + 'b'.repeat(64);
    const requests = []; let intent, committed = false;
    const p = provenance(credential === 'agent' ? 'agent_credential' : 'http_token', token);
    const server = createServer(async (req, res) => {
      const parts = []; for await (const part of req) parts.push(part);
      const row = { path: req.url, method: req.method, key: req.headers['idempotency-key'],
        authorization: req.headers.authorization, body: Buffer.concat(parts).toString('utf8') }; requests.push(row);
      assert.equal(req.method, 'POST'); assert.equal(row.key, intent.key);
      let value;
      if (req.url.endsWith('/outcomes')) {
        assert.equal(row.body, ''); const raw = family === 'pull' ? pullOutcome(intent, committed ? 'committed' : 'key_not_observed') : receipt(committed ? 'committed' : 'key_not_observed');
        value = annotated(raw, committed ? p : { state: 'not_terminal' });
      } else {
        assert.equal(row.authorization, 'Bearer ' + token); assert.equal(row.body, intent.body); committed = true;
        value = family === 'pull' ? pullPublication(intent) : { type: 'issue_publication', schema_version: 1,
          tenant_id: scope.tenant_id, repository_id: scope.repository_id, principal_id: scope.principal_id,
          number: intent.number, expected_version: intent.expected_version, action: intent.action,
          tx_id: 'native-transaction', outcome: 'committed', decision_sequence: sequence, repository_commit_id: 'native-rcr',
          refusal_record_id: null, refusal_code: null, delivery_acknowledged: null };
      }
      const bytes = Buffer.from(wire(value)); res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': bytes.length }); res.end(bytes);
    });
    const port = await listenForFetch(server);
    t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
    const endpoint = `http://127.0.0.1:${port}/repo.git`, input = join(root, 'input'), file = join(root, 'token');
    const rotation = join(root, 'rotated'), slot = join(root, 'slot'), record = join(root, 'record'), recovered = join(root, 'recovered');
    for (const [path, bytes] of [[input, JSON.stringify(family === 'pull' ? pullInput(endpoint) : issueInput(endpoint))],
      [file, token + '\n'], [rotation, rotated]]) await writeFile(path, bytes, { mode: 0o600 });
    const cli = fileURLToPath(new URL(`../../scripts/remote_${family}.mjs`, import.meta.url));
    const run = args => runNativeProcess(process.execPath, [cli, ...args], { timeoutMs: 10000,
      stdoutLimit: 1024 * 1024, stderrLimit: 1024 * 1024, signal: t.signal });
    const prepared = await run(['prepare', '--input', input, '--token-file', file, '--request-dir', slot]);
    assert.equal(prepared.code, 0, prepared.stderr.toString()); assert.equal(requests.length, 0);
    intent = await (family === 'pull' ? loadPullIntent(slot) : loadIssueIntent(slot));
    const original = await readFile(join(slot, 'intent.json'));
    const sent = await run(['send', '--request-dir', slot, '--token-file', file, '--confirm-key', intent.key, '--record', record]);
    assert.equal(sent.code, 0, sent.stderr.toString());
    const observed = JSON.parse(await readFile(record, 'utf8')); assert.equal(observed.outcome.state, 'committed');
    assert.deepEqual(observed.outcome.principal_provenance, p);
    const denied = await run(['send', '--request-dir', slot, '--token-file', rotation, '--confirm-key', intent.key,
      '--record', join(root, 'must-not-send')]); assert.notEqual(denied.code, 0);
    const result = await run(['recover', '--request-dir', slot, '--token-file', rotation, '--record', recovered]);
    assert.equal(result.code, 0, result.stderr.toString());
    assert.deepEqual(JSON.parse(await readFile(recovered, 'utf8')).outcome.principal_provenance, p);
    assert.equal(requests.at(-1).authorization, 'Bearer ' + rotated);
    assert.equal(requests.filter(r => !r.path.endsWith('/outcomes')).length, 1);
    assert.deepEqual(await readFile(join(slot, 'intent.json')), original);
  });
}
