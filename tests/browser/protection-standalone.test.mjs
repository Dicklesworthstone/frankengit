// View unit tests with an explicit native-client peer, not native-server or
// real-browser evidence. The production entrypoint loads the shared client.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mountProtection, protectionClientHref, referenceLabel, editorPolicy } from '../../crates/fgit-node/src/smart_http/server/browser/protection-view.mjs';
const browser = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
const html = readFileSync(new URL('protection.html', browser), 'utf8');
const script = readFileSync(new URL('protection-view.mjs', browser), 'utf8');
import { harness, deferred, snapshot, actor, reviewer, token, hex } from './protection-standalone-fixture.mjs';
import { refPolicy } from './protection-fixtures.mjs';

for (const profile of ['reference_facts_v1', 'reference_actor_id_v1', 'reference_authentication_v1']) {
test(`${profile}: standalone editor preserves an observed policy unless clear-all is explicit`, async () => {
  const compiled = refPolicy(profile);
  const calls = [];
  const h = harness({
    async load() { this.observed = { ...snapshot(), policy: { administrators: [actor], branches: [], ref_policy: compiled } }; return this.observed; },
    async stage(replacement, clear) { calls.push({ replacement, clear }); },
  });
  await h.connect();
  assert.match(h.get('policy').textContent, /Repository protection enabled/);
  assert.ok(h.get('policy').textContent.includes(compiled.snapshot_id));
  h.get('administrators').value = reviewer; await h.get('edit').fire('submit');
  assert.deepEqual(calls[0], { replacement: { administrators: [reviewer], branches: [], ref_policy: compiled }, clear: false });
  h.get('clear').checked = true; await h.get('edit').fire('submit');
  assert.deepEqual(calls[1], { replacement: { administrators: [reviewer], branches: [] }, clear: true });
});
}

test('standalone page binds the existing client to exactly the same repository API root', () => {
  for (const origin of ['https://forge.example', 'http://127.0.0.1:8123', 'http://localhost:8123', 'http://[::1]:8123']) {
    assert.equal(protectionClientHref(`${origin}/tenant/repo.git/ui/protection/`), `${origin}/tenant/repo.git/ui/pulls/`);
  }
});
for (const href of ['https://forge.example/ui/protection/', 'https://forge.example/repo.git/ui/pulls/',
  'https://forge.example/repo.git/ui/protection', 'https://forge.example/repo.git/ui/protection/?token=secret',
  'https://forge.example/repo.git/ui/protection/#secret', 'https://user:secret@forge.example/repo.git/ui/protection/',
  'http://forge.example/repo.git/ui/protection/', 'file:///repo.git/ui/protection/',
  'https://forge.example/repo%2fgit/ui/protection/', 'https://forge.example//repo.git/ui/protection/']) {
  test(`standalone scope refuses ${href}`, () => assert.throws(() => protectionClientHref(href)));
}
test('inspection preserves complete full-width counters and all native identities', async () => {
  const h = harness(); assert.equal(h.get('reload').disabled, true); await h.connect();
  assert.deepEqual(h.calls, [['connect', token, actor], ['load']]);
  assert.equal(h.get('token').value, ''); assert.equal(h.get('reload').disabled, false);
  for (const exact of [snapshot().head, snapshot().version, snapshot().epoch, snapshot().scope.repository]) assert.ok(h.get('snapshot').textContent.includes(exact));
  assert.ok(h.get('policy').textContent.includes(reviewer));
  assert.match(h.get('status').textContent, /No transaction/);
});
test('uninstalled policy is inspectable but cannot bootstrap through this page', async () => {
  const h = harness({ async load() { return { ...snapshot(), version: '0', epoch: '1', policy: null }; } });
  await h.connect(); assert.match(h.get('policy').textContent, /local-only/);
});
test('disabled protection retains policy administrators rather than pretending uninstalled', async () => {
  const h = harness({ async load() { const s = snapshot(); s.policy.branches = []; return s; } });
  await h.connect(); assert.match(h.get('policy').textContent, /administrators retained/);
  assert.ok(h.get('policy').textContent.includes(actor));
});
test('byte-only and hostile-looking references remain inert with exact bytes available', async () => {
  const encoded = hex('refs/heads/<script>\u202e') + 'ff';
  const h = harness({ async load() { const s = snapshot(); s.policy.branches[0].reference_hex = encoded; return s; } });
  await h.connect(); assert.ok(h.get('policy').textContent.includes(encoded));
  assert.match(h.get('policy').textContent, /Non-UTF-8/);
  assert.equal(referenceLabel(hex('refs/heads/<script>\u202e')), 'refs/heads/<script>\\u{202e}');
});
test('inspection failures clear old policy and never invent a new snapshot', async () => {
  const h = harness(); await h.connect();
  h.client.load = async () => { throw new Error('Native protection scope refused.'); };
  await h.mounted.inspect(); assert.equal(h.get('snapshot').textContent, '');
  assert.equal(h.get('policy').textContent, ''); assert.match(h.get('status').textContent, /refused/);
});
test('credential failure does not perform a policy read and clears token input', async () => {
  const h = harness({ async connect() { throw new Error('Credential rejected.'); } });
  await h.connect(); assert.equal(h.get('token').value, ''); assert.deepEqual(h.calls, []);
  assert.match(h.get('status').textContent, /rejected/);
});
test('disconnect fences late success and erases displayed repository information', async () => {
  const pending = deferred(), h = harness({ async load() { return pending.promise; } });
  const work = h.connect(); await new Promise(resolve => setImmediate(resolve)); h.mounted.disconnect(); pending.resolve(snapshot()); await work;
  assert.equal(h.get('snapshot').textContent, ''); assert.equal(h.get('policy').textContent, '');
  assert.equal(h.get('actor').value, ''); assert.match(h.get('status').textContent, /^Disconnected/);
});
test('pagehide fences late failure without displaying its stale response', async () => {
  const pending = deferred(), h = harness({ async load() { return pending.promise; } });
  const work = h.connect(); await new Promise(resolve => setImmediate(resolve)); await h.events.fire('pagehide'); pending.reject(new Error('stale secret')); await work;
  assert.equal(h.get('snapshot').textContent, ''); assert.doesNotMatch(h.get('status').textContent, /stale secret/);
});
test('repeated inspection while busy does not start concurrent native reads', async () => {
  const pending = deferred(); let reads = 0;
  const h = harness({ async load() { reads++; return pending.promise; } });
  const work = h.connect(); await new Promise(resolve => setImmediate(resolve)); await h.mounted.inspect(); assert.equal(reads, 1);
  pending.resolve(snapshot()); await work; assert.equal(h.get('reload').disabled, false);
});
test('markup and native route include every independent asset without broadening PR/source permissions', () => {
  const route = readFileSync(new URL('protection.rs', browser), 'utf8');
  const router = readFileSync(new URL('../browser.rs', browser), 'utf8');
  assert.match(route, /profile\.config\.http_protection_admin_enabled\(\)/);
  assert.doesNotMatch(route, /profile\.allow_(?:source|pull_requests|issues)/);
  for (const asset of ['protection-view.mjs', 'pulls-actions.mjs', 'pulls-core.mjs', 'pulls-candidate.mjs', 'browser.css']) assert.ok(route.includes(`/ui/protection/${asset}`));
  assert.ok(router.includes('protection::serve(profile, request, trailing, writer)?'));
  assert.match(script, /await import\('\.\/pulls-actions\.mjs'\)/);
  assert.doesNotMatch(script, /mountPullRequests|innerHTML|localStorage|sessionStorage|document\.write/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /type="password"/);
});


test('reviewer editor preserves exact workflow selectors and check-only rows', () => {
  const reference = hex('refs/heads/main');
  const required_checks = [{
    source_ref_hex: hex('refs/heads/workflows'), publisher: reviewer, graph_root: '7'.repeat(64), job: 'build: α',
  }];
  const branches = [{ reference_hex: reference, required_reviewers: [], required_checks }];
  assert.deepEqual(editorPolicy(actor, `${reference} -`, branches), { administrators: [actor], branches });
  const edited = editorPolicy(actor, `${reference} ${reviewer}`, branches);
  assert.deepEqual(edited.branches[0].required_checks, required_checks);
  assert.deepEqual(edited.branches[0].required_reviewers, [reviewer]);
  assert.throws(() => editorPolicy(actor, `${hex('refs/heads/new')} -`, branches), /configured checks/);
  assert.deepEqual(editorPolicy(actor, '', branches), { administrators: [actor], branches: [] });
});

test('standalone editor displays N-of-M and preserves quorum while eligible reviewers change', async () => {
  const reference = hex('refs/heads/main');
  const members = [reviewer, 'c'.repeat(32), 'd'.repeat(32)];
  const branches = [{ reference_hex: reference, required_reviewers: members, required_approvals: 2 }];
  const h = harness({ async load() { const s = snapshot(); s.policy.branches = branches; return s; } });
  await h.connect();
  assert.match(h.get('policy').textContent, /2 of 3 listed reviewers/);
  assert.equal(h.get('rules').value, `${reference} ${members.join(',')} 2`);
  const edited = editorPolicy(actor, `${reference} ${[...members, 'e'.repeat(32)].join(',')}`, branches);
  assert.equal(edited.branches[0].required_approvals, 2);
  assert.equal(edited.branches[0].required_reviewers.length, 4);
  const all = editorPolicy(actor, `${reference} ${members.join(',')} all`, branches);
  assert.equal(Object.hasOwn(all.branches[0], 'required_approvals'), false);
  const one = editorPolicy(actor, `${reference} ${members.join(',')} 1`, branches);
  assert.equal(one.branches[0].required_approvals, 1);
  for (const count of ['0', '4', '01', '-1', '+1', '1.0', '1e0', '33']) {
    assert.throws(() => editorPolicy(actor, `${reference} ${members.join(',')} ${count}`, branches));
  }
  assert.throws(() => editorPolicy(actor, `${reference} ${reviewer}`, branches), /Approval count/);
});


test('explicit workflow drafts enforce canonical selector bounds without truncation or ignored fields', () => {
  const reference = hex('refs/heads/main'), rule = `${reference} ${reviewer}`;
  const row = { reference_hex: reference, source_ref_hex: hex('refs/heads/ci'), publisher: reviewer, graph_root: '7'.repeat(64), job: 'build' };
  const parsed = rows => editorPolicy(actor, rule, [], null, rows);
  assert.throws(() => parsed(Array.from({ length: 33 }, (_, index) => ({ ...row, job: `job-${index}` }))), /32 required workflow checks/);
  assert.throws(() => parsed(Array.from({ length: 2049 }, () => row)), /Too many/);
  for (const malformed of [null, { ...row, ignored: 'field' }, { source_ref_hex: row.source_ref_hex }, 'selector']) {
    assert.throws(() => parsed([malformed]), /Each required check/);
  }
  const exact = parsed([{ ...row, job: '  β: build  ' }, { ...row, job: '  α: build  ' }]);
  assert.deepEqual(exact.branches[0].required_checks.map(check => check.job), ['  α: build  ', '  β: build  ']);
  assert.deepEqual(parsed([]), { administrators: [actor], branches: [{ reference_hex: reference, required_reviewers: [reviewer] }] });
});
