// Actual verifier and view, WebCrypto, explicit full-file host callback and fake
// DOM. This does not claim browser navigation, live Transport or native authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { verifyContextFiles, mountContextVerification, contextVerificationSummary } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-verify.mjs';
import { fixture, check, copy, hex } from './search-context-fixtures.mjs';
class Element {
  children = []; handlers = new Map(); textContent = ''; disabled = false; checked = false; value = '';
  constructor(tag) { this.tag = tag; }
  append(...nodes) { for (const node of nodes) { this.children.push(node); node.parent = this; } }
  setAttribute(name, value) { this[name] = value; }
  addEventListener(name, fn) { const list = this.handlers.get(name) ?? []; list.push(fn); this.handlers.set(name, list); }
  async fire(name) { for (const fn of this.handlers.get(name) ?? []) await fn({ preventDefault() {} }); }
  click() { return this.fire('click'); }
  remove() { this.parent.children = this.parent.children.filter(node => node !== this); }
  find(id) { if (this.id === id) return this; for (const child of this.children) { const found = child.find(id); if (found) return found; } }
  text() { return this.textContent + this.children.map(node => node.text()).join('\n'); }
}
function make() {
  const f = fixture(); f.retrieval.query.maxFileBytes = 8 * 1024 * 1024;
  Object.assign(f.retrieval.symbols.result.hits[0], { line: 1, column: 12, excerptOffset: 0, excerptHex: hex(f.bytes.subarray(0, -1)) });
  const result = { ...f.retrieval, context: check(f) }, calls = [], downloads = [], revoked = [];
  const host = { current: true, verify: async limits => {
    calls.push(limits); return verifyContextFiles(result, async (file, charge) => { charge(); return { bytes: f.bytes, kind: 'file' }; }, webcrypto, () => {}, limits);
  } };
  const doc = { createElement: tag => new Element(tag) };
  const panel = mountContextVerification(doc, result, {
    verify: limits => host.verify(limits), current: () => host.current,
    display: bytes => Buffer.from(bytes).toString('hex'),
    urlApi: { createObjectURL: blob => { downloads.push(blob); return `blob:local-${downloads.length}`; }, revokeObjectURL: value => revoked.push(value) },
  });
  const get = id => panel.element.find(id);
  const consent = async () => { get('verify-context-consent').checked = true; await get('verify-context-consent').fire('change'); };
  return { f, result, host, panel, get, consent, calls, downloads, revoked };
}
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
test('rendering and export attempts cannot trigger source reads without consent', async () => {
  const s = make(); assert.equal(s.panel.submit.disabled, true); assert.equal(s.panel.download.disabled, true);
  await s.panel.submit.click(); await s.panel.download.click(); assert.equal(s.calls.length, 0); assert.equal(s.downloads.length, 0);
  assert.match(s.panel.element.text(), /18 source bytes, 1 page requests/);
});
test('explicit verification uses exact displayed limits and exports a token-free local summary', async () => {
  const s = make(); s.result.accessToken = 'private-credential-not-exportable'; await s.consent(); await s.panel.submit.click();
  assert.deepEqual(s.calls, [{ maxSourceBytes: 18, maxRequests: 1 }]);
  assert.equal(s.get('verify-context-consent').checked, false); assert.equal(s.panel.submit.disabled, true); assert.equal(s.panel.download.disabled, false);
  assert.match(s.panel.element.text(), /Every selected context file and excerpt passed/);
  await s.panel.download.click(); const report = JSON.parse(await s.downloads[0].text());
  assert.equal(report.localObservationOnly, true); assert.equal(report.independentlyReplayableProof, false);
  assert.equal(report.repositoryMembershipVerified, false); assert.equal(report.searchCoverageVerified, false); assert.equal(report.files.length, 1);
  assert.equal(JSON.stringify(report).includes('authorization'), false); assert.equal(JSON.stringify(report).includes('private-credential-not-exportable'), false);
  assert.deepEqual(report.generationVector, s.result.vector, 'generation tokens are retained identities, not credentials');
});
test('budget edits invalidate consent, not the exact completed observation', async () => {
  const s = make(); await s.consent(); s.get('verify-context-bytes').value = '17'; await s.get('verify-context-bytes').fire('input');
  assert.equal(s.get('verify-context-consent').checked, false); await s.panel.submit.click(); assert.equal(s.calls.length, 0);
  await s.consent(); await s.panel.submit.click(); assert.equal(s.calls.length, 0); assert.equal(s.panel.download.disabled, true);
  assert.match(s.panel.element.text(), /verification failed/);
});
for (const value of ['1e6', '-1', '0', '1.5', ' 18', '018', '99999999999999']) test(`invalid budget ${value} cannot invoke the host`, async () => {
  const s = make(); s.get('verify-context-bytes').value = value; await s.consent(); await s.panel.submit.click();
  assert.equal(s.calls.length, 0); assert.equal(s.panel.download.disabled, true);
});
test('verification failure clears an earlier success and download URL', async () => {
  const s = make(); await s.consent(); await s.panel.submit.click(); await s.panel.download.click();
  s.host.verify = async () => { throw Error('remote untrusted prose <script>'); };
  await s.consent(); await s.panel.submit.click(); assert.equal(s.panel.download.disabled, true);
  assert.deepEqual(s.revoked, ['blob:local-1']); assert.equal(s.get('verify-context-result').textContent, '');
  assert.equal(s.panel.element.text().includes('<script>'), false);
});
test('an in-flight operation blocks duplicate clicks and exports', async () => {
  const s = make(), held = deferred(), original = s.host.verify; let invoked = 0;
  s.host.verify = async limits => { invoked++; await held.promise; return original(limits); };
  await s.consent(); const pending = s.panel.submit.click(); assert.equal(s.panel.download.disabled, true);
  await s.panel.submit.click(); await s.panel.download.click(); assert.equal(invoked, 1);
  held.resolve(); await pending; assert.equal(s.panel.download.disabled, false);
});
for (const stop of ['dispose', 'invalidate', 'current']) test(`${stop} during verification fences late success`, async () => {
  const s = make(), held = deferred(), original = s.host.verify;
  s.host.verify = async limits => { await held.promise; return original(limits); };
  await s.consent(); const pending = s.panel.submit.click();
  if (stop === 'current') s.host.current = false; else s.panel[stop]();
  held.resolve(); await pending; assert.equal(s.panel.download.disabled, true);
  assert.equal(s.get('verify-context-result').textContent, ''); await s.panel.download.click(); assert.equal(s.downloads.length, 0);
});
test('a later generation cannot inherit an older pending verification result', async () => {
  const s = make(), held = deferred(), original = s.host.verify;
  s.host.verify = async limits => { await held.promise; return original(limits); };
  await s.consent(); const previous = s.panel.submit.click(); s.panel.invalidate();
  s.host.verify = original; await s.consent(); await s.panel.submit.click(); const before = s.get('verify-context-result').textContent;
  held.resolve(); await previous; assert.equal(s.get('verify-context-result').textContent, before); assert.equal(s.panel.download.disabled, false);
});
test('repeat export revokes the previous URL and disposal revokes the last URL', async () => {
  const s = make(); await s.consent(); await s.panel.submit.click(); await s.panel.download.click(); await s.panel.download.click();
  assert.deepEqual(s.revoked, ['blob:local-1']); s.panel.dispose(); assert.deepEqual(s.revoked, ['blob:local-1', 'blob:local-2']);
  assert.equal(s.panel.submit.disabled, true); assert.equal(s.panel.download.disabled, true);
});
for (const name of ['scope', 'pin', 'generationVector', 'files', 'sourceBytesRead', 'repositoryMembershipVerified']) test(`changed summary ${name} is refused`, async () => {
  const s = make(); const receipt = await s.host.verify({ maxSourceBytes: 18, maxRequests: 1 });
  if (name === 'files') receipt.files = [];
  else if (name === 'repositoryMembershipVerified') receipt[name] = true;
  else if (name === 'sourceBytesRead') receipt[name]++;
  else receipt[name] = { changed: true };
  assert.throws(() => contextVerificationSummary(s.result, receipt), /verification/);
});
test('summary output never copies unknown receipt fields', async () => {
  const s = make(), receipt = await s.host.verify({ maxSourceBytes: 18, maxRequests: 1 });
  receipt.accessToken = 'secret'; receipt.files[0].accessToken = 'secret';
  const summary = contextVerificationSummary(s.result, receipt); assert.equal(JSON.stringify(summary).includes('secret'), false);
});
test('no hydrated files cannot produce a misleading verification click', async () => {
  const s = make(); s.result.context.files = []; await s.consent(); await s.panel.submit.click(); assert.equal(s.calls.length, 0);
});
