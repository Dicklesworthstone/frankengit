// Run from the repository root:
// node --experimental-vm-modules --test scripts/tests/source_edit_binary.test.mjs
//
// Execute the actual browser controller AND full-file patch encoder. The DOM,
// network client and unrelated recovery module are explicit unit-test doubles;
// these tests do not claim live browser, transport or native admission coverage.
// Ported onto the concurrent hex-editor implementation; retain its existing
// controls and upload semantics rather than replacing them with the older patch.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

if (typeof vm.SourceTextModule !== 'function') {
  throw new Error('Run with node --experimental-vm-modules --test scripts/tests/source_edit_binary.test.mjs');
}
const directory = process.env.FG_SOURCE_BROWSER_DIR
  ? resolve(process.env.FG_SOURCE_BROWSER_DIR)
  : fileURLToPath(new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url));
const utf8 = new TextEncoder();
const hex = bytes => Buffer.from(bytes).toString('hex');
const fail = message => { throw new Error(message); };
// The controller's shared primitive boundary is deliberately small. Keep these
// refusals aligned with pulls-core.mjs; authority and network work is not faked.
const core = {
  utf8, hex, fail,
  keys(value, allowed) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Invalid API record.');
    if (Object.keys(value).some(key => !allowed.includes(key))) fail('Unknown or inapplicable field.');
  },
  unhex(value, maximum = 8 * 1024 * 1024) {
    if (typeof value !== 'string' || value.length > maximum * 2 || value.length % 2 || !/^[0-9a-f]*$/.test(value)) fail('Invalid hex bytes.');
    return Uint8Array.from(Buffer.from(value, 'hex'));
  },
  decimal(value, name, minimum = 0) {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) fail(`Invalid ${name}.`);
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < minimum) fail(`Invalid ${name}.`);
    return parsed;
  },
  text(value, maximum, name, single = false) {
    if (typeof value !== 'string' || value.length > maximum || utf8.encode(value).length > maximum ||
        /[\uD800-\uDFFF]/u.test(value) || value.includes('\0') ||
        (single && (!value.trim() || /[\u0000-\u001f\u007f-\u009f]/u.test(value)))) fail(`Invalid or oversized ${name}.`);
    return value;
  },
};
function synthetic(exports, identifier) {
  return new vm.SyntheticModule(Object.keys(exports), function () {
    for (const [name, value] of Object.entries(exports)) this.setExport(name, value);
  }, { identifier });
}
const patch = new vm.SourceTextModule(await readFile(resolve(directory, 'source-edit-patch.mjs'), 'utf8'), { identifier: 'source-edit-patch.mjs' });
const view = new vm.SourceTextModule(await readFile(resolve(directory, 'source-edit-view.mjs'), 'utf8'), { identifier: 'source-edit-view.mjs' });
const modules = {
  './pulls-core.mjs': synthetic(core, 'core-boundary'),
  './source-edit.mjs': synthetic({ SourceEditClient: class {
    constructor() { throw new Error('This test must inject its explicit client double.'); }
  } }, 'client-boundary'),
  './pulls-actions.mjs': synthetic({ RECEIPT_LIMIT: 32 * 1024 * 1024 }, 'recovery-boundary'),
  './source-edit-patch.mjs': patch,
};
await view.link(specifier => {
  const module = modules[specifier];
  if (!module) throw new Error(`Unreviewed controller dependency: ${specifier}`);
  return module;
});
await view.evaluate();
const { mountSourceEditor, editorBytes, chosenBytes } = view.namespace;
const { FILE_LIMIT, fullFilePatch, fileBytes } = patch.namespace;

class Element {
  #value = '';
  constructor(id = '') {
    this.id = id; this.listeners = new Map(); this.children = [];
    this.disabled = false; this.readOnly = false; this.checked = false;
    this.files = []; this.textContent = '';
  }
  get value() { return this.#value; }
  set value(value) {
    // Textareas normalize CR/CRLF. That must NOT change an untouched file.
    this.#value = this.id === 'file-text' ? String(value).replace(/\r\n?/g, '\n') : value;
    if (this.id === 'replacement' && value === '') this.files = [];
  }
  addEventListener(type, listener) {
    const list = this.listeners.get(type) ?? []; list.push(listener); this.listeners.set(type, list);
  }
  async emit(type) {
    // Deliberately permit injected events on disabled/read-only controls too:
    // the byte boundary must refuse unsafe edits independently of presentation.
    for (const listener of this.listeners.get(type) ?? []) await listener({ target: this });
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = [...nodes]; }
}
function selectedFile(bytes) {
  return { size: bytes.length, async arrayBuffer() { return bytes.slice().buffer; } };
}
function fixture(original = utf8.encode('old\n'), kind = 'modify') {
  const controls = new Map();
  const get = id => {
    if (!controls.has(id)) controls.set(id, new Element(id));
    return controls.get(id);
  };
  for (const [id, value] of Object.entries({ path: 'asset.bin', 'path-kind': 'text',
    'change-kind': kind, 'file-mode': '100644', 'line-endings': 'lf',
    branch: 'refs/heads/main', format: 'sha1', timestamp: '0',
    author: 'A <a@example.test>', committer: 'A <a@example.test>', message: 'edit' })) get(id).value = value;
  const client = {
    connected: true, pending: null, candidate: null, selection: { branch: 'refs/heads/main' },
    prepared: [], sends: 0,
    invalidateCandidate() { this.candidate = null; },
    clearSelection() { this.selection = null; },
    disconnect() { this.connected = false; this.selection = null; },
    async loadFile(path) { return { path_hex: path, before: { bytes: original.slice(), mode: 0o100644 } }; },
    async prepareEdits(edits, metadata) {
      this.prepared.push({ edits: structuredClone(edits), metadata });
      this.candidate = { fields: { ref: 'refs/heads/main', expected_commit: 'base', candidate_commit: 'candidate' },
        sha256: 'digest', bundleBytes: 1, inspection: { comparison: { entries: [] } } };
      return this.candidate;
    },
    async send() { this.sends += 1; throw new Error('Publication was not authorized by this test.'); },
  };
  const app = mountSourceEditor({ getElementById: get, createElement: () => new Element() }, {
    client, events: { addEventListener() {} },
  });
  return {
    app, client, get,
    status: () => get('status').textContent,
    async load() { await get('load-file').emit('click'); },
    async queue() { await get('queue-file').emit('click'); },
    async upload(file) {
      get('replacement').files = file ? [file] : [];
      get('replacement').value = file ? 'chosen.bin' : '';
      await get('replacement').emit('change');
    },
    async input(id, value) { get(id).value = value; await get(id).emit('input'); },
  };
}
function bytesEqual(actual, expected) {
  // Keep failures bounded too: rendering a 256 KiB array diff can overwhelm
  // Node's assertion formatter when testing a controller that loses the bytes.
  assert.equal(actual.length, expected.length, 'exact byte length');
  assert.ok(Buffer.from(actual).equals(Buffer.from(expected)), 'exact byte contents');
}

// Success cases exercise real controls, queue validation and the actual native
// patch encoder input, not just the byte helper in isolation.
test('create a binary file containing every byte without submitting a mutation', async () => {
  const f = fixture(undefined, 'create'), data = Uint8Array.from({ length: 256 }, (_, i) => i);
  await f.upload(selectedFile(data)); await f.queue();
  assert.equal(f.app.queued.length, 1, f.status());
  assert.equal(f.app.queued[0].before, null);
  bytesEqual(f.app.queued[0].after.bytes, data);
  assert.equal(f.client.prepared.length, 0); assert.equal(f.client.sends, 0);
});
test('replace text with binary bytes and pass the exact pair to native preparation', async () => {
  const before = utf8.encode('before\r\n'), after = Uint8Array.of(0, 255, 10, 13, 0, 128);
  const f = fixture(before); await f.load(); await f.upload(selectedFile(after)); await f.queue();
  assert.equal(f.app.queued.length, 1, f.status());
  await f.get('prepare-edits').emit('click');
  assert.equal(f.client.prepared.length, 1, f.status());
  bytesEqual(f.client.prepared[0].edits[0].before.bytes, before);
  bytesEqual(f.client.prepared[0].edits[0].after.bytes, after);
  assert.equal(f.client.pending, null); assert.equal(f.client.sends, 0);
});
for (const [name, data] of [['NUL-containing UTF-8', Uint8Array.of(65, 0, 10)], ['invalid UTF-8', Uint8Array.of(255, 128, 10)]]) {
  test(`${name}: mode-only editing preserves bytes and locks text conversion`, async () => {
    const f = fixture(data); await f.load();
    assert.equal(f.get('file-text').disabled, true);
    assert.equal(f.get('content-mode').value, 'hex');
    assert.equal(f.get('line-endings').disabled, true);
    assert.equal(f.get('file-text').value, '');
    await f.input('file-mode', '100755'); await f.queue();
    assert.equal(f.app.queued.length, 1, f.status());
    const edit = f.app.queued[0]; bytesEqual(edit.before.bytes, data); bytesEqual(edit.after.bytes, data);
    assert.equal(edit.after.mode, 0o100755);
    const encoded = fullFilePatch([edit], { allowBinary: true }).bytes;
    assert.match(new TextDecoder().decode(encoded), /old mode 100644\nnew mode 100755/);
    assert.equal(Buffer.from(encoded).includes(Buffer.from('@@')), false);
  });
  test(`${name}: an injected text/line-ending event cannot turn blank UI into file contents`, async () => {
    const f = fixture(data); await f.load(); await f.input('line-endings', 'crlf'); await f.queue();
    assert.equal(f.app.queued.length, 0);
    assert.match(f.status(), /Unchanged files/);
    assert.throws(() => editorBytes('replacement text', data, true, 'lf'), /Binary\/non-text files/);
  });
  test(`${name}: delete does not read irrelevant replacement text, endings or mode`, async () => {
    const f = fixture(data, 'delete'); await f.load();
    await f.input('file-text', '\ud800'); await f.input('line-endings', 'not-an-ending');
    await f.input('file-mode', 'not-a-mode'); await f.queue();
    assert.equal(f.app.queued.length, 1, f.status());
    bytesEqual(f.app.queued[0].before.bytes, data); assert.equal(f.app.queued[0].after, null);
  });
}
test('binary replacement permits an explicit zero-byte result', async () => {
  const f = fixture(Uint8Array.of(0, 255)); await f.load();
  await f.upload(selectedFile(new Uint8Array())); await f.queue();
  assert.equal(f.app.queued.length, 1, f.status()); assert.equal(f.app.queued[0].after.bytes.length, 0);
});
test('the exact 256 KiB binary boundary is accepted, without broadening the envelope', async () => {
  const data = new Uint8Array(FILE_LIMIT), f = fixture(undefined, 'create');
  await f.upload(selectedFile(data)); await f.queue();
  assert.equal(f.app.queued.length, 1, f.status()); bytesEqual(f.app.queued[0].after.bytes, data);
});
test('the shared text/initial-history profile still rejects binary data', () => {
  const data = Uint8Array.of(0, 255);
  assert.throws(() => fileBytes(data), /NUL/);
  assert.throws(() => fullFilePatch([{ path_hex: '78', before: null, after: { bytes: data, mode: 0o100644 } }]), /NUL/);
  assert.throws(() => editorBytes('typed\0text', null, true, 'lf'), /edited text/);
});
test('valid text remains editable and an untouched BOM/mixed-newline file stays byte-exact', async () => {
  const original = Uint8Array.from([0xef, 0xbb, 0xbf, ...utf8.encode('one\r\ntwo\rthree\n')]);
  const f = fixture(original); await f.load();
  assert.equal(f.get('file-text').readOnly, false); assert.equal(f.get('line-endings').disabled, false);
  assert.equal(f.get('file-text').value.charCodeAt(0), 0xfeff);
  assert.equal(f.get('file-text').value.includes('\r'), false); // real textarea normalization
  await f.input('file-mode', '100755'); await f.queue();
  assert.equal(f.app.queued.length, 1, f.status()); bytesEqual(f.app.queued[0].after.bytes, original);
});
test('edited text still obeys explicit LF/CRLF selection and size limits', () => {
  const value = '\ufeffone\r\ntwo\rthree\n';
  bytesEqual(editorBytes(value, utf8.encode('old'), true, 'lf'), utf8.encode('\ufeffone\ntwo\nthree\n'));
  bytesEqual(editorBytes(value, utf8.encode('old'), true, 'crlf'), utf8.encode('\ufeffone\r\ntwo\r\nthree\r\n'));
  assert.throws(() => editorBytes('x'.repeat(FILE_LIMIT + 1), null, true, 'lf'), /edited text/);
  assert.throws(() => editorBytes('', new Uint8Array(FILE_LIMIT + 1), false, 'lf'), /256 KiB/);
});

// Replacement failures must be fail-closed with respect to both an earlier
// upload and an apparently available textarea/old-file fallback.
for (const [name, rejected] of [
  ['oversized declaration', () => ({ size: FILE_LIMIT + 1, arrayBuffer() { throw new Error('must not be read'); } })],
  ['inconsistent returned length', () => ({ size: 3, async arrayBuffer() { return new ArrayBuffer(2); } })],
  ['read failure', () => ({ size: 3, async arrayBuffer() { throw new Error('disk read failed'); } })],
  ['wrong returned type', () => ({ size: 3, async arrayBuffer() { return new Uint8Array(3); } })],
]) {
  test(`${name}: never reuse the previous upload or a fallback text buffer`, async () => {
    const f = fixture(undefined, 'create');
    await f.input('file-text', 'fallback text');
    await f.upload(selectedFile(utf8.encode('previous upload')));
    await f.upload(rejected()); await f.queue();
    assert.equal(f.app.queued.length, 0, 'a failed selection must not become any previous bytes');
    assert.match(f.status(), /selected replacement has not completed validation/);
  });
}
test('oversized files are refused before arrayBuffer performs any work', async () => {
  let reads = 0;
  await assert.rejects(chosenBytes({ size: FILE_LIMIT + 1, async arrayBuffer() { reads += 1; return new ArrayBuffer(0); } }, FILE_LIMIT), /byte limit/);
  assert.equal(reads, 0);
});
test('clearing a failed picker selection explicitly restores text authoring', async () => {
  const f = fixture(undefined, 'create'); await f.input('file-text', 'explicit fallback');
  await f.upload({ size: FILE_LIMIT + 1 }); await f.queue(); assert.equal(f.app.queued.length, 0);
  await f.upload(null); assert.match(f.status(), /Replacement selection cleared/); await f.queue();
  assert.equal(f.app.queued.length, 1, f.status()); bytesEqual(f.app.queued[0].after.bytes, utf8.encode('explicit fallback'));
});
test('a subsequent valid binary selection can recover from a failed read', async () => {
  const f = fixture(undefined, 'create'); await f.upload({ size: FILE_LIMIT + 1 });
  const selected = Uint8Array.of(0, 1, 255); await f.upload(selectedFile(selected)); await f.queue();
  assert.equal(f.app.queued.length, 1, f.status()); bytesEqual(f.app.queued[0].after.bytes, selected);
});
test('an explicit deletion needs no successful replacement upload', async () => {
  const original = Uint8Array.of(0, 255), f = fixture(original, 'delete'); await f.load();
  await f.upload({ size: FILE_LIMIT + 1 }); await f.queue();
  assert.equal(f.app.queued.length, 1, f.status()); assert.equal(f.app.queued[0].after, null);
  bytesEqual(f.app.queued[0].before.bytes, original);
});
test('changing paths while a file read is outstanding cannot install stale bytes', async () => {
  const f = fixture(undefined, 'create'); let complete;
  const pending = f.upload({ size: 3, arrayBuffer: () => new Promise(resolveRead => { complete = resolveRead; }) });
  assert.equal(typeof complete, 'function');
  await f.input('path', 'different.bin'); complete(Uint8Array.of(0, 1, 2).buffer); await pending;
  assert.match(f.status(), /selection changed/i); assert.equal(f.app.queued.length, 0);
  await f.input('file-text', 'fresh selection'); await f.queue();
  assert.equal(f.app.queued.length, 1, f.status());
  assert.equal(f.app.queued[0].path_hex, hex(utf8.encode('different.bin')));
  bytesEqual(f.app.queued[0].after.bytes, utf8.encode('fresh selection'));
});
test('disconnect drains a late replacement result without restoring cleared bytes', async () => {
  const f = fixture(undefined, 'create'); let complete;
  const pending = f.upload({ size: 2, arrayBuffer: () => new Promise(resolveRead => { complete = resolveRead; }) });
  f.app.disconnect(); complete(Uint8Array.of(0, 255).buffer); await pending;
  assert.equal(f.client.connected, false); assert.equal(f.app.queued.length, 0);
  assert.equal(f.get('replacement').files.length, 0); assert.equal(f.get('file-text').value, '');
});
test('a failed reload clears the old replacement picker and editor text', async () => {
  const f = fixture(); await f.load(); await f.upload(selectedFile(utf8.encode('old replacement')));
  f.client.loadFile = async () => { throw new Error('source moved'); };
  await f.load(); assert.equal(f.get('replacement').files.length, 0); assert.equal(f.get('file-text').value, '');
  await f.queue(); assert.equal(f.app.queued.length, 0); assert.match(f.status(), /Load the complete existing file/);
});
test('the complete encoded-patch budget remains atomic across binary edits', async () => {
  const f = fixture(undefined, 'create');
  for (let i = 0; i < 4; i += 1) {
    await f.input('path', `binary-${i}`); await f.upload(selectedFile(new Uint8Array(FILE_LIMIT))); await f.queue();
    assert.equal(f.app.queued.length, Math.min(i + 1, 3), f.status());
  }
  assert.match(f.status(), /Encoded patch exceeds/);
});
test('the 64-file limit still refuses a 65th edit without mutating the existing queue', async () => {
  const f = fixture(undefined, 'create');
  for (let i = 0; i < 65; i += 1) {
    await f.input('path', `binary-${i}`); await f.upload(selectedFile(Uint8Array.of(0, 1))); await f.queue();
  }
  assert.equal(f.app.queued.length, 64, f.status()); assert.match(f.status(), /selected replacement has not completed validation/);
});
test('binary authoring does not weaken repository path validation', async () => {
  const f = fixture(undefined, 'create'); await f.input('path', '../outside');
  await f.upload(selectedFile(Uint8Array.of(0, 1))); await f.queue();
  assert.equal(f.app.queued.length, 0); assert.match(f.status(), /Unsafe repository path/);
});
test('an unresolved publication still blocks binary queue changes', async () => {
  const f = fixture(undefined, 'create'); await f.upload(selectedFile(Uint8Array.of(0, 1)));
  f.client.pending = { sent: true, exported: true }; await f.queue();
  assert.equal(f.app.queued.length, 0); assert.match(f.status(), /Resolve the original publication/);
});

for (const [name, original] of [
  ['oversized untouched bytes', new Uint8Array(256 * 1024 + 1)],
  ['oversized dirty bytes', new Uint8Array(256 * 1024 + 1)],
  ['non-byte string', 'old'],
  ['non-byte array', [65]],
]) {
  test(`text helper validates ${name} before retaining or converting the original`, () => {
    assert.throws(() => editorBytes('new', original, name.includes('dirty'), 'lf'), /256 KiB/);
  });
}
for (const [name, original] of [
  ['NUL', Uint8Array.of(65, 0)], ['invalid UTF-8', Uint8Array.of(255)],
  ['control', Uint8Array.of(65, 1)], ['bidi', utf8.encode('a\u202eb')],
]) {
  test(`${name}: helper preserves untouched bytes but refuses implicit text conversion`, () => {
    const retained = editorBytes('', original, false, 'lf');
    bytesEqual(retained, original); assert.notEqual(retained, original);
    assert.throws(() => editorBytes('new', original, true, 'lf'), /Binary\/non-text files/);
  });
}
test('an explicit hex replacement and safe text view remain supported', async () => {
  const f = fixture(Uint8Array.of(0, 255)); await f.load();
  await f.input('file-hex', '6e 65 77 0a');
  f.get('content-mode').value = 'text'; await f.get('content-mode').emit('change');
  assert.equal(f.get('content-mode').value, 'text', f.status());
  await f.input('file-text', 'changed\n'); await f.queue();
  assert.equal(f.app.queued.length, 1, f.status());
  bytesEqual(f.app.queued[0].after.bytes, utf8.encode('changed\n'));
});
