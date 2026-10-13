// Isolated controller dependencies. Production modules are copied unchanged;
// these adapters do NOT implement native HTTP or Initial conformance.
import { mkdtemp, copyFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const root = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
const core = `
export { binding, hex, keys, oid, record, snapshot, utf8 } from '${new URL('pulls-core.mjs', root).href}';
export const copy = value => structuredClone(value);
export const decimal = (value, name, min = 0) => integer(Number(value), name, min);
export const unhex = value => Uint8Array.from({ length: value.length / 2 }, (_, i) => Number.parseInt(value.slice(i * 2, i * 2 + 2), 16));
export const fail = message => { throw new Error(message); };
export function integer(value, name, min = 0, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(name); return value;
}
export function form(fields) { const out = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) for (const item of Array.isArray(value) ? value : [value]) out.append(key, String(item));
  return out.toString();
}
export class Transport {
  connected = false; epoch = 0;
  constructor(options) { this.dispatch = options.fetchImpl; }
  async connect() { this.epoch++; this.connected = true; }
  disconnect() { this.epoch++; this.connected = false; }
  cancelReads() {}
  request(path, options) { return this.dispatch(path, options); }
}`;
const data = `
export const PAGE_BYTES = 65536;
export const byteInput = (value, encoding) => encoding === 'hex' ? value : Array.from(new TextEncoder().encode(value), b => b.toString(16).padStart(2, '0')).join('');
export const selection = (reference, format) => ({ reference, format });
export const fields = (selection, pin) => ({ ref: selection.reference, object_format: selection.format,
  ...(pin ? { expected_head: pin.head, expected_commit: pin.commit } : {}) });
const unused = () => { throw new Error('This isolated test must not enter other search modes or full-file navigation.'); };
export { unused as filePage, unused as query, unused as searchCommand, unused as searchReply, unused as verifyFile };
`;
const index = `
import { form } from './pulls-core.mjs';
import { fields } from './search-data.mjs';
export function initialQuery(input) {
  if (Object.hasOwn(input, 'context')) throw new Error('context leaked to closed Initial grammar');
  return structuredClone(input);
}
export function initialCommand(selected, pin, q, minimum) {
  return form({ ...fields(selected, pin), term_hex: q.termsHex,
    ...(minimum.lexical ? { minimum_lexical_token: minimum.lexical.token, minimum_lexical_number: minimum.lexical.number } : {}),
    ...(q.symbol && minimum.symbols ? { minimum_symbol_token: minimum.symbols.token, minimum_symbol_number: minimum.symbols.number } : {}) });
}
export function initialReply(raw, selected, q) {
  if (!raw || raw.reject || !raw.normalized) throw new Error('Initial adapter rejected nested receipt');
  return { ...structuredClone(raw.normalized), query: structuredClone(q) };
}
const unused = () => { throw new Error('Unexpected standalone index invocation.'); };
export { unused as indexCommand, unused as indexQuery, unused as indexReply, unused as verifyIndexedFile,
  unused as symbolCommand, unused as symbolQuery, unused as symbolReply };
`;
export async function setup(t, dispatch, timeoutMs = 30000) {
  const dir = await mkdtemp(join(tmpdir(), 'fgit-context-controller-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  for (const name of ['search.mjs', 'search-context.mjs', 'search-context-verify.mjs', 'search-context-membership.mjs', 'search-view.mjs']) await copyFile(new URL(name, root), join(dir, name));
  for (const [name, bytes] of [['pulls-core.mjs', core], ['search-data.mjs', data], ['search-index.mjs', index], ['search-current.mjs', `export const sourceMode = value => value ?? 'exact';`]]) await writeFile(join(dir, name), bytes);
  const { CodeSearch } = await import(pathToFileURL(join(dir, 'search.mjs')).href);
  const calls = [];
  const options = { href: 'http://localhost/repo.git/ui/search/', timeoutMs,
    fetchImpl: (path, options) => { calls.push({ path, options }); return dispatch(path, options); } };
  const client = new CodeSearch(options);
  await client.connect('fixture-token-not-a-credential', 'refs/heads/main', 'sha1');
  return { client, calls, options, loadView: () => import(pathToFileURL(join(dir, 'search-view.mjs')).href) };
}
