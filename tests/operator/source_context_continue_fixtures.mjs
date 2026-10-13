// Real client/store calls; replies are explicit native-schema peers, not Rust fg.
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { acquire, query } from '../../scripts/operator/source_context.mjs';
import { publishBundle } from '../../scripts/operator/source_context_export.mjs';
import { input, report, peer, json, TOKEN, defaults } from './source_context_fixtures.mjs';
import { nativeSymbols } from './source_context_symbols_fixtures.mjs';
export { input, TOKEN };
export async function fixture(t, original = input(), settings = {}) {
  const q = query(original), root = await mkdtemp(join(tmpdir(), 'fg-context-continue-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const state = { decorate: settings.decorate ?? (r => r), hang: false, seen: [], status: 200 };
  const p = await peer(t, (_req, res, call) => {
    const form = new URLSearchParams(call.body), requested = { ...q,
      terms: form.getAll('term_hex').map(s => Buffer.from(s, 'hex').toString()),
      prefixes_hex: form.getAll('path_prefix_hex'),
      limits: Object.fromEntries(Object.keys(defaults).map(k => [k, Number(form.get(k))])) };
    if (form.has('symbol_name_hex')) requested.symbols = { name: Buffer.from(form.get('symbol_name_hex'), 'hex').toString(),
      match: form.get('symbol_match'), policy: form.get('symbol_policy'), kinds: form.getAll('symbol_kind') };
    state.seen.push(requested);
    if (state.status !== 200) { res.writeHead(state.status); res.end('refused'); return; }
    if (state.hang) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); state.started?.(); return; }
    const raw = requested.symbols ? nativeSymbols(requested, settings.files, settings.declarations)
      : report(requested, settings.files);
    json(res, state.decorate(raw, requested));
  });
  const capture = await acquire(p.endpoint, TOKEN, q), bundle = join(root, 'parent');
  const receipt = await publishBundle(bundle, capture);
  p.calls.length = 0; state.seen.length = 0;
  const originalBytes = await Promise.all(['capture.json', 'context.txt', 'manifest.json'].map(f => readFile(join(bundle, f))));
  return { root, bundle, receipt, capture, p, state, originalBytes,
    readParent: () => Promise.all(['capture.json', 'context.txt', 'manifest.json'].map(f => readFile(join(bundle, f)))) };
}
