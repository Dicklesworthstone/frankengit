// Explicit native-schema peers for progressive browser tests, not a Rust node.
// The production controller, transport and validators are imported unchanged.
import { webcrypto } from 'node:crypto';
import { CodeSearch } from '../../crates/fgit-node/src/smart_http/server/browser/search.mjs';
import { TOKEN, hex } from '../operator/source_context_fixtures.mjs';
import { symbolInput } from '../operator/source_context_symbols_fixtures.mjs';
import { nativeRanked, PROFILE } from '../operator/source_context_ranking_fixtures.mjs';
export { webcrypto, TOKEN, PROFILE, hex };
export const clone = value => structuredClone(value);
export const turn = () => new Promise(resolve => setTimeout(resolve, 0));
export function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
export function fixture(format = 'sha1') {
  const q = symbolInput(format, { limits: { context_max_files: 1 } });
  return { q, wire: nativeRanked(q), request: { mode: 'initial', termsHex: q.terms.map(hex),
    symbol: { nameHex: hex(q.symbols.name), match: q.symbols.match, kinds: [], policy: q.symbols.policy },
    context: { selection: PROFILE, maxFiles: 1 } } };
}
export function streamReply(headers = {}) {
  let controller, ended = false;
  const body = new ReadableStream({
    start(value) { controller = value; },
    cancel() { ended = true; },
  });
  return {
    response: new Response(body, { status: 200, headers: { 'Content-Type': 'application/x-ndjson', ...headers } }),
    bytes(text) { if (ended) throw new Error('fixture stream already ended'); controller.enqueue(new TextEncoder().encode(text)); },
    record(value) { this.bytes(JSON.stringify(value) + '\n'); },
    close() { if (!ended) { ended = true; controller.close(); } },
    attach(signal) {
      const abort = () => { if (!ended) { ended = true; controller.error(signal.reason ?? new Error('fixture aborted')); } };
      if (signal.aborted) abort(); else signal.addEventListener('abort', abort, { once: true });
    },
  };
}
export async function connected(t, { format = 'sha1', timeoutMs = 30000, headers = {}, fetchImpl = null } = {}) {
  const data = fixture(format), stream = streamReply(headers), calls = [];
  const client = new CodeSearch({ href: 'http://localhost/team/repo.git/ui/search/', cryptoImpl: webcrypto, timeoutMs,
    fetchImpl: async (url, options) => {
      calls.push({ url: String(url), options, body: new URLSearchParams(options.body) });
      if (fetchImpl) return fetchImpl(url, options, data, stream);
      if (String(url).endsWith('/source/search-progressive')) { stream.attach(options.signal); return stream.response; }
      const value = String(url).endsWith('/source/context-initial') ? data.wire : data.wire.retrieval;
      return new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
    } });
  t.after(() => client.disconnect());
  await client.connect(TOKEN, data.q.reference, format);
  return { ...data, client, stream, calls };
}
export function initial(wire) { return { phase: 'Initial', answer: clone(wire.retrieval) }; }
export function refined(wire) { return { phase: 'Refined', answer: clone(wire) }; }
