// Same-snapshot search and independently hash-checked source navigation. Tokens,
// queries and source bytes are ephemeral; there is no mutation/recovery surface.
import { Transport, copy, fail, form, integer } from './pulls-core.mjs';
import { PAGE_BYTES, fields, filePage, query, searchCommand, searchReply, selection, verifyFile } from './search-data.mjs';

import { indexCommand, indexQuery, indexReply, verifyIndexedFile } from './search-index.mjs';

export class CodeSearch {
  #transport; #selection = null; #scope = null; #pin = null; #result = null; #generation = 0; #timeout; #indexMinimum = null;
  constructor(options) {
    this.#timeout = integer(options.timeoutMs ?? 30_000, 'operation timeout', 1, 300_000);
    this.#transport = new Transport({ ...options, pageSuffix: '/ui/search/' });
  }
  get connected() { return this.#transport.connected; }
  get state() { return copy({ connected: this.connected, selection: this.#selection, scope: this.#scope, pin: this.#pin, result: this.#result, indexMinimum: this.#indexMinimum }); }
  async connect(token, reference, algorithm) {
    this.disconnect();
    const selected = selection(reference, algorithm), generation = this.#generation;
    await this.#transport.connect(token);
    if (generation !== this.#generation) fail('Connection superseded.');
    this.#selection = selected;
  }
  disconnect() {
    this.#generation += 1; this.#transport.disconnect();
    this.#selection = null; this.#scope = null; this.#pin = null; this.#result = null; this.#indexMinimum = null;
  }
  cancel() { this.#generation += 1; this.#transport.cancelReads(); }
  discardResults() { this.cancel(); this.#result = null; }
  refreshSnapshot() { this.discardResults(); this.#pin = null; } // Keep the repository/incarnation binding.
  async #run(action) {
    if (!this.connected || !this.#selection) fail('Connect a read-scoped token and reference first.');
    this.cancel();
    const generation = this.#generation, epoch = this.#transport.epoch;
    const deadline = performance.now() + this.#timeout;
    let expired = false;
    const check = () => {
      if (expired || performance.now() >= deadline) fail('Search operation exceeded its total time limit.');
      if (generation !== this.#generation || epoch !== this.#transport.epoch || !this.connected) fail('Read superseded or disconnected.');
    };
    const timer = setTimeout(() => { expired = true; if (generation === this.#generation) this.#transport.cancelReads(); }, this.#timeout);
    try { const result = await action(check); check(); return result; }
    catch (error) {
      if (generation === this.#generation && !this.connected) this.disconnect();
      if (expired || performance.now() >= deadline) fail('Search operation exceeded its total time limit.');
      throw error;
    } finally { clearTimeout(timer); }
  }
  async search(input) {
    this.discardResults();
    const q = input?.mode === 'indexed' ? indexQuery(input) : query(input); // Copies caller arrays before the first await.
    return this.#run(async check => {
      if (q.mode === 'indexed') return this.#indexed(q, null, check);
      const selected = this.#selection, command = searchCommand(selected, this.#pin, q);
      const response = await this.#transport.request(command.path, { method: 'POST', body: command.body });
      check();
      const result = searchReply(response.value, selected, q, this.#scope, this.#pin);
      check();
      this.#scope = result.scope; this.#pin = result.pin; this.#result = result;
      return copy(result);
    });
  }
  async #indexed(q, previous, check) {
    const selected = this.#selection, minimum = this.#indexMinimum;
    const body = indexCommand(selected, this.#pin, q, previous, minimum);
    const response = await this.#transport.request('source/search-index', { method: 'POST', body });
    check();
    const result = indexReply(response.value, selected, q, this.#scope, this.#pin, previous, minimum);
    check();
    this.#scope = result.scope; this.#pin = result.pin; this.#indexMinimum = result.selectedIndex; this.#result = result;
    return copy(result);
  }
  async nextIndexed() {
    const previous = this.#result;
    if (!previous || previous.query.mode !== 'indexed' || previous.nextAfter === null) fail('No indexed continuation remains.');
    this.discardResults();
    // Reuse the saved normalized query, original source and index. No form input
    // can refresh its leases or turn a continuation into an unrelated query.
    return this.#run(check => this.#indexed(previous.query, previous, check));
  }
  async openIndexed(hitIndex) {
    const result = this.#result;
    if (!result || result.query.mode !== 'indexed') fail('Run a successful indexed search first.');
    integer(hitIndex, 'indexed hit', 0, result.hits.length - 1);
    const hit = result.hits[hitIndex];
    if (hit.contentBytes > result.query.maxFileBytes) fail('Indexed file exceeds the selected navigation byte limit.');
    return this.#run(async check => {
      const selected = this.#selection;
      const file = await this.#readFile(selected, result, hit, check, hit.contentBytes);
      const verified = await verifyIndexedFile(file.bytes, hit, result.query, selected.format, this.#transport.crypto, check);
      check();
      return { hit: copy(hit), query: copy(result.query), scope: copy(result.scope), pin: copy(result.pin), ...file, ...verified };
    });
  }
  async #readFile(selected, result, hit, check, total = null) {
    let bytes = null, offset = 0, kind = null;
    do {
      check();
      const response = await this.#transport.request('source/blob', { method: 'POST', body: form({
        ...fields(selected, result.pin), path_hex: hit.pathHex, offset, limit: PAGE_BYTES,
      }) });
      check();
      const page = filePage(response.value, selected, result, hit, offset, bytes?.length ?? total);
      if (bytes === null) { bytes = new Uint8Array(page.total); kind = page.kind; }
      if (page.kind !== kind) fail('File mode changed between pages.');
      bytes.set(page.bytes, offset); offset = page.next;
    } while (offset !== null);
    return { bytes, kind };
  }
  async openMatch(groupIndex, matchIndex) {
    const result = this.#result;
    if (!result || result.query.mode === 'indexed') fail('Run a successful literal or regex search first.');
    integer(groupIndex, 'query index', 0, result.groups.length - 1);
    const group = result.groups[groupIndex];
    integer(matchIndex, 'match index', 0, group.matches.length - 1);
    const hit = group.matches[matchIndex];
    return this.#run(async check => {
      const selected = this.#selection;
      const { bytes, kind } = await this.#readFile(selected, result, hit, check);
      const verified = await verifyFile(bytes, hit, result.query, groupIndex, selected.format, this.#transport.crypto, check);
      check();
      return { hit: copy(hit), scope: copy(result.scope), pin: copy(result.pin), bytes, kind, ...verified };
    });
  }
}
