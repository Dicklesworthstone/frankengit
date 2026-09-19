// Same-snapshot search and independently hash-checked source navigation. Tokens,
// queries and source bytes are ephemeral; there is no mutation/recovery surface.
import { Transport, copy, fail, form, integer } from './pulls-core.mjs';
import { PAGE_BYTES, fields, filePage, query, searchCommand, searchReply, selection, verifyFile } from './search-data.mjs';

export class CodeSearch {
  #transport; #selection = null; #scope = null; #pin = null; #result = null; #generation = 0; #timeout;
  constructor(options) {
    this.#timeout = integer(options.timeoutMs ?? 30_000, 'operation timeout', 1, 300_000);
    this.#transport = new Transport({ ...options, pageSuffix: '/ui/search/' });
  }
  get connected() { return this.#transport.connected; }
  get state() { return copy({ connected: this.connected, selection: this.#selection, scope: this.#scope, pin: this.#pin, result: this.#result }); }
  async connect(token, reference, algorithm) {
    this.disconnect();
    const selected = selection(reference, algorithm), generation = this.#generation;
    await this.#transport.connect(token);
    if (generation !== this.#generation) fail('Connection superseded.');
    this.#selection = selected;
  }
  disconnect() {
    this.#generation += 1; this.#transport.disconnect();
    this.#selection = null; this.#scope = null; this.#pin = null; this.#result = null;
  }
  cancel() { this.#generation += 1; this.#transport.cancelReads(); }
  discardResults() { this.cancel(); this.#result = null; }
  refreshSnapshot() { this.discardResults(); this.#pin = null; } // Keep the repository/incarnation binding.
  async #run(action) {
    if (!this.connected || !this.#selection) fail('Connect a read-scoped token and reference first.');
    this.cancel();
    const generation = this.#generation, epoch = this.#transport.epoch;
    let expired = false;
    const check = () => {
      if (expired) fail('Search operation exceeded its total time limit.');
      if (generation !== this.#generation || epoch !== this.#transport.epoch || !this.connected) fail('Read superseded or disconnected.');
    };
    const timer = setTimeout(() => { expired = true; if (generation === this.#generation) this.#transport.cancelReads(); }, this.#timeout);
    try { const result = await action(check); check(); return result; }
    catch (error) {
      if (generation === this.#generation && !this.connected) this.disconnect();
      if (expired) fail('Search operation exceeded its total time limit.');
      throw error;
    } finally { clearTimeout(timer); }
  }
  async search(input) {
    this.discardResults();
    const q = query(input); // Copies caller arrays before the first await.
    return this.#run(async check => {
      const selected = this.#selection, command = searchCommand(selected, this.#pin, q);
      const response = await this.#transport.request(command.path, { method: 'POST', body: command.body });
      check();
      const result = searchReply(response.value, selected, q, this.#scope, this.#pin);
      check();
      this.#scope = result.scope; this.#pin = result.pin; this.#result = result;
      return copy(result);
    });
  }
  async openMatch(groupIndex, matchIndex) {
    const result = this.#result;
    if (!result) fail('Run a successful search first.');
    integer(groupIndex, 'query index', 0, result.groups.length - 1);
    const group = result.groups[groupIndex];
    integer(matchIndex, 'match index', 0, group.matches.length - 1);
    const hit = group.matches[matchIndex];
    return this.#run(async check => {
      const selected = this.#selection;
      let bytes = null, offset = 0, kind = null;
      do {
        check();
        const response = await this.#transport.request('source/blob', { method: 'POST', body: form({
          ...fields(selected, result.pin), path_hex: hit.pathHex, offset, limit: PAGE_BYTES,
        }) });
        check();
        const page = filePage(response.value, selected, result, hit, offset, bytes?.length ?? null);
        if (bytes === null) { bytes = new Uint8Array(page.total); kind = page.kind; }
        if (page.kind !== kind) fail('File mode changed between pages.');
        bytes.set(page.bytes, offset); offset = page.next;
      } while (offset !== null);
      const verified = await verifyFile(bytes, hit, result.query, groupIndex, selected.format, this.#transport.crypto, check);
      check();
      return { hit: copy(hit), scope: copy(result.scope), pin: copy(result.pin), bytes, kind, ...verified };
    });
  }
}
