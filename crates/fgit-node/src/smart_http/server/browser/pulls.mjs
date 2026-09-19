// Native PR client. Views are immutable observations, never merge permission.
import { Transport, integer, principal, snapshot, listReply, showReply, reviewsReply, copy, fail } from './pulls-core.mjs';

export class PullClient {
  #transport; #scope = null;
  constructor(options) { this.#transport = new Transport(options); }
  get connected() { return this.#transport.connected; }
  get binding() { return this.#scope && copy(this.#scope); }
  async connect(token) { this.#scope = null; await this.#transport.connect(token); }
  disconnect() { this.#transport.disconnect(); this.#scope = null; }
  cancelReads() { this.#transport.cancelReads(); }
  async list({ after = 0, limit = 20, head = null } = {}) {
    integer(after, 'PR cursor'); integer(limit, 'page size', 1, 100);
    if (head !== null) snapshot(head); if (after && !head) fail('Continuation requires its original snapshot.');
    const query = new URLSearchParams({ after: String(after), limit: String(limit) });
    if (head) query.set('expected_head', head);
    const raw = await this.#transport.request(`pulls?${query}`);
    const checked = listReply(raw.value, { after, limit, head, scope: this.#scope });
    this.#scope = checked.binding; return checked;
  }
  async show(number, head = null) {
    integer(number, 'PR number', 1); if (head !== null) snapshot(head);
    const query = new URLSearchParams(); if (head) query.set('expected_head', head);
    const raw = await this.#transport.request(`pulls/${number}${head ? `?${query}` : ''}`, { statuses: [200, 404] });
    const checked = showReply(raw.value, number, { head, scope: this.#scope });
    if (checked.reply.found !== (raw.status === 200)) fail('PR presence and HTTP status disagree.');
    this.#scope = checked.binding; return checked;
  }
  async reviews(number, { after = null, limit = 20, head = null } = {}) {
    integer(number, 'PR number', 1); integer(limit, 'page size', 1, 100);
    if (after !== null) principal(after); if (head !== null) snapshot(head);
    if (after !== null && head === null) fail('Review continuation requires its original snapshot.');
    const query = new URLSearchParams({ limit: String(limit) });
    if (after !== null) query.set('after', after); if (head !== null) query.set('expected_head', head);
    const raw = await this.#transport.request(`pulls/${number}/reviews?${query}`, { statuses: [200, 404] });
    const checked = reviewsReply(raw.value, number, { after, limit, head, scope: this.#scope });
    if (checked.reply.found !== (raw.status === 200)) fail('Review presence and HTTP status disagree.');
    this.#scope = checked.binding; return checked;
  }
}
