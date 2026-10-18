// One traversal for capture, retained-prefix recovery and complete offline readback.
// Native decoders remain the schema authority; archive checks add cross-page custody.
import { isDeepStrictEqual } from 'node:util';
import { Transport, integer, principal, snapshot, listReply, showReply, reviewsReply }
  from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { commentsReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-comments.mjs';

const fail = code => { const error = new Error(`pull_archive_${code}`); error.code = error.message; throw error; };
function decode(kind, reply, number, options) {
  if (kind === 'list') return listReply(reply, options);
  if (kind === 'show') return showReply(reply, number, options);
  if (kind === 'reviews') return reviewsReply(reply, number, options);
  if (kind === 'comments') return commentsReply(reply, number, options);
  fail('page_kind');
}

export class PullArchiveWalk {
  #request = { kind: 'list', number: null, cursor: 0 };
  #rows = []; #row = 0; #after = null; #epoch = null; #discussion = null;
  #scope; #head; #source; #limits; #tenant; #repository; #pageSize;
  #counts = { pages: 0, pulls: 0, reviews: 0, comments: 0 };
  constructor({ tenant, repository, pageSize, head = null, source = null, scope = null, limits }) {
    this.#tenant = tenant; this.#repository = repository; this.#pageSize = pageSize;
    this.#scope = scope; this.#head = head; this.#source = source; this.#limits = limits;
  }
  get request() { return this.#request && { ...this.#request }; }
  get state() { return { ...this.#counts, head: this.#head, source: this.#source,
    scope: this.#scope && { ...this.#scope }, complete: this.#request === null }; }
  #nextPull() {
    this.#epoch = null; this.#discussion = null;
    if (this.#row < this.#rows.length) this.#request = { kind: 'show', number: this.#rows[this.#row].number, cursor: 0 };
    else { this.#rows = []; this.#request = this.#after === null ? null : { kind: 'list', number: null, cursor: this.#after }; }
  }
  accept(descriptor, reply) {
    const wanted = this.#request;
    if (!wanted || ['kind', 'number', 'cursor'].some(key => descriptor[key] !== wanted[key])) fail('page_sequence');
    if (++this.#counts.pages > this.#limits.pages) fail('page_limit');
    const checked = decode(wanted.kind, reply, wanted.number,
      { after: wanted.cursor, limit: this.#pageSize, head: this.#head, scope: this.#scope });
    if (checked.binding.tenant !== this.#tenant || checked.binding.repository !== this.#repository) fail('repository_mismatch');
    if (checked.head === null || (wanted.kind !== 'list' && reply.found !== true)) fail('subject_unavailable');
    if (this.#source !== null && reply.source_head !== this.#source) fail('source_head_changed');
    this.#scope = checked.binding; this.#head = checked.head; this.#source = reply.source_head;
    const row = this.#rows[this.#row];
    if (wanted.kind === 'list') {
      this.#counts.pulls += reply.pull_requests.length;
      if (this.#counts.pulls > this.#limits.pulls) fail('pull_limit');
      // Own this page, rather than retaining caller-mutable metadata across awaits.
      this.#rows = structuredClone(reply.pull_requests); this.#row = 0; this.#after = reply.next_after;
      this.#nextPull();
    } else if (wanted.kind === 'show') {
      if (!isDeepStrictEqual(row, reply.pull_request)) fail('metadata_changed');
      this.#request = { kind: 'reviews', number: wanted.number, cursor: null };
    } else if (wanted.kind === 'reviews') {
      if (reply.pull_request_version !== row.version || (this.#epoch !== null && reply.policy_epoch !== this.#epoch)) fail('review_basis_changed');
      this.#epoch = reply.policy_epoch; this.#counts.reviews += reply.reviews.length;
      if (this.#counts.reviews > this.#limits.reviews) fail('review_limit');
      this.#request = reply.next_after === null ? { kind: 'comments', number: wanted.number, cursor: 0 }
        : { ...wanted, cursor: reply.next_after };
    } else {
      if (this.#discussion !== null && reply.discussion_version !== this.#discussion) fail('discussion_changed');
      this.#discussion = reply.discussion_version; this.#counts.comments += reply.comments.length;
      if (this.#counts.comments > this.#limits.comments) fail('comment_limit');
      if (reply.next_after !== null) this.#request = { ...wanted, cursor: reply.next_after };
      else { this.#row++; this.#nextPull(); }
    }
    return checked;
  }
  finish() { if (this.#request !== null || this.#counts.pages === 0) fail('incomplete'); return this.state; }
}

// A deliberately read-only operator adapter over the shipped Transport and
// decoders. Offline inspection never constructs it or connects a dummy token.
export async function createPullArchiveBackend({ href, token, timeoutMs, signal, maximum = 1024 * 1024 }) {
  signal?.throwIfAborted();
  const transport = new Transport({ href, timeoutMs });
  const stop = () => transport.disconnect();
  signal?.addEventListener('abort', stop, { once: true });
  let scope = null;
  const close = () => { signal?.removeEventListener('abort', stop); transport.disconnect(); };
  try { await transport.connect(token); signal?.throwIfAborted(); }
  catch (error) { close(); throw error; }
  async function read(kind, number, { after = kind === 'reviews' ? null : 0, limit = 20, head = null } = {}) {
    signal?.throwIfAborted();
    integer(limit, 'page size', 1, 100);
    if (kind !== 'list') integer(number, 'PR number', 1);
    if (kind === 'reviews') { if (after !== null) principal(after); }
    else integer(after, 'cursor');
    if (head !== null) snapshot(head);
    if (after !== null && after !== 0 && head === null) fail('continuation_snapshot');
    const query = new URLSearchParams();
    if (kind !== 'show') { if (after !== null) query.set('after', String(after)); query.set('limit', String(limit)); }
    if (head !== null) query.set('expected_head', head);
    const path = kind === 'list' ? 'pulls' : `pulls/${number}${kind === 'show' ? '' : `/${kind}`}`;
    const raw = await transport.request(`${path}${query.size ? `?${query}` : ''}`,
      { statuses: kind === 'list' ? [200] : [200, 404], maximum });
    signal?.throwIfAborted();
    const checked = decode(kind, raw.value, number, { after, limit, head, scope });
    if (kind !== 'list' && checked.reply.found !== (raw.status === 200)) fail('http_presence');
    scope = checked.binding; return checked;
  }
  return { close, list: args => read('list', null, args), show: (number, head) => read('show', number, { head }),
    reviews: (number, args) => read('reviews', number, args), comments: (number, args) => read('comments', number, args) };
}

export function readPullArchivePage(backend, request, pageSize, head) {
  const { kind, number, cursor } = request, args = { after:cursor, limit:pageSize, head };
  if (kind === 'list') return backend.list(args);
  if (kind === 'show') return backend.show(number,head);
  if (kind === 'reviews') return backend.reviews(number,args);
  if (kind === 'comments') return backend.comments(number,args);
  fail('page_kind');
}
