// One complete native discussion traversal for capture and offline readback.
// Replay checks an API observation; it never establishes repository authority.
import { isDeepStrictEqual } from 'node:util';
import { discussionPage, discussionHistory, discussionState, discussionAction }
  from '../../crates/fgit-node/src/smart_http/server/browser/discussions.mjs';
import { operatorError } from './forge-operator-io.mjs';

const fail = reason => { throw operatorError(`discussion_archive_${reason}`); };
export function discussionArchiveState(row) {
  discussionState(row);
  return { number: row.number, version: row.version, title: row.title, body: row.body,
    state: row.state, opened_by: row.opened_by, last_actor: row.last_actor,
    comments: row.comments, locked: row.locked };
}
export function discussionSourceHead(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 256 ||
      /[\x00-\x20\x7f\uD800-\uDFFF]/u.test(value)) fail('source_head');
  return value;
}
export class DiscussionArchiveWalk {
  #scope; #limit; #caps; #head; #source;
  #next = { number: null, after: 0 };
  #queue = []; #listNext = null; #folded = null;
  #discussions = 0; #events = 0;
  constructor(scope, limit, caps) {
    this.#scope = { tenant: scope.tenant_id, repository: scope.repository_id };
    this.#limit = limit; this.#caps = caps;
    this.#head = scope.snapshot_token; this.#source = scope.source_head;
  }
  get next() { return this.#next && { ...this.#next }; }
  get state() { return { head: this.#head, source: this.#source,
    discussions: this.#discussions, events: this.#events, complete: this.#next === null }; }
  accept(descriptor, reply) {
    if (!isDeepStrictEqual(descriptor, this.#next) || this.#next === null) fail('page_order');
    const { number, after } = this.#next;
    const options = { after, limit: this.#limit, head: this.#head, binding: this.#scope };
    const checked = number === null ? discussionPage(reply, options) : discussionHistory(reply, number, options);
    const source = discussionSourceHead(reply.source_head);
    if (this.#source !== null && this.#source !== source) fail('source_head_changed');
    this.#source = source; this.#head = checked.head;
    if (number === null) {
      this.#discussions += reply.discussions.length;
      if (this.#discussions > this.#caps.discussions) fail('discussion_limit');
      this.#queue = reply.discussions.map(discussionArchiveState);
      this.#listNext = reply.next_after;
      // Declared histories spend the shared budget before further HTTP reads.
      const declared = this.#queue.reduce((n, row) => n + row.version, this.#events);
      if (!Number.isSafeInteger(declared) || declared > this.#caps.events) fail('event_limit');
      this.#advance(); return;
    }
    const expected = this.#queue[0];
    if (!reply.found || !isDeepStrictEqual(discussionArchiveState(reply.discussion), expected)) {
      fail('list_history_disagreement');
    }
    for (const event of reply.events) {
      const { name, body_rendered: _rendered, ...fields } = event.action;
      const action = discussionAction(name, fields);
      if (name === 'open') this.#folded = { number, version: 0, title: action.title, body: action.body,
        state: 'open', opened_by: event.actor, last_actor: event.actor, comments: 0, locked: false };
      const s = this.#folded;
      if (!s || event.version !== s.version + 1) fail('history_version');
      if (name === 'edit') for (const key of ['title', 'body']) if (Object.hasOwn(action, key)) s[key] = action[key];
      if (name === 'comment') {
        if (s.locked) fail('comment_while_locked');
        s.comments++;
      }
      if (name === 'close' || name === 'reopen') {
        const state = name === 'close' ? 'closed' : 'open';
        if (s.state === state) fail('invalid_state_transition');
        s.state = state;
      }
      if (name === 'lock' || name === 'unlock') {
        const locked = name === 'lock';
        if (s.locked === locked) fail('invalid_lock_transition');
        s.locked = locked;
      }
      s.version = event.version; s.last_actor = event.actor;
      if (++this.#events > this.#caps.events) fail('event_limit');
    }
    if (reply.next_after_version !== null) this.#next = { number, after: reply.next_after_version };
    else {
      if (!isDeepStrictEqual(this.#folded, expected)) fail('history_state_disagreement');
      this.#queue.shift(); this.#folded = null; this.#advance();
    }
  }
  #advance() {
    this.#next = this.#queue.length ? { number: this.#queue[0].number, after: 0 }
      : this.#listNext !== null ? { number: null, after: this.#listNext } : null;
  }
}
