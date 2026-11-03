// The v2 archive traverses both canonical aggregate families at one authority
// snapshot. Replay proves API self-consistency, never destination authority.
import { issuePage, issueHistory, issueState, issueLocked, issueMilestone, issueAction }
  from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { milestonePage, milestoneHistory, milestoneState, milestoneAction }
  from '../../crates/fgit-node/src/smart_http/server/browser/milestones.mjs';
import { operatorError } from './forge-operator-io.mjs';

export const ISSUE_ARCHIVE_SCHEMA_V2 = 'frankengit-issue-read-archive-v2';
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const fail = reason => { throw operatorError(`issue_archive_${reason}`); };
export function milestoneArchiveState(row) {
  milestoneState(row);
  return { number: row.number, version: row.version, title: row.title, body: row.body, due_at: row.due_at,
    state: row.state, opened_by: row.opened_by, last_actor: row.last_actor,
    open_issues: row.open_issues, closed_issues: row.closed_issues };
}
export function issueArchiveState(row) {
  issueState(row);
  return { number: row.number, version: row.version, title: row.title, body: row.body, labels: row.labels,
    state: row.state, opened_by: row.opened_by, last_actor: row.last_actor,
    comments: row.comments, assignees: row.assignees ?? [], locked: issueLocked(row), milestone: issueMilestone(row) };
}
export class MilestoneArchiveWalk {
  constructor(scope, limit, caps) {
    this.scope = scope; this.limit = limit; this.caps = caps;
    this.head = scope.snapshot_token; this.source = scope.source_head;
    this.next = { kind: 'milestone', number: null, after: 0 };
    this.queue = []; this.listNext = null; this.folded = null;
    this.issues = 0; this.milestones = 0; this.events = 0;
    this.milestoneVersions = new Map(); this.progress = new Map();
  }
  accept(reply) {
    if (this.next === null) fail('extra_page');
    const { kind, number, after } = this.next;
    const options = { after, limit: this.limit, head: this.head,
      binding: { tenant: this.scope.tenant_id, repository: this.scope.repository_id } };
    const checked = kind === 'milestone'
      ? number === null ? milestonePage(reply, options) : milestoneHistory(reply, number, options)
      : number === null ? issuePage(reply, options) : issueHistory(reply, number, options);
    const source = reply.source_head;
    if (typeof source !== 'string' || !source || Buffer.byteLength(source) > 256 ||
        /[\x00-\x20\x7f\uD800-\uDFFF]/u.test(source)) fail('source_head');
    if (this.source !== null && this.source !== source) fail('source_head_changed');
    this.source = source; this.head = checked.head;
    if (number === null) {
      const rows = kind === 'milestone' ? reply.milestones : reply.issues;
      if (kind === 'milestone') {
        this.milestones += rows.length;
        if (this.milestones > this.caps.milestones) fail('milestone_limit');
        this.queue = rows.map(milestoneArchiveState);
      } else {
        this.issues += rows.length;
        if (this.issues > this.caps.issues) fail('issue_limit');
        this.queue = rows.map(issueArchiveState);
        for (const row of this.queue) if (row.milestone !== null) {
          const progress = this.progress.get(row.milestone);
          if (!progress) fail('unknown_milestone_membership');
          progress[row.state === 'open' ? 'open' : 'closed']++;
        }
      }
      this.listNext = reply.next_after;
      const declared = this.queue.reduce((n, row) => n + row.version, this.events);
      if (!Number.isSafeInteger(declared) || declared > this.caps.events) fail('event_limit');
      this.advance(kind); return;
    }
    const expected = this.queue[0];
    const state = kind === 'milestone' ? milestoneArchiveState : issueArchiveState;
    if (!reply.found || !equal(state(kind === 'milestone' ? reply.milestone : reply.issue), expected)) {
      fail('list_history_disagreement');
    }
    for (const event of reply.events) {
      if (kind === 'milestone') this.foldMilestone(number, event);
      else this.foldIssue(number, event);
      this.events++;
      if (this.events > this.caps.events) fail('event_limit');
    }
    if (reply.next_after_version !== null) this.next = { kind, number, after: reply.next_after_version };
    else {
      const folded = kind === 'milestone' ? { ...this.folded,
        open_issues: expected.open_issues, closed_issues: expected.closed_issues } : this.folded;
      if (!equal(folded, expected)) fail('history_state_disagreement');
      if (kind === 'milestone') this.progress.set(number, { expected, open: 0, closed: 0 });
      this.queue.shift(); this.folded = null; this.advance(kind);
    }
  }
  foldMilestone(number, event) {
    const { name, body_rendered: _rendered, ...fields } = event.action;
    const action = milestoneAction(name, fields);
    if (name === 'open') {
      this.folded = { number, version: 0, title: action.title, body: action.body, due_at: action.due_at ?? null,
        state: 'open', opened_by: event.actor, last_actor: event.actor };
      this.milestoneVersions.set(number, []);
    }
    const s = this.folded;
    if (!s) fail('missing_open');
    if (name === 'edit') for (const key of ['title', 'body', 'due_at']) if (Object.hasOwn(action, key)) s[key] = action[key];
    if (name === 'close' || name === 'reopen') {
      const next = name === 'close' ? 'closed' : 'open';
      if (s.state === next) fail('invalid_milestone_transition');
      s.state = next;
    }
    s.version = event.version; s.last_actor = event.actor;
    this.milestoneVersions.get(number).push(s.state);
  }
  foldIssue(number, event) {
    const { name, body_rendered: _rendered, ...fields } = event.action;
    const action = issueAction(name, fields);
    if (name === 'open') this.folded = { number, version: 0, title: action.title, body: action.body,
      labels: action.labels, state: 'open', opened_by: event.actor, last_actor: event.actor,
      comments: 0, assignees: [], locked: false, milestone: null };
    const s = this.folded;
    if (!s) fail('missing_open');
    if (name === 'edit') for (const key of ['title', 'body', 'labels']) if (Object.hasOwn(action, key)) s[key] = action[key];
    if (name === 'add-labels') s.labels = issueAction('edit', {
      labels: [...new Set([...s.labels, ...action.labels])],
    }).labels;
    if (name === 'comment') {
      if (s.locked) fail('comment_while_locked');
      s.comments++;
    }
    if (name === 'lock' || name === 'unlock') {
      const locked = name === 'lock';
      if (s.locked === locked) fail('invalid_lock_transition');
      s.locked = locked;
    }
    if (name === 'close' || name === 'reopen') s.state = name === 'close' ? 'closed' : 'open';
    if (name === 'assign') s.assignees = [...new Set([...s.assignees, ...action.assignees])].sort();
    if (name === 'unassign') s.assignees = s.assignees.filter(id => !action.assignees.includes(id));
    if (name === 'set-milestone') {
      const versions = this.milestoneVersions.get(action.milestone);
      if (!versions || versions[action.expected_milestone_version - 1] !== 'open') fail('invalid_milestone_selection');
      s.milestone = action.milestone;
    }
    if (name === 'clear-milestone') s.milestone = null;
    s.version = event.version; s.last_actor = event.actor;
    if (s.assignees.length > 16) fail('event_limit');
  }
  advance(kind) {
    if (this.queue.length) this.next = { kind, number: this.queue[0].number, after: 0 };
    else if (this.listNext !== null) this.next = { kind, number: null, after: this.listNext };
    else if (kind === 'milestone') this.next = { kind: 'issue', number: null, after: 0 };
    else {
      for (const { expected, open, closed } of this.progress.values()) {
        if (open !== expected.open_issues || closed !== expected.closed_issues) fail('milestone_progress_disagreement');
      }
      this.next = null;
    }
  }
}
