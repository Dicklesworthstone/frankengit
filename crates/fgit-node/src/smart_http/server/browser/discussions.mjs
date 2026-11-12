// Standalone discussions use the shared transport and immutable retry custody.
// Their grant, aggregate, route and request-key domain remain independent.
import { IssueClient, MAX_FORM_BYTES, natural, snapshotToken } from './issues.mjs';

const encoder = new TextEncoder();
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const fail = message => { throw new Error(message); };
function object(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Invalid discussion API object.');
  return value;
}
function text(value, maximum, field, singleLine = false) {
  if (typeof value !== 'string' || value.length > maximum || encoder.encode(value).length > maximum ||
      /[\uD800-\uDFFF]/u.test(value) || value.includes('\0') ||
      (singleLine && (!value.trim() || /[\u0000-\u001f\u007f-\u009f]/u.test(value)))) fail(`Invalid or oversized ${field}.`);
  return value;
}
function opaque(value, field) { return text(value, 256, field, true); }
function identity(reply, previous) {
  object(reply);
  if (reply.schema_version !== 1 || reply.scope !== 'repository_discussions') fail('Unsupported discussion response profile.');
  const binding = { tenant: opaque(reply.tenant_id, 'tenant'), repository: opaque(reply.repository_id, 'repository') };
  if (previous && (binding.tenant !== previous.tenant || binding.repository !== previous.repository)) fail('Repository identity changed. Reconnect explicitly.');
  return binding;
}
export function discussionAction(name, fields) {
  object(fields);
  if (!['open', 'edit', 'comment', 'close', 'reopen', 'lock', 'unlock'].includes(name)) fail('Unsupported discussion action.');
  const allowed = ['open', 'edit'].includes(name) ? ['title', 'body'] : name === 'comment' ? ['body'] : [];
  if (Object.keys(fields).some(key => !allowed.includes(key))) fail('Unknown or inapplicable discussion field.');
  const checked = {};
  if (own(fields, 'title')) checked.title = text(fields.title, 256, 'title', true);
  if (own(fields, 'body')) checked.body = text(fields.body, 64 * 1024, 'body');
  if (name === 'open' && (!own(checked, 'title') || !own(checked, 'body'))) fail('Opening a discussion requires title and body.');
  if (name === 'edit' && !Object.keys(checked).length) fail('Select at least one discussion field to replace.');
  if (name === 'comment' && (!own(checked, 'body') || !checked.body.trim())) fail('Comment must not be empty.');
  return checked;
}
export function discussionMutationRequest(number, version, action, fields) {
  natural(number, 'discussion number', 1);
  const append = action === 'append-comment';
  if (append) {
    if (version !== null) fail('An append comment has no expected discussion version.');
  } else {
    natural(version, 'expected discussion version', 0, Number.MAX_SAFE_INTEGER - 1);
    if ((action === 'open') !== (version === 0)) fail('Only a new discussion uses expected version zero.');
  }
  // Append is a separate request profile, not a new canonical history action.
  // Legacy exact-version commands and their saved retry identities stay intact.
  const checked = discussionAction(append ? 'comment' : action, fields);
  const form = new URLSearchParams(append ? {} : { expected_version: String(version) });
  for (const name of ['title', 'body']) if (own(checked, name)) form.append(name, checked[name]);
  const body = form.toString();
  if (body.length > MAX_FORM_BYTES) fail('Encoded discussion form exceeds 256 KiB.');
  return { number, expected_version: version, action, fields: checked, body };
}
export function discussionState(row) {
  object(row);
  natural(row.number, 'discussion number', 1); natural(row.version, 'discussion version', 1);
  discussionAction('open', { title: row.title, body: row.body });
  if (!['open', 'closed'].includes(row.state) || typeof row.locked !== 'boolean') fail('Invalid discussion state.');
  opaque(row.opened_by, 'opening principal'); opaque(row.last_actor, 'last principal');
  natural(row.comments, 'comment count', 0, row.version - 1);
  return row;
}
export function discussionPage(reply, { after = 0, limit = 20, head = null, binding = null } = {}) {
  const observed = identity(reply, binding), snapshot = snapshotToken(reply.snapshot_token);
  if (head !== null && head !== snapshot) fail('Discussion snapshot moved. Reload explicitly.');
  if (reply.type !== 'discussion_page' || reply.after !== after || reply.limit !== limit ||
      !Array.isArray(reply.discussions) || reply.discussions.length > limit) fail('Invalid discussion page.');
  let previous = after;
  for (const row of reply.discussions) {
    discussionState(row);
    if (row.number <= previous) fail('Invalid discussion ordering.');
    previous = row.number;
  }
  if (reply.next_after !== null && (reply.discussions.length !== limit || reply.next_after !== previous)) fail('Invalid discussion continuation.');
  return { reply, binding: observed, head: snapshot };
}
export function discussionHistory(reply, number, { after = 0, limit = 20, head = null, binding = null } = {}) {
  const observed = identity(reply, binding), snapshot = snapshotToken(reply.snapshot_token);
  if (head !== null && head !== snapshot) fail('Discussion snapshot moved. Reload explicitly.');
  if (reply.type !== 'discussion_history' || reply.after_version !== after || reply.limit !== limit ||
      typeof reply.found !== 'boolean' || !Array.isArray(reply.events) || reply.events.length > limit) fail('Invalid discussion history.');
  if (!reply.found) {
    if (reply.discussion !== null || reply.events.length || reply.next_after_version !== null) fail('Invalid missing-discussion response.');
  } else {
    const row = discussionState(reply.discussion);
    if (row.number !== number) fail('Discussion number mismatch.');
    const remaining = Math.max(0, row.version - after), count = Math.min(remaining, limit);
    if (reply.events.length !== count || reply.next_after_version !== (remaining > count ? after + count : null)) fail('Incomplete discussion history or invalid continuation.');
    let state = null, locked = null, comments = after === 0 ? 0 : null;
    let title, body, openedBy, lastActor;
    reply.events.forEach((event, index) => {
      object(event); object(event.action); opaque(event.actor, 'event principal');
      if (event.version !== after + index + 1) fail('Discussion history contains a version gap.');
      const { name, ...fields } = event.action;
      if (own(fields, 'body_rendered')) {
        if (!own(fields, 'body')) fail('Rendered action has no canonical body.');
        delete fields.body_rendered;
      }
      discussionAction(name, fields);
      if ((event.version === 1) !== (name === 'open')) fail('Invalid discussion opening event position.');
      if (name === 'open') { state = 'open'; locked = false; openedBy = event.actor; }
      if (name === 'open' || name === 'edit') {
        if (own(fields, 'title')) title = fields.title;
        if (own(fields, 'body')) body = fields.body;
      } else if (name === 'close' || name === 'reopen') {
        const next = name === 'close' ? 'closed' : 'open';
        if (state === next) fail('Invalid discussion state transition.');
        state = next;
      } else if (name === 'lock' || name === 'unlock') {
        const next = name === 'lock';
        if (locked === next) fail('Invalid discussion lock transition.');
        locked = next;
      } else if (name === 'comment') {
        if (locked === true) fail('A locked discussion cannot receive comments.');
        if (comments !== null) comments += 1;
      }
      lastActor = event.actor;
    });
    if (reply.next_after_version === null && (
        (state !== null && state !== row.state) || (locked !== null && locked !== row.locked) ||
        (comments !== null && comments !== row.comments) || (title !== undefined && title !== row.title) ||
        (body !== undefined && body !== row.body) || (openedBy !== undefined && openedBy !== row.opened_by) ||
        (lastActor !== undefined && lastActor !== row.last_actor))) fail('Discussion state disagrees with its history.');
  }
  return { reply, binding: observed, head: snapshot };
}
const profile = Object.freeze({ kind: 'discussion', mutationRequest: discussionMutationRequest, page: discussionPage, history: discussionHistory });
export class DiscussionClient extends IssueClient {
  constructor(options) { super(options, profile); }
}
