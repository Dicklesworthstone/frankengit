// Native milestone metadata through the same exact-key custody and transport
// implementation as issues. The /ui/issues/ URL selects a repository only;
// milestone grants remain the explicitly scoped native issues-read/write grants.
import { IssueClient, MAX_FORM_BYTES, natural, snapshotToken } from './issues.mjs';

const encoder = new TextEncoder();
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const fail = message => { throw new Error(message); };
function object(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Invalid milestone API object.');
  return value;
}
function text(value, maximum, field, singleLine = false) {
  if (typeof value !== 'string' || value.length > maximum || encoder.encode(value).length > maximum ||
      /[\uD800-\uDFFF]/u.test(value) || value.includes('\0') ||
      (singleLine && (!value.trim() || /[\u0000-\u001f\u007f-\u009f]/u.test(value)))) fail(`Invalid or oversized ${field}.`);
  return value;
}
function opaque(value, field) { return text(value, 256, field, true); }
function due(value) { return value === null ? null : natural(value, 'milestone due date', 0, 253402300799); }
function identity(reply, previous) {
  object(reply);
  if (reply.schema_version !== 1 || reply.scope !== 'repository_milestones') fail('Unsupported milestone response profile.');
  const binding = { tenant: opaque(reply.tenant_id, 'tenant'), repository: opaque(reply.repository_id, 'repository') };
  if (previous && (binding.tenant !== previous.tenant || binding.repository !== previous.repository)) fail('Repository identity changed. Reconnect explicitly.');
  return binding;
}
export function milestoneAction(name, fields) {
  object(fields);
  if (!['open', 'edit', 'close', 'reopen'].includes(name)) fail('Unsupported milestone action.');
  const allowed = ['open', 'edit'].includes(name) ? ['title', 'body', 'due_at'] : [];
  if (Object.keys(fields).some(key => !allowed.includes(key))) fail('Unknown or inapplicable milestone field.');
  const checked = {};
  if (own(fields, 'title')) checked.title = text(fields.title, 256, 'title', true);
  if (own(fields, 'body')) checked.body = text(fields.body, 64 * 1024, 'body');
  if (own(fields, 'due_at')) checked.due_at = due(fields.due_at);
  if (name === 'open') {
    if (!own(checked, 'title') || !own(checked, 'body')) fail('Opening a milestone requires title and body.');
    checked.due_at ??= null;
  } else if (name === 'edit' && !Object.keys(checked).length) fail('Select at least one milestone field to replace.');
  return checked;
}
export function milestoneMutationRequest(number, version, action, fields) {
  natural(number, 'milestone number', 1);
  natural(version, 'expected milestone version', 0, Number.MAX_SAFE_INTEGER - 1);
  if ((action === 'open') !== (version === 0)) fail('Only a new milestone uses expected version zero.');
  const checked = milestoneAction(action, fields);
  const form = new URLSearchParams({ expected_version: String(version) });
  for (const name of ['title', 'body']) if (own(checked, name)) form.append(name, checked[name]);
  if (own(checked, 'due_at')) {
    if (checked.due_at !== null) form.append('due_at', String(checked.due_at));
    else if (action === 'edit') form.append('clear_due_at', 'true');
  }
  const body = form.toString();
  if (body.length > MAX_FORM_BYTES) fail('Encoded milestone form exceeds 256 KiB.');
  return { number, expected_version: version, action, fields: checked, body };
}
export function milestoneState(row) {
  object(row);
  natural(row.number, 'milestone number', 1); natural(row.version, 'milestone version', 1);
  milestoneAction('open', { title: row.title, body: row.body, due_at: row.due_at });
  if (!['open', 'closed'].includes(row.state)) fail('Invalid milestone state.');
  opaque(row.opened_by, 'opening principal'); opaque(row.last_actor, 'last principal');
  natural(row.open_issues, 'open issue count'); natural(row.closed_issues, 'closed issue count');
  natural(row.open_issues + row.closed_issues, 'total issue count');
  return row;
}
export function milestonePage(reply, { after = 0, limit = 20, head = null, binding = null } = {}) {
  const observed = identity(reply, binding), snapshot = snapshotToken(reply.snapshot_token);
  if (head !== null && head !== snapshot) fail('Milestone snapshot moved. Reload explicitly.');
  if (reply.type !== 'milestone_page' || reply.after !== after || reply.limit !== limit ||
      !Array.isArray(reply.milestones) || reply.milestones.length > limit) fail('Invalid milestone page.');
  let previous = after;
  for (const row of reply.milestones) {
    milestoneState(row);
    if (row.number <= previous) fail('Invalid milestone ordering.');
    previous = row.number;
  }
  if (reply.next_after !== null && (reply.milestones.length !== limit || reply.next_after !== previous)) fail('Invalid milestone continuation.');
  return { reply, binding: observed, head: snapshot };
}
export function milestoneHistory(reply, number, { after = 0, limit = 20, head = null, binding = null } = {}) {
  const observed = identity(reply, binding), snapshot = snapshotToken(reply.snapshot_token);
  if (head !== null && head !== snapshot) fail('Milestone snapshot moved. Reload explicitly.');
  if (reply.type !== 'milestone_history' || reply.after_version !== after || reply.limit !== limit ||
      typeof reply.found !== 'boolean' || !Array.isArray(reply.events) || reply.events.length > limit) fail('Invalid milestone history.');
  if (!reply.found) {
    if (reply.milestone !== null || reply.events.length || reply.next_after_version !== null) fail('Invalid missing-milestone response.');
  } else {
    const row = milestoneState(reply.milestone);
    if (row.number !== number) fail('Milestone number mismatch.');
    const remaining = Math.max(0, row.version - after), count = Math.min(remaining, limit);
    if (reply.events.length !== count || reply.next_after_version !== (remaining > count ? after + count : null)) fail('Incomplete milestone history or invalid continuation.');
    let state = null;
    reply.events.forEach((event, index) => {
      object(event); object(event.action); opaque(event.actor, 'event principal');
      if (event.version !== after + index + 1) fail('Milestone history contains a version gap.');
      const { name, ...fields } = event.action;
      if (own(fields, 'body_rendered')) {
        if (!own(fields, 'body')) fail('Rendered action has no canonical body.');
        delete fields.body_rendered;
      }
      milestoneAction(name, fields);
      if ((event.version === 1) !== (name === 'open')) fail('Invalid milestone opening event position.');
      if (name === 'open') state = 'open';
      else if (name === 'close' || name === 'reopen') {
        const next = name === 'close' ? 'closed' : 'open';
        if (state === next) fail('Invalid milestone state transition.');
        state = next;
      }
    });
    if (reply.next_after_version === null && state !== null && state !== row.state) fail('Milestone state disagrees with its history.');
  }
  return { reply, binding: observed, head: snapshot };
}
const profile = Object.freeze({ kind: 'milestone', mutationRequest: milestoneMutationRequest, page: milestonePage, history: milestoneHistory });
export class MilestoneClient extends IssueClient {
  constructor(options) { super(options, profile); }
}
