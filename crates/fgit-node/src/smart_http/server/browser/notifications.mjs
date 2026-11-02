// Native self-only issue inbox. Preferences are sealed commands, never local
// unread flags. The shared client retains exact request keys after ambiguity.
import { IssueClient, natural, snapshotToken } from './issues.mjs';
const fail = message => { throw new Error(message); };
const object = value => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Invalid notification object.');
  return value;
};
const id = (value, field) => {
  if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('Invalid ' + field + '.');
  return value;
};
const optionalVersion = (value, field, maximum) => value === null ? null : natural(value, field, 1, maximum);
const reasons = ['author', 'participant', 'assignee', 'subscribed'];

export function notificationMutationRequest(number, version, action, fields = {}, binding = null) {
  natural(number, 'issue number', 1);
  natural(version, 'preference version', 0, Number.MAX_SAFE_INTEGER - 1);
  object(fields);
  if (!['subscribe', 'mute', 'automatic', 'read', 'unread'].includes(action)) fail('Unsupported notification action.');
  const keys = Object.keys(fields);
  if (action === 'read' ? keys.length !== 1 || keys[0] !== 'read_through' : keys.length !== 0) fail('Unknown or inapplicable notification field.');
  const checked = action === 'read' ? { read_through: natural(fields.read_through, 'read-through version', 1) } : {};
  object(binding);
  const form = new URLSearchParams({ expected_version: String(version),
    expected_principal: id(binding.principal, 'expected principal'), expected_incarnation: id(binding.incarnation, 'expected incarnation') });
  if (action === 'read') form.set('read_through', String(checked.read_through));
  return { number, expected_version: version, action, fields: checked, body: form.toString() };
}
function identity(reply, previous) {
  object(reply);
  if (reply.schema_version !== 1) fail('Unsupported notification response version.');
  const binding = { tenant: id(reply.tenant_id, 'tenant'), repository: id(reply.repository_id, 'repository'),
    principal: id(reply.principal_id, 'principal'), incarnation: id(reply.repository_incarnation, 'incarnation') };
  if (previous && Object.keys(binding).some(key => previous[key] !== binding[key])) fail('Notification repository or recipient changed. Reconnect explicitly.');
  const positions = object(reply.source_positions);
  natural(positions.authority_head_generation, 'authority head generation', 1);
  if (positions.complete !== true || ['forge_position_root', 'outbox_root'].some(key =>
    typeof positions[key] !== 'string' || !positions[key].length || positions[key].length > 256 || /\s/.test(positions[key]))) fail('Incomplete notification source positions.');
  return binding;
}
export function notificationState(row) {
  object(row);
  natural(row.number, 'issue number', 1); natural(row.issue_version, 'issue version', 1);
  if (typeof row.title !== 'string' || !row.title.trim() || new TextEncoder().encode(row.title).length > 256 ||
      /[\u0000-\u001f\u007f-\u009f\uD800-\uDFFF]/u.test(row.title)) fail('Invalid issue title.');
  if (!['open', 'closed'].includes(row.state) || !['automatic', 'subscribed', 'muted'].includes(row.mode)) fail('Invalid notification state.');
  optionalVersion(row.preference_version, 'preference version', Number.MAX_SAFE_INTEGER);
  optionalVersion(row.read_through, 'read-through version', row.issue_version);
  optionalVersion(row.latest_other_version, 'latest other-actor version', row.issue_version);
  if (row.preference_version === null && (row.mode !== 'automatic' || row.read_through !== null)) fail('Implicit preferences were changed.');
  if (row.unread !== ((row.latest_other_version ?? 0) > (row.read_through ?? 0))) fail('Unread status disagrees with canonical versions.');
  if (!Array.isArray(row.reasons) || row.reasons.length > reasons.length ||
      row.reasons.some((reason, index) => !reasons.includes(reason) || (index && reasons.indexOf(row.reasons[index - 1]) >= reasons.indexOf(reason))) ||
      row.reasons.includes('subscribed') !== (row.mode === 'subscribed')) fail('Invalid notification reasons.');
  return row;
}
export function notificationPage(reply, { after = 0, limit = 20, head = null, binding = null, unreadOnly = false, includeMuted = false } = {}) {
  const observed = identity(reply, binding), snapshot = snapshotToken(reply.snapshot_token);
  if (head !== null && head !== snapshot) fail('Notification snapshot moved. Reload explicitly.');
  if (reply.type !== 'notification_page' || reply.after !== after || reply.limit !== limit ||
      reply.unread_only !== unreadOnly || reply.include_muted !== includeMuted || !Array.isArray(reply.threads) || reply.threads.length > limit) fail('Invalid notification page.');
  let previous = after;
  for (const row of reply.threads) {
    notificationState(row);
    if (row.number <= previous || (!includeMuted && row.mode === 'muted') || (unreadOnly && !row.unread) ||
        (!row.reasons.length && row.mode !== 'muted')) fail('Unordered or nonmatching notification thread.');
    previous = row.number;
  }
  if (reply.next_after !== null && (reply.threads.length !== limit || reply.next_after !== previous)) fail('Invalid notification continuation.');
  return { reply, binding: observed, head: snapshot };
}
export function notificationThread(reply, number, { head = null, binding = null } = {}) {
  const observed = identity(reply, binding), snapshot = snapshotToken(reply.snapshot_token);
  if (head !== null && head !== snapshot) fail('Notification snapshot moved. Reload explicitly.');
  if (reply.type !== 'notification_thread' || typeof reply.found !== 'boolean') fail('Invalid notification thread response.');
  if (reply.found) {
    notificationState(reply.thread);
    if (reply.thread.number !== number) fail('Notification issue number changed.');
  } else if (reply.thread !== null) fail('Missing notification issue has state.');
  return { reply, binding: observed, head: snapshot };
}
const profile = Object.freeze({ kind: 'notification', mutationRequest: notificationMutationRequest, page: notificationPage, history: notificationThread });
export class NotificationClient extends IssueClient {
  constructor(options) { super(options, profile); }
}
