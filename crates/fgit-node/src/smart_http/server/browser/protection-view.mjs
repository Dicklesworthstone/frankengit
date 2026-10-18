// Independent protection administration uses the existing native protection
// client. Shell coordinates are not capabilities or repository authority.
const SUFFIX = '/ui/protection/';
const visible = value => String(value).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
  character => `\\u{${character.codePointAt(0).toString(16)}}`);

// The existing client accepts the PR shell coordinate, but contacts only the
// repository's protection/outcomes API. Keep the exact same origin and route
// so receipts have one identity across both shells; never navigate to the PR
// shell or require its profile. This adapter does not add a transport route.
export function protectionClientHref(href) {
  if (typeof href !== 'string' || href.length > 8192) throw new Error('Invalid protection page address.');
  const page = new URL(href);
  if (!['https:', 'http:'].includes(page.protocol) || page.username || page.password || page.search || page.hash ||
      !page.pathname.endsWith(SUFFIX)) throw new Error('Open the exact repository /ui/protection/ endpoint.');
  if (page.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(page.hostname)) throw new Error('Use HTTPS outside trusted loopback.');
  const route = page.pathname.slice(0, -SUFFIX.length);
  if (!/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(route) ||
      route.split('/').some(part => ['.', '..'].includes(part))) throw new Error('Invalid repository route.');
  return `${page.origin}${route}/ui/pulls/`;
}
export function referenceLabel(encoded) {
  if (typeof encoded !== 'string' || !/^(?:[0-9a-f]{2}){1,1024}$/.test(encoded)) throw new Error('Invalid reference bytes.');
  const bytes = Uint8Array.from(encoded.match(/../g), pair => Number.parseInt(pair, 16));
  try { return visible(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { return '[Non-UTF-8 reference; use its exact hex bytes.]'; }
}

export function editorPolicy(administrators, rules) {
  const lines = (value, maximum, count) => {
    if (typeof value !== 'string' || value.length > maximum) throw new Error('Protection editor exceeds its input limit.');
    const rows = value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    if (rows.length > count) throw new Error('Too many protection editor rows.');
    return rows;
  };
  return { administrators: lines(administrators, 2048, 32), branches: lines(rules, 256 * 1024, 64).map(line => {
    const fields = line.split(/\s+/u);
    if (fields.length !== 2) throw new Error('Each rule needs exact reference hex, a space, and comma-separated reviewer IDs.');
    const reviewers = fields[1].split(',');
    if (reviewers.length > 32 || reviewers.some(person => person === '')) throw new Error('Choose 1 through 32 reviewers for each rule.');
    return { reference_hex: fields[0], required_reviewers: reviewers };
  }) };
}
export function mountProtection(doc, { client, events = doc.defaultView } = {}) {
  if (!client) throw new Error('A native protection client is required.');
  const ids = ['connect', 'token', 'actor', 'recovery-only', 'reload', 'disconnect', 'status', 'snapshot', 'policy',
    'edit', 'administrators', 'rules', 'clear', 'prepare', 'confirm', 'ownership-confirm', 'send', 'retry',
    'lookup', 'discard', 'export', 'restore', 'receipt', 'preview', 'terminal'];
  const ui = Object.fromEntries(ids.map(id => {
    const element = doc.getElementById(`protection-${id}`);
    if (!element) throw new Error(`Missing protection control ${id}`);
    return [id, element];
  }));
  let revision = 0, busy = false;
  const node = (tag, content) => {
    const element = doc.createElement(tag);
    if (content !== undefined) element.textContent = visible(content);
    return element;
  };
  const say = message => { ui.status.textContent = visible(message); };
  function clear() { ui.snapshot.textContent = ''; ui.policy.replaceChildren(); }
  function clearEditor() { ui.administrators.value = ''; ui.rules.value = ''; ui.clear.checked = false; }
  function unconfirm() { ui.confirm.checked = false; ui['ownership-confirm'].checked = false; }
  function removesActor(pending) { return pending && !pending.intent.replacement.administrators.includes(pending.intent.principal); }
  function sync() {
    const pending = client.pending, working = busy || client.busy;
    const ordinary = client.connected && !client.recoveryOnly;
    const editable = ordinary && !pending && !working && Boolean(client.observed?.policy);
    ui.reload.disabled = !ordinary || Boolean(pending) || working;
    for (const id of ['token', 'actor', 'recovery-only']) ui[id].disabled = working;
    for (const id of ['administrators', 'rules', 'clear', 'prepare']) ui[id].disabled = !editable;
    ui.confirm.disabled = !ordinary || !pending || working;
    ui['ownership-confirm'].disabled = !ordinary || !removesActor(pending) || working;
    const confirmed = ui.confirm.checked && (!removesActor(pending) || ui['ownership-confirm'].checked);
    const canSend = ordinary && pending && !working && confirmed;
    ui.send.disabled = !canSend || pending.sent || pending.exported;
    ui.retry.disabled = !canSend || (!pending.sent && !pending.exported);
    ui.lookup.disabled = !client.connected || !pending || working;
    ui.discard.disabled = !ordinary || !pending || pending.sent || pending.exported || working;
    ui.export.disabled = !pending || working;
    ui.restore.disabled = !client.connected || Boolean(pending) || working;
  }
  function renderPending() {
    const pending = client.pending;
    ui.preview.textContent = '';
    if (!pending || !client.connected) return;
    const { intent } = pending;
    ui.preview.append(node('h2', 'Frozen complete replacement'), node('p', `Principal: ${intent.principal}`),
      node('p', `Original key: ${intent.key}`), node('p', `Expected version: ${intent.source.version}; epoch: ${intent.source.epoch}`),
      node('p', `Original authority snapshot: ${intent.source.head}`),
      node('p', pending.sent || pending.exported ? 'Submission may have occurred. Resolve only this original request and key.' : 'Not submitted or exported by this client.'),
      node('p', client.recoveryOnly ? 'Recovery-only credential: no reads, edits, or resubmission.' : 'Sending never reads the editable form again.'),
      node('pre', JSON.stringify(intent.replacement)));
    if (removesActor(pending)) ui.preview.append(node('p', 'WARNING: this replacement removes the submitting principal from the administrator set. A separate acknowledgment is required.'));
  }
  function render(selected) {
    const { scope, head, version, epoch, policy } = selected;
    const table = node('dl');
    for (const [label, value] of Object.entries({ Tenant: scope.tenant, Repository: scope.repository,
      Incarnation: scope.incarnation, 'Object format': scope.format, 'Authority snapshot': head,
      'Policy version': version, 'Policy epoch': epoch })) table.append(node('dt', label), node('dd', value));
    ui.snapshot.append(table);
    if (policy === null) {
      ui.policy.append(node('p', 'Review protection is not installed. Initial administrator bootstrap is local-only.'));
      clearEditor(); return;
    }
    ui.policy.append(node('h2', policy.branches.length ? 'Required-review protection enabled' : 'Review protection disabled; administrators retained'),
      node('h3', 'Policy administrators'));
    for (const person of policy.administrators) ui.policy.append(node('p', person));
    for (const branch of policy.branches) {
      const section = node('article');
      section.append(node('h3', referenceLabel(branch.reference_hex)), node('p', `Exact reference bytes: ${branch.reference_hex}`),
        node('p', 'Every listed principal must approve the exact candidate. The PR opener and merge submitter cannot satisfy these requirements.'));
      for (const person of branch.required_reviewers) section.append(node('p', person));
      ui.policy.append(section);
    }
    ui.administrators.value = policy.administrators.join('\n');
    ui.rules.value = policy.branches.map(branch => `${branch.reference_hex} ${branch.required_reviewers.join(',')}`).join('\n');
    ui.clear.checked = false;
  }
  async function run(work, success, message) {
    if (busy || client.busy) return;
    const current = ++revision; busy = true; unconfirm(); sync(); say(message);
    const check = () => { if (current !== revision) throw new Error('Protection operation superseded.'); };
    try {
      const result = await work(check); check(); success(result);
    } catch (error) {
      if (current === revision) {
        if (!client.pending) { clear(); clearEditor(); }
        if (!client.connected) { clear(); clearEditor(); ui.actor.value = ''; ui.receipt.value = ''; }
        say(error.outcomeUnknown ? 'Outcome unknown. Preserve the original receipt and key; inspect its outcome or explicitly retry unchanged.' : error.message ?? 'Protection operation failed.');
      }
    } finally {
      if (current === revision) { busy = false; unconfirm(); renderPending(); }
      // An old request may finish draining after disconnect. Enable current
      // controls without allowing its late content to replace the current view.
      sync();
    }
  }
  const inspect = () => {
    if (client.pending || client.recoveryOnly) { say('Resolve the original request before inspecting a new policy.'); return; }
    return run(() => { clear(); clearEditor(); return client.load(); }, selected => {
      render(selected); say('Complete native policy inspected. No transaction was created.');
    }, 'Reading the complete native protection policy…');
  };
  const prepare = () => run(() => client.stage(editorPolicy(ui.administrators.value, ui.rules.value), ui.clear.checked), () => {
    ui.terminal.textContent = ''; ui.receipt.value = ''; say('Replacement frozen, not submitted. Review the complete policy and confirm explicitly.');
  }, 'Preparing one exact policy replacement without publication…');
  function settle(result) {
    if (!result.terminal) { say(`Original request remains unresolved (${result.state}). Absence does not prove non-commit.`); return; }
    clear(); clearEditor(); ui.receipt.value = '';
    ui.terminal.textContent = JSON.stringify(result);
    say(result.outcome === 'committed' ? 'Native replacement committed. This is not delivery acknowledgment; inspect current policy explicitly.'
      : `Native replacement refused (${result.refusal}). Inspect current policy before preparing a different request.`);
  }
  function send(retry = false) {
    const pending = client.pending;
    if (client.recoveryOnly || !pending || !ui.confirm.checked || (removesActor(pending) && !ui['ownership-confirm'].checked) ||
        Boolean(pending.sent || pending.exported) !== retry) { say('Confirm the frozen request, including administrator removal, before this submission.'); return; }
    return run(() => client.send(), settle, 'Submitting the original policy replacement and key…');
  }
  const recover = () => run(() => client.recover(), settle, 'Looking up the original key without reexecuting its command…');
  function exportReceipt() {
    if (busy || client.busy) return;
    try { ui.receipt.value = client.exportReceipt(); unconfirm(); renderPending(); sync(); say('Save this token-free receipt securely. It includes private policy data and the original recovery key; it has not been submitted automatically.'); }
    catch (error) { say(error.message); }
  }
  const restore = () => run(() => client.restoreReceipt(ui.receipt.value), () => {
    clear(); clearEditor(); ui.terminal.textContent = ''; say('Original receipt restored without submission. Look up its original outcome; only the original credential can resubmit.');
  }, 'Checking the receipt against its original route, principal, command and key…');
  function disconnect() {
    revision++; busy = false; client.disconnect(); clear(); clearEditor(); unconfirm();
    ui.token.value = ''; ui.actor.value = ''; ui.receipt.value = ''; ui.preview.textContent = ''; ui.terminal.textContent = '';
    ui['recovery-only'].checked = false; sync();
    say(client.pending ? 'Disconnected. Credential and displayed policy cleared. An unresolved request is retained; export it before leaving.' : 'Disconnected. Credential and displayed policy cleared.');
  }
  ui.connect.addEventListener('submit', event => {
    event.preventDefault(); const token = ui.token.value, actor = ui.actor.value, recoveryOnly = ui['recovery-only'].checked; ui.token.value = '';
    return run(() => { clear(); clearEditor(); ui.terminal.textContent = ''; return client.connect(token, actor, { recoveryOnly }); }, () => {
      say(client.recoveryOnly ? 'Recovery-only credential selected. Restore or look up the original receipt; resubmission is disabled.'
        : 'Credential selected. Inspect policy explicitly or restore the original receipt; native authorization occurs on the API request.');
    }, 'Selecting the explicit protection principal and credential…');
  });
  ui.edit.addEventListener('submit', event => { event.preventDefault(); return prepare(); });
  ui.confirm.addEventListener('change', sync); ui['ownership-confirm'].addEventListener('change', sync);
  ui.send.addEventListener('click', () => send()); ui.retry.addEventListener('click', () => send(true));
  ui.lookup.addEventListener('click', recover); ui.export.addEventListener('click', exportReceipt); ui.restore.addEventListener('click', restore);
  ui.discard.addEventListener('click', () => {
    if (busy || client.busy) return;
    try { client.discardUnsent(); unconfirm(); ui.receipt.value = ''; renderPending(); sync(); say('Never-sent, never-exported draft discarded.'); }
    catch (error) { say(error.message); }
  });
  ui.reload.addEventListener('click', inspect); ui.disconnect.addEventListener('click', disconnect);
  events?.addEventListener('beforeunload', event => { if (client.pending) { event.preventDefault(); event.returnValue = ''; } });
  events?.addEventListener('pagehide', disconnect);
  clear(); clearEditor(); unconfirm(); renderPending(); sync();
  return { client, inspect, prepare, send, recover, restore, exportReceipt, disconnect };
}
export async function startProtection(doc, options = {}) {
  const href = protectionClientHref(options.href ?? globalThis.location.href);
  // Load the actual shared protocol implementation, not the PR page controller.
  const { ProtectionClient } = await import('./pulls-actions.mjs');
  const client = new ProtectionClient({ href, fetchImpl: options.fetchImpl, cryptoImpl: options.cryptoImpl });
  return mountProtection(doc, { ...options, client });
}
if (typeof document !== 'undefined') void startProtection(document).catch(() => {
  const status = document.getElementById('protection-status');
  if (status) status.textContent = 'Protection administration could not start. No request was submitted.';
});
