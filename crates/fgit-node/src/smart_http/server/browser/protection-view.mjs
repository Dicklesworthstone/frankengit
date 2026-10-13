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

export function mountProtection(doc, { client, events = doc.defaultView } = {}) {
  if (!client) throw new Error('A native protection client is required.');
  const ids = ['connect', 'token', 'actor', 'reload', 'disconnect', 'status', 'snapshot', 'policy'];
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
  function clear() { ui.snapshot.textContent = ''; ui.policy.replaceChildren(); }
  function sync() {
    ui.reload.disabled = busy || !client.connected;
    ui.token.disabled = busy; ui.actor.disabled = busy;
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
      return;
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
  }
  async function run(work) {
    if (busy) return;
    const current = ++revision; busy = true; clear(); sync();
    ui.status.textContent = 'Reading the complete native protection policy…';
    try {
      const selected = await work();
      if (current !== revision) return;
      render(selected); ui.status.textContent = 'Complete native policy inspected. No transaction was created.';
    } catch (error) {
      if (current !== revision) return;
      clear(); ui.status.textContent = visible(error.message ?? 'Protection read failed.');
    } finally { if (current === revision) { busy = false; sync(); } }
  }
  const inspect = () => run(() => client.inspect());
  function disconnect() {
    revision++; busy = false; client.disconnect(); clear(); ui.token.value = ''; ui.actor.value = ''; sync();
    ui.status.textContent = 'Disconnected. Credential and displayed policy cleared.';
  }
  ui.connect.addEventListener('submit', event => {
    event.preventDefault(); const token = ui.token.value, actor = ui.actor.value; ui.token.value = '';
    return run(async () => { await client.connect(token, actor); return client.inspect(); });
  });
  ui.reload.addEventListener('click', inspect); ui.disconnect.addEventListener('click', disconnect);
  events?.addEventListener('pagehide', disconnect);
  clear(); sync(); return { client, inspect, disconnect };
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
