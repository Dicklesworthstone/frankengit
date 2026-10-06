import { ActivityClient } from './activity.mjs';

const shown = value => JSON.stringify(value).replace(/[\u202a-\u202e\u2066-\u2069]/g,
  char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
export function mountActivity(doc, options = {}) {
  const client = options.client ?? new ActivityClient({ href: options.href ?? globalThis.location.href });
  const ids = ['token', 'connect', 'disconnect', 'after', 'limit', 'load', 'next', 'refresh', 'cancel', 'save',
    'status', 'scope', 'snapshot', 'watermark', 'page-note', 'events'];
  const el = Object.fromEntries(ids.map(id => {
    const element = doc.getElementById(id); if (!element) throw new Error(`Missing activity control: ${id}`);
    return [id, element];
  }));
  let busy = false, revision = 0;
  const node = (tag, text) => { const element = doc.createElement(tag); if (text !== undefined) element.textContent = text; return element; };
  const status = text => { el.status.textContent = text; };
  function render() {
    const page = client.page, connected = client.connected;
    el.connect.disabled = busy; el.token.disabled = busy;
    for (const id of ['after', 'limit', 'load']) el[id].disabled = busy || !connected;
    el.next.disabled = busy || !connected || !page?.has_more;
    el.refresh.disabled = busy || !connected || !page;
    el.save.disabled = busy || !connected || !page;
    el.cancel.disabled = !busy; el.disconnect.disabled = !connected && !busy;
    el.events.setAttribute('aria-busy', String(busy)); el.events.replaceChildren();
    el.scope.textContent = page ? `Tenant ${shown(page.tenant_id)}; repository ${shown(page.repository_id)}; incarnation ${shown(page.repository_incarnation)}; ${page.object_format}. Granted families: ${[page.issues_read ? 'issues' : '', page.pulls_read ? 'pull requests' : ''].filter(Boolean).join(', ')}.` : 'No authenticated activity observation.';
    el.snapshot.textContent = page ? `Observed head ${shown(page.source_head)}\nSnapshot token ${page.snapshot_token}` : '';
    el.watermark.textContent = page ? `Resume after ${page.resume_after ?? '0'}${page.next_after !== null ? `; next page after ${page.next_after}` : ''}` : '';
    el['page-note'].textContent = page ? `${page.events.length} disclosed events in this page. ${page.has_more ? 'More canonical positions remain at this snapshot, even when this filtered page is empty.' : 'End of this observation, not proof that no newer activity exists.'} Other families and hidden-ref events are omitted; cursor gaps can reveal repository activity.` : '';
    if (!page) return;
    if (!page.events.length) {
      el.events.append(node('li', page.has_more ? 'No granted event was disclosed in this page. Continue with Next page.' : 'No granted event was disclosed in this page. Refresh checks after the retained watermark.'));
      return;
    }
    for (const event of page.events) {
      const item = node('li'), heading = node('h3', `${shown(event.aggregate)} · version ${event.aggregate_version}`);
      item.append(heading, node('p', `Cursor ${event.cursor} · native kind ${event.kind} · policy epoch ${event.policy_epoch}`),
        node('p', `Transaction ${shown(event.tx_id)}`));
      const frame = node('details');
      frame.append(node('summary', `Canonical event frame (${event.event_frame_hex.length / 2} bytes; opaque hexadecimal)`), node('pre', event.event_frame_hex));
      item.append(frame); el.events.append(item);
    }
  }
  async function perform(work) {
    if (busy) return;
    const version = ++revision; busy = true; status('Reading canonical activity; any displayed page is the previous observation.'); render();
    try {
      await work();
      if (version === revision) status('Activity page loaded. No repository state was changed.');
    } catch (error) {
      if (version === revision) status(`${error.message}${client.page ? ' The last successful page is still displayed.' : ''}`);
    } finally {
      if (version === revision) { busy = false; render(); }
    }
  }
  function disconnect() {
    revision++; busy = false; client.disconnect(); el.token.value = ''; el.after.value = '0';
    status('Disconnected. Credentials and activity observations cleared.'); render();
  }
  el.connect.addEventListener('click', () => {
    if (busy) return;
    revision++; const token = el.token.value; el.token.value = '';
    try { client.connect(token); status('Credential held in memory. Load a page to authenticate its activity grants.'); }
    catch (error) { status(error.message); }
    render();
  });
  el.disconnect.addEventListener('click', disconnect);
  el.cancel.addEventListener('click', () => {
    revision++; busy = false; client.cancel();
    status('Read cancelled. No repository mutation was submitted; any displayed page is the last successful observation.'); render();
  });
  el.load.addEventListener('click', () => perform(() => {
    if (!/^[1-9][0-9]{0,2}$/.test(el.limit.value)) throw new Error('Page size must be an integer from 1 to 100.');
    return client.open({ after: el.after.value, limit: Number(el.limit.value) });
  }));
  el.next.addEventListener('click', () => perform(() => client.next()));
  el.refresh.addEventListener('click', () => perform(() => client.refresh()));
  el.save.addEventListener('click', () => {
    if (busy || !client.connected) return;
    const page = client.page; if (!page) return;
    try {
      const text = JSON.stringify(page, null, 2), filename = 'frankengit-activity-page.json';
      if (options.savePage) options.savePage({ text, filename });
      else {
        const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
        try { const link = node('a'); link.href = url; link.download = filename; link.click(); }
        finally { setTimeout(() => URL.revokeObjectURL(url), 1000); }
      }
      status('Displayed page exported without credentials. It contains repository metadata and event frames; keep it secure.');
    } catch (error) { status(error.message); }
  });
  const events = options.events ?? globalThis;
  events.addEventListener?.('pagehide', disconnect);
  render(); return { client, disconnect, render };
}
if (typeof document !== 'undefined') mountActivity(document);
