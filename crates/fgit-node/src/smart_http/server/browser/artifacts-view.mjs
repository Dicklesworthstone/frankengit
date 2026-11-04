import { ArtifactClient } from './artifacts.mjs';
import { NATIVE_ARTIFACT_BYTES, payloadPins, visible } from './artifacts-protocol.mjs';

const KINDS = { ci_artifact: 'CI artifact', build_log: 'Build log', release_asset: 'Release asset',
  sbom: 'Software bill of materials', signature: 'Signature', provenance: 'Provenance', git_lfs: 'Git LFS payload' };
export function inputPins(sha256, bytes) {
  if (sha256 === '' && bytes === '') return payloadPins();
  if (typeof sha256 !== 'string' || sha256.length !== 64 || typeof bytes !== 'string' || bytes.length > 8 ||
      !/^(0|[1-9][0-9]*)$/.test(bytes) || Number(bytes) > NATIVE_ARTIFACT_BYTES) {
    throw new Error('Supply an exact payload SHA-256 and canonical byte count together, or leave both empty.');
  }
  return payloadPins({ payloadSha256: sha256, payloadBytes: Number(bytes) });
}
export function mountArtifacts(doc, options = {}) {
  const client = options.client ?? new ArtifactClient({ href: options.href ?? globalThis.location.href });
  const events = options.events ?? globalThis, urlApi = options.urlApi ?? globalThis.URL;
  const ids = ['artifact-connection','artifact-token','artifact-incarnation','artifact-connect','artifact-disconnect',
    'artifact-connection-state','artifact-selection','artifact-id','artifact-payload-sha256','artifact-payload-bytes',
    'artifact-inspect','artifact-cancel','artifact-status','artifact-summary','artifact-details','artifact-identities',
    'artifact-link','artifact-verify','artifact-download','artifact-limit','artifact-preview-label','artifact-preview'];
  const c = Object.fromEntries(ids.map(id => {
    const element = doc.getElementById(id); if (!element) throw new Error(`Missing artifact control ${id}.`); return [id, element];
  }));
  let generation = 0, busy = false, disposed = false, downloadUrl = null, downloadTimer = null;
  const listeners = [];
  const listen = (target, event, fn) => { target.addEventListener(event, fn); listeners.push([target, event, fn]); };
  const node = (tag, value) => { const element = doc.createElement(tag); if (value !== undefined) element.textContent = visible(value); return element; };
  const status = value => { c['artifact-status'].textContent = visible(value); };
  function releaseDownload() {
    clearTimeout(downloadTimer); downloadTimer = null;
    if (downloadUrl !== null) urlApi.revokeObjectURL(downloadUrl);
    downloadUrl = null;
  }
  function clearInputs() {
    for (const id of ['artifact-token','artifact-incarnation','artifact-id','artifact-payload-sha256','artifact-payload-bytes']) c[id].value = '';
  }
  function showFacts(parent, facts) {
    const list = node('dl');
    for (const [label, value] of facts) list.append(node('dt', label), node('dd', value));
    parent.append(list);
  }
  function render() {
    const state = client.state, artifact = state.artifact, connected = client.connected && !disposed;
    c['artifact-connect'].disabled = busy || disposed;
    c['artifact-inspect'].disabled = busy || !connected;
    c['artifact-cancel'].disabled = !busy && !artifact;
    c['artifact-verify'].disabled = busy || !connected || !artifact || artifact.payload_bytes > client.maximumBytes;
    c['artifact-download'].disabled = busy || !connected || !state.downloadAvailable;
    c['artifact-connection-state'].textContent = connected
      ? `Connected locally for incarnation ${state.expectedIncarnation}. Each read must pass server authorization.` : 'Disconnected. No credential is active.';
    c['artifact-limit'].textContent = `The browser loads at most ${client.maximumBytes.toLocaleString('en-US')} bytes (16 MiB by default). Larger retained artifacts can be inspected here and downloaded with the native artifact client. Loading and verification share one deadline.`;
    c['artifact-summary'].replaceChildren(); c['artifact-identities'].replaceChildren();
    c['artifact-details'].hidden = !artifact;
    c['artifact-link'].hidden = !artifact; c['artifact-link'].removeAttribute('href');
    c['artifact-preview'].hidden = true; c['artifact-preview'].textContent = ''; c['artifact-preview-label'].textContent = '';
    if (!artifact) return;
    showFacts(c['artifact-summary'], [['Kind', KINDS[artifact.kind]], ['Size', `${artifact.payload_bytes.toLocaleString('en-US')} bytes`],
      ['Declared media type', artifact.media_type], ['Retention policy (declared, not enforced)', state.retention],
      ['Verification', state.payloadVerified ? 'Complete payload length and SHA-256 verified.' : 'Metadata identity and custody namespace verified. Payload has not been loaded.'],
      ['Independent receipt pins', state.receiptPinsMatched ? 'Payload hash and byte count match the supplied pins.' : 'No additional payload pins supplied.']]);
    if (artifact.payload_bytes > client.maximumBytes) c['artifact-summary'].append(node('p', 'This artifact exceeds the browser download limit. Use the native artifact download client.'));
    showFacts(c['artifact-identities'], [['Artifact ID', artifact.artifact_id], ['Payload SHA-256', artifact.payload_sha256],
      ['Tenant', artifact.tenant_id], ['Repository', artifact.repository_id], ['Repository incarnation', artifact.repository_incarnation_id],
      ['Custody namespace SHA-256', artifact.scope_sha256], ['Build capsule assertion', artifact.build_capsule_sha256 ?? 'None retained'],
      ['Check receipt assertion', artifact.check_receipt_sha256 ?? 'None retained'], ['Source RCR assertion', artifact.source_rcr_sha256 ?? 'None retained']]);
    c['artifact-identities'].append(node('p', 'These retained provenance assertions are not authenticated proof of their producer or of a passing check.'));
    c['artifact-link'].href = client.link();
    const prefix = client.preview;
    if (prefix) {
      c['artifact-preview'].hidden = false; c['artifact-preview'].textContent = prefix.text;
      c['artifact-preview-label'].textContent = `Verified byte preview: ${prefix.shownBytes.toLocaleString('en-US')} of ${prefix.totalBytes.toLocaleString('en-US')} bytes${prefix.clipped ? ' (preview clipped)' : ''}. Controls and non-text bytes are escaped.`;
    }
  }
  async function perform(work) {
    if (busy || disposed) return;
    const started = ++generation; busy = true; releaseDownload(); render();
    const current = () => generation === started && !disposed;
    try { await work(current); }
    catch (error) { if (current()) status(error.message); }
    finally {
      if (current()) {
        busy = false;
        if (!client.connected) { clearInputs(); releaseDownload(); }
        render();
      }
    }
  }
  function disconnect() {
    generation++; busy = false; client.disconnect(); releaseDownload(); clearInputs(); render();
    status('Disconnected. Credential, metadata, preview and download bytes cleared.');
  }
  function selectionChanged() {
    generation++; busy = false; client.cancelReads(); releaseDownload(); render();
    status('Selection changed. Inspect this exact artifact and any receipt pins explicitly.');
  }
  for (const id of ['artifact-connection','artifact-selection']) listen(c[id], 'submit', event => event.preventDefault());
  listen(c['artifact-connect'], 'click', () => {
    const token = c['artifact-token'].value, incarnation = c['artifact-incarnation'].value; c['artifact-token'].value = '';
    return perform(async current => {
      const connection = client.connect(token, incarnation); render();
      await connection; if (current()) status('Credential connected locally. Inspect an artifact to authorize its read.');
    });
  });
  listen(c['artifact-disconnect'], 'click', disconnect);
  for (const id of ['artifact-token','artifact-incarnation']) listen(c[id], 'input', () => {
    generation++; busy = false; client.disconnect(); releaseDownload(); render(); status('Connection details changed. Connect explicitly.');
  });
  for (const id of ['artifact-id','artifact-payload-sha256','artifact-payload-bytes']) listen(c[id], 'input', selectionChanged);
  listen(c['artifact-cancel'], 'click', () => { selectionChanged(); status('Read cancelled. Metadata, preview and download bytes cleared.'); });
  listen(c['artifact-inspect'], 'click', () => perform(async current => {
    // Discard the old result even when a newly typed pin is malformed.
    client.cancelReads(); render();
    const pins = inputPins(c['artifact-payload-sha256'].value, c['artifact-payload-bytes'].value);
    await client.inspect(c['artifact-id'].value, pins);
    if (current()) status('Artifact metadata and namespace commitments verified. Load its bytes explicitly to verify the payload.');
  }));
  listen(c['artifact-verify'], 'click', () => perform(async current => {
    const verification = client.verifyDownload(); render();
    await verification; if (current()) status('Complete artifact bytes verified. Preview and binary download are ready.');
  }));
  listen(c['artifact-download'], 'click', () => {
    if (busy || disposed) return;
    try {
      const { blob, filename } = client.download(); releaseDownload();
      downloadUrl = urlApi.createObjectURL(blob);
      const link = node('a'); link.href = downloadUrl; link.download = filename;
      try { doc.body.append(link); link.click(); } finally { link.remove(); }
      downloadTimer = setTimeout(releaseDownload, 30_000);
      status('Verified artifact offered as a binary download.');
    } catch (error) { releaseDownload(); status(error.message); }
  });
  listen(events, 'pagehide', disconnect);
  listen(events, 'hashchange', () => { disconnect(); status('Pinned link changed. Reload this page to select its artifact and incarnation.'); });
  const initial = client.initialSelection;
  if (initial) { c['artifact-id'].value = initial.id; c['artifact-incarnation'].value = initial.incarnation; }
  render();
  return { client, disconnect, destroy() {
    if (disposed) return; disposed = true; disconnect();
    for (const [target, event, listener] of listeners) target.removeEventListener(event, listener);
  } };
}
if (typeof document !== 'undefined') {
  try { mountArtifacts(document); }
  catch { document.getElementById('artifact-status').textContent = 'Unable to open this artifact page. Use an exact repository URL and a valid pinned artifact link.'; }
}
