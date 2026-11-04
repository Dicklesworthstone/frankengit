// One explicitly selected artifact in one incarnation. Bytes become available
// only after the native metadata commitments and the whole payload agree.
import { Transport, copy, fail, integer } from './pulls-core.mjs';
import { ARTIFACT_BYTES, METADATA_BYTES, artifactId, artifactLocation, artifactMetadata,
  incarnationId, payloadPins, pinnedArtifactLink, preview, sameArtifact, sha256 } from './artifacts-protocol.mjs';

export class ArtifactClient {
  #transport; #crypto; #timeout; #maximum; #initial; #serial = 0; #operation = null;
  #incarnation = null; #scope = null; #selected = null; #bytes = null; #loading = null;
  constructor({ href, fetchImpl = globalThis.fetch, cryptoImpl = globalThis.crypto,
    timeoutMs = 30_000, maximumBytes = ARTIFACT_BYTES }) {
    const location = artifactLocation(href);
    this.#initial = location.selected; this.#crypto = cryptoImpl;
    this.#timeout = integer(timeoutMs, 'operation deadline', 1, 300_000);
    this.#maximum = integer(maximumBytes, 'browser artifact limit', 0, ARTIFACT_BYTES);
    this.#transport = new Transport({ href: location.href, pageSuffix: '/ui/artifacts/', fetchImpl, cryptoImpl, timeoutMs });
  }
  get connected() { return this.#transport.connected && this.#incarnation !== null; }
  get initialSelection() { return copy(this.#initial); }
  get maximumBytes() { return this.#maximum; }
  get state() {
    return copy({ expectedIncarnation: this.#incarnation, scope: this.#scope,
      artifact: this.#selected?.metadata ?? null, retention: this.#selected?.retention ?? null,
      artifactIdentityVerified: this.#selected?.artifactIdentityVerified === true,
      scopeCommitmentVerified: this.#selected?.scopeCommitmentVerified === true,
      receiptPinsMatched: this.#selected?.pins.payloadSha256 != null,
      payloadVerified: this.#bytes !== null,
      downloadAvailable: this.connected && this.#bytes !== null });
  }
  get preview() { return this.connected && this.#bytes !== null ? preview(this.#bytes) : null; }
  #clear() {
    if (this.#bytes !== null) this.#bytes.fill(0);
    if (this.#loading !== null) this.#loading.fill(0);
    this.#bytes = null; this.#loading = null; this.#selected = null;
  }
  cancelReads() {
    this.#serial++;
    const operation = this.#operation; this.#operation = null;
    if (operation) {
      clearTimeout(operation.timer); operation.reject(new Error('Artifact operation cancelled.'));
      if (operation.connect) { this.#transport.disconnect(); this.#scope = null; this.#incarnation = null; }
    }
    this.#transport.cancelReads(); this.#clear();
  }
  disconnect() {
    this.cancelReads(); this.#transport.disconnect(); this.#scope = null; this.#incarnation = null;
  }
  async #run(work, connect = false) {
    const serial = ++this.#serial;
    let reject;
    const cancelled = new Promise((_, refuse) => { reject = refuse; });
    const operation = { serial, reject, connect, timer: null }; this.#operation = operation;
    const checkpoint = () => {
      if (serial !== this.#serial || this.#operation !== operation) fail('Artifact operation superseded.');
      if (!connect && !this.connected) fail('Credential disconnected.');
    };
    operation.timer = setTimeout(() => {
      if (this.#operation !== operation) return;
      this.#serial++; this.#transport.cancelReads(); this.#clear();
      if (connect) { this.#transport.disconnect(); this.#scope = null; this.#incarnation = null; }
      reject(new Error('Artifact operation exceeded its deadline. Inspect explicitly to try again.'));
    }, this.#timeout);
    try { return await Promise.race([Promise.resolve().then(() => work(checkpoint)), cancelled]); }
    catch (error) {
      if (this.#operation === operation) {
        this.#clear();
        if (!this.#transport.connected) { this.#scope = null; this.#incarnation = null; }
      }
      throw error;
    } finally {
      clearTimeout(operation.timer);
      if (this.#operation === operation) this.#operation = null;
    }
  }
  async connect(token, expectedIncarnation) {
    this.disconnect();
    const incarnation = incarnationId(expectedIncarnation);
    if (this.#initial && this.#initial.incarnation !== incarnation) fail('The pinned link names another incarnation. Open the unpinned artifact page to select it explicitly.');
    return this.#run(async checkpoint => {
      checkpoint(); await this.#transport.connect(token); checkpoint(); this.#incarnation = incarnation;
      return this.state;
    }, true);
  }
  async inspect(id, expectedPayload = {}) {
    this.cancelReads();
    if (!this.connected) fail('Connect an artifact-read credential and expected incarnation first.');
    const selection = { id: artifactId(id), incarnation: this.#incarnation,
      scope: copy(this.#scope), pins: payloadPins(expectedPayload) };
    return this.#run(async checkpoint => {
      checkpoint();
      const response = await this.#transport.request(`artifacts/${selection.id}`, { maximum: METADATA_BYTES });
      checkpoint();
      const inspected = await artifactMetadata(response.value, selection, this.#crypto, checkpoint);
      checkpoint(); this.#scope = inspected.scope; this.#selected = { ...inspected, pins: selection.pins };
      return this.state;
    });
  }
  async verifyDownload() {
    const inspected = copy(this.#selected); this.cancelReads();
    if (!this.connected || !inspected) fail('Inspect the exact artifact before loading its bytes.');
    if (inspected.metadata.payload_bytes > this.#maximum) fail(`This artifact exceeds the browser limit of ${this.#maximum} bytes. Use the native artifact download client.`);
    const selected = { id: inspected.metadata.artifact_id, incarnation: this.#incarnation,
      scope: copy(this.#scope), pins: inspected.pins };
    return this.#run(async checkpoint => {
      let bytes = null, retained = false;
      try {
        checkpoint();
        // Recheck custody and incarnation immediately before requesting the bytes.
        const response = await this.#transport.request(`artifacts/${selected.id}`, { maximum: METADATA_BYTES });
        checkpoint();
        const current = await artifactMetadata(response.value, selected, this.#crypto, checkpoint);
        sameArtifact(inspected.metadata, current.metadata); checkpoint();
        const content = await this.#transport.request(`artifacts/${selected.id}/content`, {
          maximum: current.metadata.payload_bytes, binary: true });
        bytes = content.value; checkpoint(); this.#loading = bytes;
        if (bytes.byteLength !== current.metadata.payload_bytes) fail('Artifact content length differs from its verified metadata.');
        if (await sha256(bytes, this.#crypto, checkpoint) !== current.metadata.payload_sha256) fail('Artifact content SHA-256 differs from its verified metadata.');
        // The binary endpoint has no incarnation header. Require another exact
        // metadata observation before exposing bytes or offering a download.
        const after = await this.#transport.request(`artifacts/${selected.id}`, { maximum: METADATA_BYTES });
        checkpoint();
        const confirmed = await artifactMetadata(after.value, selected, this.#crypto, checkpoint);
        sameArtifact(current.metadata, confirmed.metadata); checkpoint();
        this.#selected = { ...confirmed, pins: selected.pins }; this.#bytes = bytes; this.#loading = null; retained = true;
        return this.state;
      } finally {
        if (!retained && bytes !== null) bytes.fill(0);
        if (this.#loading === bytes) this.#loading = null;
      }
    });
  }
  link() {
    if (!this.connected || !this.#selected) fail('Inspect an artifact before sharing its pinned link.');
    return pinnedArtifactLink(this.#transport.root, this.#selected.metadata);
  }
  download() {
    if (!this.connected || this.#bytes === null || !this.#selected) fail('No complete verified artifact is available for download.');
    return { blob: new Blob([this.#bytes], { type: 'application/octet-stream' }),
      filename: `artifact-${this.#selected.metadata.artifact_id}` };
  }
}
