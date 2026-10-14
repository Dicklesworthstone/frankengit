// Immutable local page archive. This is a derived consumer checkpoint, never
// repository authority or an acknowledgement of an external webhook effect.
import { constants } from 'node:fs';
import { lstat, open, opendir, mkdir, mkdtemp, rename, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { EVENT_LIMITS, EventFeedError, eventBytes, eventConfiguration, eventCredentialBinding,
  eventFail, eventHash, eventInteger, eventJson, eventKeys, validateEventPage, readEventPage } from './event_feed.mjs';

export const ARCHIVE_LIMITS = Object.freeze({ pages: 4096, bytes: 128 * 1024 * 1024,
  record: EVENT_LIMITS.response + 16384, entries: 4353 });
const checkDefault = () => {};
function platform() {
  if (typeof process.getuid !== 'function' || !constants.O_NOFOLLOW || !constants.O_DIRECTORY) eventFail('event_archive_platform_unsupported');
}
function owned(meta, directory = false) {
  if (!(directory ? meta.isDirectory() : meta.isFile()) || meta.uid !== process.getuid() || (meta.mode & 0o077) ||
      (!directory && meta.nlink !== 1)) eventFail('event_archive_requires_private_owned_files');
}
function same(a, b) { return a.dev === b.dev && a.ino === b.ino; }
function rootPath(path) {
  if (typeof path !== 'string' || !path || path.length > 4096 || path.includes('\0')) eventFail('invalid_event_archive_path');
  return resolve(path);
}
async function directory(path, expected = null) {
  const before = await lstat(path); owned(before, true);
  if (expected && !same(before, expected)) eventFail('event_archive_directory_changed');
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
  try { const meta = await handle.stat(); owned(meta, true); if (!same(before, meta)) eventFail('event_archive_directory_changed'); return handle; }
  catch (error) { await handle.close(); throw error; }
}
export async function readEventPrivate(path, maximum, checkpoint = checkDefault) {
  platform(); eventInteger(maximum, 1, ARCHIVE_LIMITS.record); checkpoint();
  const before = await lstat(path); owned(before);
  if (before.size > maximum) eventFail('event_archive_file_limit');
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const initial = await handle.stat(); owned(initial);
    if (!same(before, initial) || initial.size > maximum) eventFail('event_archive_file_changed');
    const bytes = Buffer.alloc(initial.size + 1); let used = 0;
    while (used < bytes.length) {
      checkpoint(); const { bytesRead } = await handle.read(bytes, used, bytes.length - used, null);
      if (!bytesRead) break; used += bytesRead;
    }
    const final = await handle.stat(), named = await lstat(path); owned(final); owned(named);
    if (!same(initial, named) || initial.size !== final.size || used !== initial.size ||
        initial.mtimeMs !== final.mtimeMs || initial.ctimeMs !== final.ctimeMs) eventFail('event_archive_file_changed');
    checkpoint(); return bytes.subarray(0, used);
  } finally { await handle.close(); }
}
async function names(path, maximum) {
  const entries = [], stream = await opendir(path);
  for await (const entry of stream) {
    if (entries.length === maximum) eventFail('event_archive_entry_limit');
    entries.push(entry.name);
  }
  return entries.sort();
}
async function readSlot(root, name, maximum, checkpoint, sync) {
  const path = join(root, name), handle = await directory(path);
  try {
    if (JSON.stringify(await names(path, 2)) !== '["record.json"]') eventFail('invalid_event_archive_slot');
    const bytes = await readEventPrivate(join(path, 'record.json'), maximum, checkpoint);
    const value = eventJson(bytes, maximum);
    if (!eventBytes(value).equals(bytes)) eventFail('noncanonical_event_archive_record');
    if (sync) {
      const record = await open(join(path, 'record.json'), constants.O_RDONLY | constants.O_NOFOLLOW);
      try { await record.sync(); } finally { await record.close(); }
      await handle.sync();
    }
    return { value, bytes };
  } finally { await handle.close(); }
}
function slotName(ordinal) { return `page-${String(eventInteger(ordinal, 1, ARCHIVE_LIMITS.pages + 1)).padStart(8, '0')}`; }
async function archiveNames(root) {
  const entries = await names(root, ARCHIVE_LIMITS.entries), pages = [];
  for (const entry of entries) {
    if (entry === 'binding' || /^\.stage-[A-Za-z0-9]{6}$/.test(entry)) continue;
    if (!/^page-[0-9]{8}$/.test(entry)) eventFail('invalid_event_archive_entry');
    pages.push(entry);
  }
  if (pages.length > ARCHIVE_LIMITS.pages || pages.some((entry, i) => entry !== slotName(i + 1))) eventFail('event_archive_page_gap');
  return pages;
}
// A staged directory contains a complete synced record. POSIX rename cannot
// replace another writer's nonempty committed directory, so competing writers
// never overwrite an accepted page. No stale lock survives a process crash.
async function publishSlot(root, identity, name, bytes, checkpoint, prepublish = async () => {}) {
  const parent = await directory(root, identity); let stage = null, published = false;
  try {
    checkpoint(); await parent.sync();
    stage = await mkdtemp(join(root, '.stage-'));
    const file = await open(join(stage, 'record.json'), 'wx', 0o600);
    try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
    const staged = await directory(stage);
    try { await staged.sync(); } finally { await staged.close(); }
    checkpoint(); await prepublish();
    const named = await lstat(root); owned(named, true);
    if (!same(named, identity)) eventFail('event_archive_directory_changed');
    checkpoint();
    await rename(stage, join(root, name)); published = true; stage = null;
    // Once publication starts, finish durability before acknowledging or
    // observing late cancellation. A confirmed page wins a late stop request.
    await parent.sync();
    const retained = await readSlot(root, name, bytes.length, checkDefault, false);
    if (!retained.bytes.equals(bytes)) eventFail('event_archive_readback_mismatch');
  } catch (error) {
    if (published) {
      const failure = new EventFeedError('event_archive_publication_unknown');
      failure.localPublicationUnknown = true; failure.recordSha256 = eventHash(bytes); throw failure;
    }
    if (error.code === 'ENOTEMPTY' || error.code === 'EEXIST') eventFail('event_archive_changed');
    throw error;
  } finally {
    if (stage) await rm(stage, { recursive: true, force: true });
    await parent.close();
  }
}
function bindingRecord(config, credential) {
  return { type: 'frankengit_event_archive', schema_version: 1, configuration: config,
    credential_binding_sha256: eventCredentialBinding(credential) };
}
function validateBinding(value, config, credentialBinding = null) {
  eventKeys(value, ['type', 'schema_version', 'configuration', 'credential_binding_sha256']);
  if (value.type !== 'frankengit_event_archive' || value.schema_version !== 1 ||
      typeof value.credential_binding_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.credential_binding_sha256) ||
      !eventBytes(eventConfiguration(value.configuration)).equals(eventBytes(config)) ||
      (credentialBinding !== null && credentialBinding !== value.credential_binding_sha256)) eventFail('event_archive_binding_mismatch');
}
export async function initializeEventArchive(path, configuration, credential, checkpoint = checkDefault) {
  platform(); const root = rootPath(path), config = eventConfiguration(configuration);
  const record = bindingRecord(config, credential); checkpoint();
  try { await mkdir(root, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const parent = await open(dirname(root), constants.O_RDONLY | constants.O_DIRECTORY);
  try { await parent.sync(); } finally { await parent.close(); }
  const handle = await directory(root), identity = await handle.stat(); await handle.close();
  const existing = await archiveNames(root);
  let present = true;
  try { await lstat(join(root, 'binding')); } catch (error) { if (error.code !== 'ENOENT') throw error; present = false; }
  if (present) {
    const retained = await readSlot(root, 'binding', EVENT_LIMITS.configuration, checkpoint, true);
    validateBinding(retained.value, config, record.credential_binding_sha256);
  } else {
    if (existing.length) eventFail('event_archive_binding_missing');
    try { await publishSlot(root, identity, 'binding', eventBytes(record), checkpoint); }
    catch (failure) {
      if (failure.code !== 'event_archive_changed') throw failure;
      const retained = await readSlot(root, 'binding', EVENT_LIMITS.configuration, checkpoint, true);
      validateBinding(retained.value, config, record.credential_binding_sha256);
    }
  }
  return openEventArchive(root, config, { credentialBinding: record.credential_binding_sha256, synchronize: true, checkpoint });
}
export async function openEventArchive(path, configuration, options = {}) {
  platform(); const root = rootPath(path), config = eventConfiguration(configuration);
  eventKeys(options, ['credentialBinding', 'expectedTail', 'synchronize', 'checkpoint', 'page'], []);
  const checkpoint = options.checkpoint ?? checkDefault, sync = options.synchronize ?? false;
  if (typeof checkpoint !== 'function' || typeof sync !== 'boolean') eventFail('invalid_event_archive_options');
  for (const name of ['credentialBinding', 'expectedTail']) if (options[name] !== undefined && (typeof options[name] !== 'string' || !/^[0-9a-f]{64}$/.test(options[name]))) eventFail('invalid_event_archive_pin');
  if (options.page !== undefined) eventInteger(options.page, 1, ARCHIVE_LIMITS.pages);
  checkpoint(); const handle = await directory(root), identity = await handle.stat();
  try {
    const binding = await readSlot(root, 'binding', EVENT_LIMITS.configuration, checkpoint, sync);
    validateBinding(binding.value, config, options.credentialBinding ?? null);
    let tail = eventHash(binding.bytes), after = config.after, bytes = binding.bytes.length, count = 0, events = 0, last = null, selected = null;
    const slots = await archiveNames(root);
    for (const name of slots) {
      checkpoint(); const record = await readSlot(root, name, ARCHIVE_LIMITS.record, checkpoint, sync);
      eventKeys(record.value, ['type', 'schema_version', 'ordinal', 'predecessor_sha256', 'after', 'page']);
      if (record.value.type !== 'frankengit_event_archive_page' || record.value.schema_version !== 1 ||
          record.value.ordinal !== count + 1 || record.value.predecessor_sha256 !== tail || record.value.after !== after) eventFail('event_archive_chain_mismatch');
      last = validateEventPage(record.value.page, config, after);
      tail = eventHash(record.bytes); after = last.resume_after ?? '0'; count++; events += last.events.length; bytes += record.bytes.length;
      if (bytes > ARCHIVE_LIMITS.bytes) eventFail('event_archive_byte_limit');
      if (count === options.page) selected = record.value;
    }
    if (options.expectedTail !== undefined && tail !== options.expectedTail) eventFail('event_archive_tail_mismatch');
    if (options.page !== undefined && selected === null) eventFail('event_archive_page_missing');
    const named = await lstat(root); owned(named, true);
    if (!same(identity, named)) eventFail('event_archive_directory_changed');
    if (sync) await handle.sync();
    checkpoint();
    return new EventArchive({ root, identity, config, binding: binding.value, bindingHash: eventHash(binding.bytes),
      tail, after, bytes, count, events, last, selected, synchronized: sync });
  } finally { await handle.close(); }
}
class EventArchive {
  #state; #busy = false; #poisoned = false;
  constructor(state) { this.#state = state; }
  summary() {
    const s = this.#state;
    return { type: 'frankengit_event_archive_status', schema_version: 1, pages: s.count, events: s.events,
      archive_bytes: s.bytes, tail_sha256: s.tail, resume_after: s.after, last_observed_head: s.last?.snapshot_token ?? null,
      last_observed_complete: s.last?.complete ?? null, canonical_settled: false };
  }
  selectedPage() { return this.#state.selected === null ? null : structuredClone(this.#state.selected); }
  configuration() { return structuredClone(this.#state.config); }
  checkCredential(credential) {
    if (eventCredentialBinding(credential) !== this.#state.binding.credential_binding_sha256) eventFail('event_archive_credential_changed');
  }
  async append(page, checkpoint = checkDefault) {
    if (!this.#state.synchronized) eventFail('event_archive_write_requires_synced_open');
    if (this.#busy || this.#poisoned) eventFail('event_archive_owner_unavailable');
    this.#busy = true;
    try {
      const s = this.#state, checked = validateEventPage(page, s.config, s.after);
      const record = { type: 'frankengit_event_archive_page', schema_version: 1, ordinal: s.count + 1,
        predecessor_sha256: s.tail, after: s.after, page: checked };
      const bytes = eventBytes(record);
      const prepublish = async () => {
        const binding = await readSlot(s.root, 'binding', EVENT_LIMITS.configuration, checkpoint, false);
        if (eventHash(binding.bytes) !== s.bindingHash) eventFail('event_archive_binding_mismatch');
        if (s.count) {
          const previous = await readSlot(s.root, slotName(s.count), ARCHIVE_LIMITS.record, checkpoint, false);
          if (eventHash(previous.bytes) !== s.tail) eventFail('event_archive_changed');
        }
        try { await lstat(join(s.root, slotName(s.count + 1))); eventFail('event_archive_changed'); }
        catch (error) { if (error.code !== 'ENOENT') throw error; }
      };
      // Identical quiet polls need no extra page. Still verify the owner has
      // not fallen behind another writer before reporting an unchanged tip.
      if (s.last && eventBytes(checked).equals(eventBytes(s.last))) {
        const handle = await directory(s.root, s.identity);
        try { await prepublish(); checkpoint(); } finally { await handle.close(); }
        return { ...this.summary(), appended: false, local_synced: true };
      }
      if (s.count === ARCHIVE_LIMITS.pages || bytes.length > ARCHIVE_LIMITS.record || s.bytes + bytes.length > ARCHIVE_LIMITS.bytes) eventFail('event_archive_capacity');
      await publishSlot(s.root, s.identity, slotName(s.count + 1), bytes, checkpoint, prepublish);
      s.count++; s.tail = eventHash(bytes); s.after = checked.resume_after ?? '0'; s.bytes += bytes.length;
      s.events += checked.events.length; s.last = checked;
      return { ...this.summary(), appended: true, local_synced: true };
    } catch (error) { this.#poisoned = true; throw error; }
    finally { this.#busy = false; }
  }
}
export async function captureEventArchive(path, configuration, credential, options = {}) {
  eventKeys(options, ['maxPages', 'maxBytes', 'timeoutMs', 'signal', 'ca', 'expectedTail', 'onPage'], []);
  const maxPages = eventInteger(options.maxPages ?? 16, 1, EVENT_LIMITS.pages);
  const maxBytes = eventInteger(options.maxBytes ?? EVENT_LIMITS.bytes, 1, EVENT_LIMITS.bytes);
  const timeout = eventInteger(options.timeoutMs ?? 30000, 1, EVENT_LIMITS.timeoutMs);
  const signal = options.signal, onPage = options.onPage ?? (async () => {}), expectedTail = options.expectedTail;
  if ((signal !== undefined && !(signal instanceof AbortSignal)) || typeof onPage !== 'function') eventFail('invalid_event_archive_options');
  const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length > 0 && options.ca.length <= 128 * 1024
    ? Buffer.from(options.ca) : eventFail('invalid_event_ca');
  const start = performance.now();
  const checkpoint = () => { if (signal?.aborted) eventFail('event_cancelled'); if (performance.now() - start >= timeout) eventFail('event_timeout'); };
  const config = eventConfiguration(configuration), credentialBinding = eventCredentialBinding(credential);
  const archive = await openEventArchive(path, config, { credentialBinding, ...(expectedTail !== undefined ? { expectedTail } : {}), synchronize: true, checkpoint });
  let received = 0, pages = 0;
  while (pages < maxPages) {
    checkpoint(); if (received === maxBytes) eventFail('event_capture_limit');
    const result = await readEventPage(config, credential, { after: archive.summary().resume_after,
      timeoutMs: Math.max(1, Math.floor(timeout - (performance.now() - start))), signal, ca,
      maximumBytes: Math.min(EVENT_LIMITS.response, maxBytes - received) });
    received += result.bytes; checkpoint();
    const receipt = await archive.append(result.page, checkpoint); pages++;
    try { await onPage(receipt); } catch {
      const error = new EventFeedError('event_archive_output_failed'); error.retained = receipt; throw error;
    }
    if (!result.page.has_more) return { ...archive.summary(), fetched_pages: pages, received_bytes: received, caught_up_at_observed_head: true };
  }
  return { ...archive.summary(), fetched_pages: pages, received_bytes: received, caught_up_at_observed_head: false };
}
