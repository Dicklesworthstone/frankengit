import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, chmod, link, symlink, rename, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eventBytes, eventHash, eventCredentialBinding, EventFeedError } from '../../scripts/operator/event_feed.mjs';
import { initializeEventArchive, openEventArchive, captureEventArchive, readEventPrivate } from '../../scripts/operator/event_archive.mjs';
import { config, page, row, peer, json, TOKEN } from './event_feed_fixture.mjs';
const code = expected => error => error.code === expected;
const privateFile = (path, value) => writeFile(path, value, { mode: 0o600 });
async function fixture(configuration = config()) {
  const parent = await mkdtemp(join(tmpdir(), 'fg-event-archive-')), root = join(parent, 'archive');
  const archive = await initializeEventArchive(root, configuration, TOKEN);
  return { parent, root, configuration, archive, close: () => rm(parent, { recursive: true, force: true }) };
}
async function finalFiles(root) {
  const out = [];
  for (const entry of (await readdir(root)).filter(name => !name.startsWith('.stage-')).sort()) {
    const file = join(root, entry, 'record.json'), meta = await lstat(file);
    out.push({ entry, bytes: await readFile(file), inode: meta.ino, mtime: meta.mtimeMs });
  }
  return out;
}

test('initialization is local, private, credential-bound and byte-idempotent', async () => {
  const f = await fixture();
  try {
    assert.equal(f.archive.summary().pages, 0); assert.equal(f.archive.summary().resume_after, '0');
    const before = await finalFiles(f.root);
    const retried = await initializeEventArchive(f.root, f.configuration, TOKEN);
    assert.deepEqual(retried.summary(), f.archive.summary()); assert.deepEqual(await finalFiles(f.root), before);
    assert.equal((await lstat(f.root)).mode & 0o777, 0o700);
    assert.equal((await lstat(join(f.root, 'binding'))).mode & 0o777, 0o700);
    assert.equal((await lstat(join(f.root, 'binding', 'record.json'))).mode & 0o777, 0o600);
    assert(!before[0].bytes.toString().includes(TOKEN));
    await assert.rejects(initializeEventArchive(f.root, f.configuration, '43'.repeat(32)), code('event_archive_binding_mismatch'));
    for (const alter of [c => c.endpoint = 'https://other.test/repo', c => c.after = '1:0', c => c.page_size = 5,
      c => c.scope.pulls_read = true, c => c.scope.repository_incarnation = '44'.repeat(16)]) {
      const cfg = structuredClone(f.configuration); alter(cfg);
      await assert.rejects(initializeEventArchive(f.root, cfg, TOKEN), code('event_archive_binding_mismatch'));
    }
    assert.deepEqual(await finalFiles(f.root), before);
  } finally { await f.close(); }
});

for (const format of ['sha1', 'sha256']) test(`${format}: sync-before-receipt, filtered watermark, restart and exact offline replay`, async () => {
  let cfg;
  const server = await peer((q, r, ordinal) => {
    const after = new URL(q.url, 'http://fixture.test').searchParams.get('after');
    assert.equal(after, ['0', '9007199254740993:1', '18446744073709551614:4294967295', '18446744073709551615:0'][ordinal - 1]);
    const raw = ordinal === 1 ? page(cfg, { rows: [], resume: '9007199254740993:1', more: true }) :
      ordinal === 2 ? page(cfg, { rows: [row('18446744073709551614', '4294967295')], more: true, head: '02' }) :
      ordinal === 3 ? page(cfg, { rows: [row('18446744073709551615')], head: '03' }) :
      page(cfg, { rows: [], resume: '18446744073709551615:0', head: '03' });
    json(r, raw);
  });
  cfg = config(server.endpoint, format); const f = await fixture(cfg);
  try {
    const receipts = [];
    const first = await captureEventArchive(f.root, cfg, TOKEN, { maxPages: 2, onPage: async receipt => {
      const reopened = await openEventArchive(f.root, cfg, { expectedTail: receipt.tail_sha256, page: receipt.pages });
      assert.equal(reopened.summary().resume_after, receipt.resume_after);
      assert.equal(reopened.selectedPage().ordinal, receipt.pages);
      assert(receipt.local_synced); receipts.push(receipt);
    } });
    assert.equal(first.caught_up_at_observed_head, false); assert.equal(first.pages, 2);
    assert.equal(receipts[0].events, 0); assert.equal(receipts[1].events, 1);
    const completed = await captureEventArchive(f.root, cfg, TOKEN, { expectedTail: first.tail_sha256 });
    assert.equal(completed.caught_up_at_observed_head, true); assert.equal(completed.pages, 3); assert.equal(completed.events, 2);
    const selected = await openEventArchive(f.root, cfg, { page: 2 });
    assert.equal(selected.selectedPage().page.events[0].event_frame_hex, '00ff80');
    assert.equal(selected.selectedPage().after, '9007199254740993:1');
    const quiet = await captureEventArchive(f.root, cfg, TOKEN);
    assert.equal(quiet.pages, 4); assert.equal(quiet.events, 2);
    const before = await finalFiles(f.root);
    const inspection = await openEventArchive(f.root, cfg, { expectedTail: quiet.tail_sha256 });
    assert.equal(inspection.summary().resume_after, '18446744073709551615:0');
    await assert.rejects(inspection.append(page(cfg, { rows: [], resume: '18446744073709551615:0', head: '03' })), code('event_archive_write_requires_synced_open'));
    assert.deepEqual(await finalFiles(f.root), before); assert.equal(server.requests.length, 4);
  } finally { await f.close(); await server.close(); }
});

test('a saved page survives lost consumer output; resume never requests that page again', async () => {
  let cfg;
  const server = await peer((q, r, n) => {
    assert.equal(new URL(q.url, 'http://fixture.test').searchParams.get('after'), n === 1 ? '0' : '1:0');
    json(r, page(cfg, { rows: [row(String(n))], more: n === 1 }));
  });
  cfg = config(server.endpoint); const f = await fixture(cfg);
  try {
    await assert.rejects(captureEventArchive(f.root, cfg, TOKEN, { onPage: () => { throw new Error('closed consumer'); } }),
      e => e.code === 'event_archive_output_failed' && e.retained.pages === 1 && e.retained.local_synced);
    assert.equal((await openEventArchive(f.root, cfg)).summary().resume_after, '1:0');
    const result = await captureEventArchive(f.root, cfg, TOKEN);
    assert.equal(result.events, 2); assert.equal(result.pages, 2); assert.equal(server.requests.length, 2);
  } finally { await f.close(); await server.close(); }
});

for (const failure of ['server', 'scope', 'bytes', 'cancel']) test(`${failure} on a later page preserves earlier synced events and the last cursor`, async () => {
  let cfg; const controller = new AbortController();
  const server = await peer((_q, r, n) => {
    if (n === 1) json(r, page(cfg, { more: true }));
    else if (failure === 'server') json(r, { error: 'private server text' }, 503);
    else if (failure === 'scope') { const raw = page(cfg, { rows: [row('2')] }); raw.repository_incarnation = '55'.repeat(16); json(r, raw); }
    else if (failure === 'bytes') { r.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': 9000000 }); r.end(); }
    else { controller.abort(); r.destroy(); }
  });
  cfg = config(server.endpoint); const f = await fixture(cfg);
  try {
    await assert.rejects(captureEventArchive(f.root, cfg, TOKEN, { signal: controller.signal }));
    const archive = await openEventArchive(f.root, cfg, { synchronize: true });
    assert.equal(archive.summary().pages, 1); assert.equal(archive.summary().resume_after, '1:0');
    const result = await archive.append(page(cfg, { rows: [row('2')] })); assert.equal(result.pages, 2);
  } finally { await f.close(); await server.close(); }
});

test('changed credentials and independent tail pins fail before a socket is opened', async () => {
  const server = await peer(() => { throw new Error('must not contact receiver'); });
  const cfg = config(server.endpoint), f = await fixture(cfg);
  try {
    await assert.rejects(captureEventArchive(f.root, cfg, '43'.repeat(32)), code('event_archive_binding_mismatch'));
    await assert.rejects(captureEventArchive(f.root, cfg, TOKEN, { expectedTail: '00'.repeat(32) }), code('event_archive_tail_mismatch'));
    await assert.rejects(captureEventArchive(f.root, cfg, TOKEN, { expectedTail: '' }), code('invalid_event_archive_pin'));
    assert.equal(server.requests.length, 0);
    const read = await openEventArchive(f.root, cfg); read.checkCredential(TOKEN);
    assert.throws(() => read.checkCredential('43'.repeat(32)), code('event_archive_credential_changed'));
  } finally { await f.close(); await server.close(); }
});

test('competing owners cannot overwrite a nonempty committed slot, and loser can reopen', async () => {
  const f = await fixture();
  try {
    const a = await openEventArchive(f.root, f.configuration, { synchronize: true });
    const b = await openEventArchive(f.root, f.configuration, { synchronize: true });
    const first = page(f.configuration), alternative = page(f.configuration, { rows: [row('2')], head: '02' });
    const result = await Promise.allSettled([a.append(first), b.append(alternative)]);
    assert.equal(result.filter(x => x.status === 'fulfilled').length, 1);
    assert.equal(result.filter(x => x.status === 'rejected').length, 1);
    assert.equal(result.find(x => x.status === 'rejected').reason.code, 'event_archive_changed');
    const winner = await openEventArchive(f.root, f.configuration, { synchronize: true, page: 1 });
    const selected = winner.selectedPage().page;
    assert([first.resume_after, alternative.resume_after].includes(selected.resume_after));
    assert.equal(winner.summary().pages, 1);
    await assert.rejects((result[0].status === 'rejected' ? a : b).append(page(f.configuration, { rows: [row('3')] })), code('event_archive_owner_unavailable'));
    await winner.append(page(f.configuration, { rows: [row('3')] }));
    assert.equal((await openEventArchive(f.root, f.configuration)).summary().pages, 2);
    assert.equal((await readdir(f.root)).filter(name => name.startsWith('.stage-')).length, 0);
  } finally { await f.close(); }
});

test('concurrent identical initialization converges without resetting later pages', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'fg-events-init-race-')), root = join(parent, 'archive'), cfg = config();
  try {
    const result = await Promise.all([initializeEventArchive(root, cfg, TOKEN), initializeEventArchive(root, cfg, TOKEN)]);
    assert.deepEqual(result[0].summary(), result[1].summary());
    await result[0].append(page(cfg)); const before = await finalFiles(root);
    assert.equal((await initializeEventArchive(root, cfg, TOKEN)).summary().pages, 1);
    assert.deepEqual(await finalFiles(root), before);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('cancellation during staging selects no page, poisons the owner and leaves a resumable prefix', async () => {
  const f = await fixture();
  try {
    let probes = 0;
    await assert.rejects(f.archive.append(page(f.configuration), () => { if (++probes === 2) throw new EventFeedError('event_cancelled'); }), code('event_cancelled'));
    const reopened = await openEventArchive(f.root, f.configuration, { synchronize: true });
    assert.equal(reopened.summary().pages, 0); assert.equal(reopened.summary().resume_after, '0');
    assert.deepEqual((await readdir(f.root)).sort(), ['binding']);
    await assert.rejects(f.archive.append(page(f.configuration)), code('event_archive_owner_unavailable'));
    await reopened.append(page(f.configuration)); assert.equal(reopened.summary().pages, 1);
  } finally { await f.close(); }
});

test('identical quiet polls do not accumulate records but detect a stale owner', async () => {
  const f = await fixture();
  try {
    const empty = page(f.configuration, { rows: [] });
    await f.archive.append(empty); const before = await finalFiles(f.root);
    for (let i = 0; i < 10; i++) assert.equal((await f.archive.append(empty)).appended, false);
    assert.deepEqual(await finalFiles(f.root), before);
    const other = await openEventArchive(f.root, f.configuration, { synchronize: true });
    await other.append(page(f.configuration));
    await assert.rejects(f.archive.append(empty), code('event_archive_changed'));
  } finally { await f.close(); }
});

for (const corruption of ['missing', 'truncated', 'grafted', 'extra', 'noncanonical', 'unknown', 'binding']) {
  test(`archive ${corruption} is refused without silently skipping, trimming or reinitializing`, async () => {
    const f = await fixture();
    try {
      await f.archive.append(page(f.configuration, { more: true }));
      await f.archive.append(page(f.configuration, { rows: [row('2')] }));
      const path = join(f.root, 'page-00000001', 'record.json');
      if (corruption === 'missing') await rm(join(f.root, 'page-00000001'), { recursive: true });
      else if (corruption === 'truncated') await writeFile(path, (await readFile(path)).subarray(0, 50));
      else if (corruption === 'grafted') {
        const value = JSON.parse(await readFile(path, 'utf8')); value.page.events[0].event_frame_hex = '01';
        await writeFile(path, eventBytes(value));
      } else if (corruption === 'extra') await privateFile(join(f.root, 'page-00000001', 'extra'), 'bad');
      else if (corruption === 'noncanonical') await writeFile(path, ` ${await readFile(path, 'utf8')}`);
      else if (corruption === 'unknown') await privateFile(join(f.root, 'checkpoint'), 'untrusted pointer');
      else await rm(join(f.root, 'binding', 'record.json'));
      await assert.rejects(openEventArchive(f.root, f.configuration));
      await assert.rejects(initializeEventArchive(f.root, f.configuration, TOKEN));
    } finally { await f.close(); }
  });
}

test('an independently retained tail detects valid-prefix rollback and last-page edits', async () => {
  const f = await fixture();
  try {
    await f.archive.append(page(f.configuration, { more: true }));
    const complete = await f.archive.append(page(f.configuration, { rows: [row('2')] }));
    const path = join(f.root, 'page-00000002', 'record.json'), original = await readFile(path);
    const changed = JSON.parse(original); changed.page.events[0].event_frame_hex = 'abcd'; await writeFile(path, eventBytes(changed));
    await assert.rejects(openEventArchive(f.root, f.configuration, { expectedTail: complete.tail_sha256 }), code('event_archive_tail_mismatch'));
    await writeFile(path, original); assert.equal((await openEventArchive(f.root, f.configuration, { expectedTail: complete.tail_sha256 })).summary().pages, 2);
    await rm(join(f.root, 'page-00000002'), { recursive: true });
    await assert.rejects(openEventArchive(f.root, f.configuration, { expectedTail: complete.tail_sha256 }), code('event_archive_tail_mismatch'));
    // Without an independent tail, a complete older prefix is deliberately not
    // claimed to be distinguishable from an earlier legitimate crash point.
    assert.equal((await openEventArchive(f.root, f.configuration)).summary().pages, 1);
  } finally { await f.close(); }
});

test('private input boundaries reject links, exposed files, special files and replaced roots', async () => {
  const f = await fixture();
  try {
    const file = join(f.parent, 'private'); await privateFile(file, 'secret');
    assert.equal((await readEventPrivate(file, 6)).toString(), 'secret');
    await assert.rejects(readEventPrivate(file, 5), code('event_archive_file_limit'));
    await chmod(file, 0o644); await assert.rejects(readEventPrivate(file, 6), code('event_archive_requires_private_owned_files'));
    await chmod(file, 0o600);
    const alias = join(f.parent, 'alias'); await symlink(file, alias);
    await assert.rejects(readEventPrivate(alias, 6), code('event_archive_requires_private_owned_files')); await rm(alias);
    await link(file, alias); await assert.rejects(readEventPrivate(file, 6), code('event_archive_requires_private_owned_files'));
    await assert.rejects(readEventPrivate(f.root, 6), code('event_archive_requires_private_owned_files'));
    const old = join(f.parent, 'old'); await rename(f.root, old);
    await initializeEventArchive(f.root, f.configuration, TOKEN);
    await assert.rejects(f.archive.append(page(f.configuration)), code('event_archive_directory_changed'));
    assert.equal((await openEventArchive(f.root, f.configuration)).summary().pages, 0);
  } finally { await f.close(); }
});

test('an abandoned staging record cannot advance the cursor or become a fallback binding', async () => {
  const f = await fixture();
  try {
    const stage = join(f.root, '.stage-aA0123'); await mkdir(stage, { mode: 0o700 });
    await privateFile(join(stage, 'record.json'), 'truncated candidate');
    assert.equal((await openEventArchive(f.root, f.configuration)).summary().pages, 0);
    await f.archive.append(page(f.configuration)); assert.equal((await openEventArchive(f.root, f.configuration)).summary().resume_after, '1:0');
    assert.equal((await readFile(join(stage, 'record.json'))).toString(), 'truncated candidate');
  } finally { await f.close(); }
});

test('pre-cancelled and invalid commands leave the initialized archive unchanged', async () => {
  const f = await fixture(), before = await finalFiles(f.root);
  try {
    const stop = new AbortController(); stop.abort();
    await assert.rejects(captureEventArchive(f.root, f.configuration, TOKEN, { signal: stop.signal }), code('event_cancelled'));
    for (const options of [{ maxPages: 0 }, { maxBytes: 0 }, { timeoutMs: 0 }, { autoRetry: true }, { signal: {} }]) {
      await assert.rejects(captureEventArchive(f.root, f.configuration, TOKEN, options));
    }
    await assert.rejects(openEventArchive(f.root, f.configuration, { page: 1 }), code('event_archive_page_missing'));
    assert.deepEqual(await finalFiles(f.root), before);
    assert.match(eventHash(before[0].bytes), /^[0-9a-f]{64}$/);
    assert.equal(JSON.parse(before[0].bytes).credential_binding_sha256, eventCredentialBinding(TOKEN));
  } finally { await f.close(); }
});

test('a planted directory-sync failure after rename stays unknown and reopening resynchronizes the visible page', async () => {
  const f = await fixture();
  const { open } = await import('node:fs/promises');
  const handle = await open(f.root, 'r'), identity = await handle.stat(), prototype = Object.getPrototypeOf(handle), original = prototype.sync;
  await handle.close(); let planted = false;
  try {
    // Actual file/stage/rename operations remain intact. Plant one I/O failure
    // only at this archive root's post-publication durability boundary.
    prototype.sync = async function () {
      const meta = await this.stat();
      if (!planted && meta.dev === identity.dev && meta.ino === identity.ino) {
        let exists = false; try { await lstat(join(f.root, 'page-00000001')); exists = true; } catch (e) { if (e.code !== 'ENOENT') throw e; }
        if (exists) { planted = true; const e = new Error('planted directory sync failure'); e.code = 'EIO'; throw e; }
      }
      return original.call(this);
    };
    await assert.rejects(f.archive.append(page(f.configuration)), e => e.code === 'event_archive_publication_unknown' && e.localPublicationUnknown === true && /^[0-9a-f]{64}$/.test(e.recordSha256));
    assert(planted);
  } finally { prototype.sync = original; }
  try {
    await assert.rejects(f.archive.append(page(f.configuration)), code('event_archive_owner_unavailable'));
    const recovered = await openEventArchive(f.root, f.configuration, { synchronize: true });
    assert.equal(recovered.summary().pages, 1); assert.equal(recovered.summary().resume_after, '1:0');
    const continued = await recovered.append(page(f.configuration, { rows: [row('2')] }));
    assert.equal(continued.pages, 2); assert.equal(continued.local_synced, true);
  } finally { await f.close(); }
});

test('the real 4096-page ceiling permits bounded replay but refuses a 4097th changed observation', async () => {
  const { ARCHIVE_LIMITS } = await import('../../scripts/operator/event_archive.mjs');
  const f = await fixture();
  try {
    let previous = f.archive.summary().tail_sha256, pending = [];
    for (let ordinal = 1; ordinal <= ARCHIVE_LIMITS.pages; ordinal++) {
      const record = { type: 'frankengit_event_archive_page', schema_version: 1, ordinal,
        predecessor_sha256: previous, after: '0', page: page(f.configuration, { rows: [] }) };
      const bytes = eventBytes(record); previous = eventHash(bytes);
      const path = join(f.root, `page-${String(ordinal).padStart(8, '0')}`);
      pending.push((async () => { await mkdir(path, { mode: 0o700 }); await privateFile(join(path, 'record.json'), bytes); })());
      if (pending.length === 32) { await Promise.all(pending); pending = []; }
    }
    await Promise.all(pending);
    const archive = await openEventArchive(f.root, f.configuration, { synchronize: true, expectedTail: previous });
    assert.equal(archive.summary().pages, ARCHIVE_LIMITS.pages);
    assert.equal((await archive.append(page(f.configuration, { rows: [] }))).appended, false);
    await assert.rejects(archive.append(page(f.configuration, { rows: [], head: '02' })), code('event_archive_capacity'));
    assert.equal((await readdir(f.root)).length, ARCHIVE_LIMITS.pages + 1);
  } finally { await f.close(); }
});
