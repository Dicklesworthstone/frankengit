import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { exportPullArchive, inspectPullArchive, PULL_ARCHIVE_LIMITS as L } from '../../scripts/lib/forge-pull-archive.mjs';
import { PullArchiveWalk } from '../../scripts/lib/forge-pull-archive-protocol.mjs';
import { fixture, pullRow, encode, hash } from './pull-archive-fixture.mjs';

// Full native-schema HTTP/client/custody traversal, not a native server load test.
test('bounded multi-page population exports through actual HTTP', async t => {
  const f = await fixture(t, { pulls: 128, reviews: 0, comments: 0 });
  const result = await exportPullArchive(f.options);
  assert.equal(result.pulls, 128);
  assert.equal(result.pages, 512);
  assert.equal(f.requests.length, 512);
  assert.equal((await inspectPullArchive({ workdir: f.out, confirm: result.archive_sha256 })).complete, true);
});

// Capacity of the real traversal, manifest and offline reader. Fixture writes
// are batched, not production capture/fsync or native server capacity evidence.
test('all 4096 pulls and 16384 page descriptors validate offline', async t => {
  const f = await fixture(t, { pulls: 0 });
  await exportPullArchive(f.options);
  const m = JSON.parse(await readFile(join(f.out, 'archive.json'), 'utf8'));
  const header = JSON.parse(await readFile(join(f.out, 'page-000001.json'), 'utf8'));
  for (const key of ['type', 'after', 'limit', 'pull_requests', 'next_after']) delete header[key];
  const root = join(f.root, 'capacity'); await mkdir(root, { mode: 0o700 });
  const walk = new PullArchiveWalk({ tenant:m.tenant_id, repository:m.repository_id, pageSize:1, limits:L });
  m.pages = []; m.pull_count = L.pulls; m.data_bytes = 0;
  let writes = [];
  for (let n = 1; n <= L.pulls; n++) {
    const row = pullRow(n);
    const replies = [
      {...header,type:'pull_request_page',after:n-1,limit:1,pull_requests:[row],next_after:n<L.pulls?n:null},
      {...header,type:'pull_request',number:n,found:true,pull_request:row},
      {...header,type:'review_page',number:n,found:true,merge_authorized:false,after:null,limit:1,reviews:[],next_after:null,pull_request_version:1,policy_epoch:1},
      {...header,type:'pull_request_comments',number:n,found:true,discussion_version:0,after:0,limit:1,comments:[],next_after:null,complete:true,merge_permission:null,transaction_created:false},
    ];
    for (const reply of replies) {
      const descriptor = walk.request; walk.accept(descriptor, reply);
      const bytes = encode(reply); m.data_bytes += bytes.length;
      m.pages.push({...descriptor,sha256:hash(bytes),bytes:bytes.length});
      writes.push(writeFile(join(root, `page-${String(m.pages.length).padStart(6,'0')}.json`), bytes, {mode:0o600}));
      if (writes.length === 32) { await Promise.all(writes); writes = []; }
    }
  }
  await Promise.all(writes);
  assert.equal(walk.finish().pages, L.pages);
  const bytes = encode(m); assert(bytes.length > L.pageBytes && bytes.length <= L.manifestBytes);
  await writeFile(join(root,'archive.json'), bytes, {mode:0o600}); await f.close();
  const inspected = await inspectPullArchive({workdir:root,confirm:hash(bytes)});
  assert.equal(inspected.pages, L.pages); assert.equal(inspected.pulls, L.pulls); assert.equal(inspected.complete, true);
});
