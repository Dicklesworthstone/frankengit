# Complete native discussion read archives

`scripts/archive_native_discussions.mjs` exports every standalone discussion and
its complete action/comment history through the existing native discussion API.
It preserves original text, versions and source actors, including edits,
close/reopen and lock/unlock history. This gives repository operators a portable
outbound discussion-data path alongside native issue and pull-request archives.

The implementation uses the shipped `DiscussionClient`, native response
decoders and existing private-file custody helpers. It adds no native codec,
database, write permission or alternate runtime to `fg`. The discussion stream
remains separate from issues, pull-request comments and notification inboxes.

## Capture one complete snapshot

The source must enable discussions and grant the existing credential
`discussions-read`. No write or outcome scope is needed. Supply the exact
repository `/ui/discussions/` URL, explicit tenant/repository IDs, a private file
containing the existing 64-hex token, and an absent output directory beneath a
stable private parent. HTTPS is required except for the client's trusted
loopback profile. Credentials never appear in command arguments or archives.

```sh
node scripts/archive_native_discussions.mjs export \
  --url https://forge.example/project/ui/discussions/ \
  --tenant 11111111111111111111111111111111 \
  --repository 22222222222222222222222222222222 \
  --token-file /srv/operator/discussions-read-token \
  --workdir /srv/exports/discussions-001 --page-size 10

# Retain export's archive_sha256 independently as ARCHIVE_SHA.
node scripts/archive_native_discussions.mjs inspect \
  --workdir /srv/exports/discussions-001 --confirm "$ARCHIVE_SHA"
```

The first list page selects the repository snapshot. Optional `--head` constrains
that first request too. Every later list and history page uses that exact token,
and the recorded source head must remain identical. Ordinary writes can proceed
while the native API serves the selected retained ancestor. An unavailable
ancestor or revoked grant stops capture; the exporter never changes to a new
head, treats a refusal as an empty result, or retries an HTTP request.

List ordering, continuation and repository identity are checked. Each listed
discussion must have exactly its declared contiguous history, beginning at
version one, and the same snapshot on every history page. Full replay must
reproduce the title, body, open/closed state, lock, opening actor, last actor and
comment count. Replay carries state across page boundaries, rejecting repeated
close/reopen and lock/unlock transitions and comments while locked. Edits while
locked and comments while closed but unlocked retain the native semantics.
Closing or reopening never clears a lock.

Every action and original comment body is retained, including text replaced by
later edits. Source actor IDs remain provenance, and do not become local
principals or permissions. Rendering is not requested. The retained pages are
canonical JSON plus a newline; original text is data and is never executed as
HTML. These are the parsed native API records, not an exact capture of HTTP wire
framing or the native binary event log.

## Completion, custody and offline verification

Pages are written as `page-NNNNNN.json` through the existing private, create-only,
synchronized writer and read back. Only after traversal completes and a second
offline readback validates every retained page does `archive.json` bind the
source endpoint, tenant/repository, snapshot token, source head, counts, page
order, byte lengths and SHA-256 digests. The manifest contains no token or token
fingerprint. An empty discussion namespace is a complete one-page observation.

Inspection requires the independently retained manifest hash. It needs no
credential or source service, makes no network request, and changes no local
file. It runs the same native decoders and full replay as live capture. Missing,
reordered, substituted, noncanonical, public, linked or unexpected files refuse.
Changing page hashes and then recomputing the manifest cannot conceal an
inconsistent history or snapshot. Supplying an entirely rewritten archive and
its new hash does not independently authenticate the original source.

The output directory is created exclusively. Existing destinations are never
overwritten or automatically removed. A failed or cancelled capture leaves an
unsealed prefix for diagnosis, which cannot be consumed as a complete archive.
There is no capture-resume operation in this profile. SIGTERM/SIGINT stop further
reads and drain the active response; SIGKILL can leave an incomplete prefix.
Every successful page remains private. A directory replacement during capture
refuses before publication into substituted custody.

An error during final manifest publication can leave a complete or incomplete
root. Error progress retains the expected manifest hash when known. Inspect the
original files with that pin before drawing a conclusion from a lost result.
A broken output pipe does not repeat capture: error output retains the complete
result and its pin when possible.

The JavaScript API exposes the same operations and a fully checked data view:

```js
import { exportDiscussionArchive, inspectDiscussionArchive, readDiscussionArchive }
  from './scripts/lib/forge-discussion-archive.mjs';

const captured = await exportDiscussionArchive({
  href: 'https://forge.example/project/ui/discussions/',
  tenant: '11111111111111111111111111111111',
  repository: '22222222222222222222222222222222',
  tokenFile: '/srv/operator/discussions-read-token',
  workdir: '/srv/exports/discussions-001',
  pageSize: 10,
});
const selection = { workdir: captured.workdir, confirm: captured.archive_sha256 };
const checked = await inspectDiscussionArchive(selection);
const { archive, records } = await readDiscussionArchive(selection);
// records: [{ snapshot, events: [{ version, actor, action }] }]
```

The reader returns records only after the entire archive passes inspection. It
does not expose a successful prefix or callbacks during validation. All original
events are available for offline analysis; there is no discussion import,
destination mapping, mutation replay or restoration API in this slice.

## Bounds and result contract

One operation has a maximum 300-second deadline covering HTTP, disk writes and
complete offline readback. Default ceilings are 8,192 requests/pages, 4,096
discussions, 65,536 events, 64 MiB of response bytes and 64 MiB of retained
pages-plus-manifest data. Each response, retained page and manifest is at most
1 MiB. Page size is 1–100, default 10. Oversized pages refuse; choose a smaller
page size for large bodies. No bound truncates a successful archive.

Use `--max-requests`, `--max-discussions`, `--max-events`, `--max-read-bytes` and
`--max-archive-bytes` to lower those ceilings, and `--timeout-ms` to lower the
deadline. JavaScript accepts the corresponding `maxRequests`, `maxDiscussions`,
`maxEvents`, `maxReadBytes`, `maxArchiveBytes` and `timeoutMs` fields, plus an
optional `AbortSignal` as `signal`. Offline inspection accepts only the archive
directory, original pin, optional timeout and signal. It rejects network and
credential overrides.

Output uses the existing bounded JSON writer with terminal-control escaping and
a ten-second deadline. Exit 0 means complete capture or inspection; 2 means
invalid input, failed inspection or failure before output-directory creation;
3 means incomplete or uncertain local capture; 4 means the complete result was
known but output failed. Complete results explicitly report
`canonical_backup: false`, `restore_authority: false` and
`mutation_submitted: false`.

The archive is a complete, self-consistent observation through the native API
within its bounds and the credential's visibility. It is not a canonical
repository backup, signed completeness proof, retention guarantee or restore
grant. Git objects, issue/PR conversations, credentials, delivery records and
canonical transaction receipts are not included. Stable owner-controlled POSIX
parents and Node.js 22.16 or later are required. The filesystem contract does not
claim a hostile same-UID sandbox or physical power-loss proof.

## Verification

```sh
node --test tests/operator/discussion-archive.test.mjs \
  tests/operator/discussion-archive-cli.test.mjs
```

Tests exercise the unchanged production HTTP client, archive traversal and
private-file helpers against real loopback response-schema peers. They cover
all actions across separate pages, all final close/lock combinations, raw
provenance, the largest exactly representable discussion number, empty sources,
fixed snapshots, malformed and missing histories, authority refusals, independent
pins and semantic corruption even after recomputed hashes. They also exercise
resource bounds, oversized pages with a smaller-page success case, complete
readback before publication, competing creators, linked/replaced files and real
HTTP cancellation. CLI tests launch fresh Node processes for export and offline
inspection, signals, abrupt termination, invalid arguments and closed output.

These peers validate the operator boundary. They do not execute Rust `fg`, a live
deployment or a physical durability test. See [NATIVE_DISCUSSIONS.md](NATIVE_DISCUSSIONS.md)
for the native aggregate, permissions and server-side validation contract.
