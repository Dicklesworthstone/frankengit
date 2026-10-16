# Complete native issue read archives

`exportIssueArchive` in `scripts/lib/forge-issue-archive.mjs` exports the native
issue list and every selected issue's complete versioned action/comment history.
This is the outbound issue-data path, complementary to FG-049's GitHub import.
It consumes the existing `IssueClient` and `issues-read` HTTP endpoints. It adds
no database, native codec, mutation, permission, or alternate runtime to `fg`.

## Read one retained repository snapshot

Supply the exact `/REPOSITORY_ROUTE/ui/issues/` URL, explicit tenant/repository
IDs, a private file containing the existing 64-hex bearer token, and an absent
output directory below a stable private parent. HTTPS is required except for the
shipped client's trusted-loopback profile. The source server must enable issues
and grant the credential `issues-read`; no write or outcome scope is needed.

```js
import { exportIssueArchive, inspectIssueArchive }
  from './scripts/lib/forge-issue-archive.mjs';

const captured = await exportIssueArchive({
  href: 'https://forge.example/project/ui/issues/',
  tenant: '11111111111111111111111111111111',
  repository: '22222222222222222222222222222222',
  tokenFile: '/srv/operator/issues-read-token',
  workdir: '/srv/exports/issues-001',
  pageSize: 10,
  // head: an independently selected native snapshot token, otherwise first read
});
// Retain captured.archive_sha256 independently before inspecting another copy.
const checked = await inspectIssueArchive({
  workdir: captured.workdir, confirm: captured.archive_sha256,
});
```

The first list page selects the head, unless an explicit `head` was supplied.
Every subsequent list/history request uses that exact token. Native retained
ancestor selection allows ordinary intervening writes without mixing snapshots.
If the source no longer supports the selected ancestor, the export refuses; it
never silently restarts at the current head. Every request authenticates the
current grant. See [HTTP_ISSUE_API.md](HTTP_ISSUE_API.md) for source-side bounds.

List order and continuation, issue/history identity, contiguous event versions,
complete histories and fixed source-head metadata are checked. Replaying the
exported actions must reproduce the listed title, body, labels, open/closed state,
assignment set, comment count, opening actor and last actor. Replay is an API
consistency check, not an independent authority implementation or an access grant.
Raw replies are retained as canonical JSON plus a newline; source text is data,
not executable HTML. Rendering is not requested. Historical attribution does not
turn into a local principal or permission.

## Root-last custody and offline inspection

Each checked page is written to `page-NNNNNN.json` through the existing private,
create-only, synchronized/readback writer. Only after the complete walk and a
second offline readback does `archive.json` bind the endpoint, tenant/repository,
snapshot, source head, counts, page order and every page's SHA-256 and length.
No credential or credential fingerprint is put into the manifest.

Inspection requires the independently retained manifest hash, not the original
credential or server. It reads no network, changes no file, validates every page
with the same native decoders and traversal, and rejects missing, reordered,
substituted, noncanonical, linked or unexpected files and inconsistent totals.
A recomputed page hash cannot hide history/state contradictions. Recomputing all
hashes and approving the new root is **not** independent source authentication.

A partial or failed capture leaves diagnostic files without a complete manifest.
It is not a resumable archive and must not be consumed as a successful prefix.
Existing output directories are never overwritten or automatically deleted.
Concurrent creators arbitrate at exclusive directory creation. Cancellation
stops new reads and drains the current HTTP body; no native request is replayed.
An error during final manifest publication may leave a complete or incomplete
root. Error progress retains its expected hash when known; inspect the original
custody instead of treating a lost reply as absence.

## Explicit bounds and non-claims

One operation has a 300-second maximum deadline. Whole-export defaults/ceilings
are 8,192 GET requests/pages, 4,096 issues, 65,536 events, 64 MiB of response bytes
and 64 MiB of local page-plus-manifest data. All may be lowered. The page size is
1–100 (default 10); each response, saved page and manifest is at most 1 MiB.
Select smaller pages for large bodies; oversized pages fail, never truncate.
There are no automatic HTTP retries, mutable cursor sessions or snapshot leases.

The package is a complete, self-consistent **observation through the native API**
within these bounds and the credential's visibility. It is not a canonical
repository backup, original binary forge-event export, signed completeness proof,
retention guarantee, cross-repository transaction or restore/import authority.
Git objects, PRs, reviews, outbox delivery, credentials and canonical transaction
receipts are not exported. Native backup/restore keeps its separate contract.
Stable owner-controlled POSIX parents are required; this is not a hostile same-UID
sandbox or a hardware power-loss durability proof. Node.js 22.16 or later is used.

## Verification

```sh
node --test tests/operator/forge_issue_archive.test.mjs
```

The tests use the complete unchanged production issue client, archive code and
private-file helpers against real loopback HTTP response-schema fixtures. No
client, traversal or custody implementation is stubbed. They exercise list and
comment pagination, both empty and populated sources, the largest exactly
representable issue number, assignment/edit/reopen histories, independent pins,
recalculated-checksum corruption, all resource bounds, competing creators,
real cancellation/body drain and directory replacement. They do not execute
Rust `fg`, a live deployment, the full workspace or a physical durability test.
Related plan areas: section 24 (forge events), section 31 (interfaces), FG-049.
The broader compatibility/import work remains partial.
