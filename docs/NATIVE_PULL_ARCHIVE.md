# Native pull-request portability archive

`scripts/archive_native_pulls.mjs` exports a bounded, read-only observation of every visible native pull request at one retained repository snapshot. For each listed PR it also captures the exact PR metadata response, all review pages, and the complete append-only conversation. This is portability/read custody, **not** merge authority, a canonical repository backup, or permission to recreate reviews in another repository.

The exporter uses the shipped PR transport and native read decoders through a read-only operator adapter. The first list page selects the snapshot unless `--head` supplies an independently retained snapshot token. Every later list, show, review and conversation request stays pinned to that same token. The archive refuses if repository identity, incarnation, object format, source head, or snapshot changes while walking.

## Export

Use the existing `/ui/pulls/` endpoint and a current credential with the independent PR-read grant:

```sh
node scripts/archive_native_pulls.mjs export \
  --workdir /srv/export/pulls \
  --url https://forge.example/repository/ui/pulls/ \
  --tenant 11111111111111111111111111111111 \
  --repository 22222222222222222222222222222222 \
  --token-file /srv/operator/pull-reader.token \
  --page-size 10
```

The destination must be absent below an owner-private 0700 directory. The token is read from an owner-private singly linked regular file and is never copied into the archive. Every saved response is canonical JSON plus one newline. Pages are create-only and synchronized before the final manifest is published. Endpoints reject embedded credentials and require HTTPS outside loopback.

For every visible PR, the exporter saves the list row, an exact `show` response, all review pages, and all conversation pages through the discussion high-water mark. The archive manifest binds repository/incarnation/hash-domain identity, snapshot token, source head, counts, page order, page kinds/cursors, byte lengths and SHA-256 commitments. `archive.json` is written last only after a complete traversal and a second validation pass over every saved page.

## Offline inspection

Retain the returned `archive_sha256` independently. Later inspection needs no bearer credential and performs no network access:

```sh
node scripts/archive_native_pulls.mjs inspect \
  --workdir /srv/export/pulls \
  --confirm "$ARCHIVE_SHA256"
```

Capture and inspection use the same traversal state machine, not independent count checks. Starting at the first list cursor, each listed PR must have an identical `show` row, every review continuation, and every conversation position before the next PR or list page. Review pages retain the PR version and policy epoch; discussion pages retain one high-water mark. The manifest's complete identity must match the first response and every successor. Unavailable subjects, truncated streams, reordered or orphan pages, changed metadata and inconsistent counts refuse even when local hashes have been recalculated. Ordinary v1 archive encoding is unchanged.

Inspection also verifies the exact file set, private single-link custody, all page hashes and lengths, and the manifest pin. It imports only native read decoders: no connection, dummy credential, mutation client or network transport is constructed during inspection.

Review and conversation pages are observations only. A captured approval does not become a merge grant, and an archived actor identity does not authorize replay in another repository. Import/migration must make a separately authenticated destination request and must not reinterpret source review evidence as current destination approval.

## Restartable captures

For a large repository or an unreliable connection, select a snapshot once and
collect bounded batches into a private job. `prepare` accepts the same source,
page-size, optional `--head`, and cumulative ceilings as `export`:

```sh
node scripts/archive_native_pulls.mjs prepare \
  --workdir /srv/export/pull-job \
  --url https://forge.example/repository/ui/pulls/ \
  --tenant 11111111111111111111111111111111 \
  --repository 22222222222222222222222222222222 \
  --token-file /srv/operator/pull-reader.token \
  --page-size 10
```

Independently retain the returned `selection_sha256`. Preparation saves the first
list page, fixes its exact bytes, snapshot, repository identity, credential
fingerprint and all cumulative limits, and publishes the first page checkpoint.
The token itself and its file path are not saved. Continue explicitly:

```sh
node scripts/archive_native_pulls.mjs resume \
  --workdir /srv/export/pull-job --confirm "$SELECTION_SHA256" \
  --token-file /srv/operator/pull-reader.token --page-budget 128

node scripts/archive_native_pulls.mjs status \
  --workdir /srv/export/pull-job --confirm "$SELECTION_SHA256"
```

`resume` uses at most `--page-budget` fresh page requests per invocation (default
128, ceiling 16,384). Exit **3** and `complete:false` mean a valid paused capture;
invoke `resume` again using the same selection pin. Only a finished capture has
`complete:true` and an `archive_sha256`. Page, PR, review, comment and byte limits
include every earlier invocation; resumption cannot change them or refresh the
snapshot. The deadline applies to one invocation, including prefix validation.
No unpinned fallback or automatic HTTP retry is performed. A missing/expired
source snapshot or a changed credential refuses continuation. A different token
file path is permitted only when it contains the original credential bytes.

The job contains immutable `selection.json`, `archive/page-*.json`, and a bounded
`journal/page-*.json` chain. Each checkpoint binds its predecessor and the exact
next request, page bytes and SHA-256. Resume validates the entire retained prefix
and re-synchronizes the private files before requesting more. Existing pages are
not downloaded again. One valid page left between page publication and checkpoint
publication is re-fetched at the original snapshot; only an exact byte match
allows its checkpoint to be added. Concurrent collectors arbitrate create-only
page/checkpoint slots; a loser refuses instead of overwriting or stealing a lock.
A stopped process leaves no stale lock to clear.

`status` needs no token and performs no network requests or explicit file writes.
Its `checkpointed_pages` and `uncommitted_tail` distinguish confirmed progress
from a page awaiting revalidation. A complete job, or a fully checkpointed job
awaiting only final root publication, can be resumed without `--token-file` or
network access. Finalization revalidates the complete ordinary v1 archive and
publishes `archive/archive.json` last. The child archive has the same format and
bytes as a one-shot export of the same observations:

```sh
node scripts/archive_native_pulls.mjs inspect \
  --workdir /srv/export/pull-job/archive --confirm "$ARCHIVE_SHA256"
```

Exit **0** means the selected operation succeeded; `prepare` and `status` may
successfully report incomplete progress. Exit **2** means refusal/invalid input.
Exit **4** means an error with retained or potentially published custody/result;
inspect the reported pins and progress rather than inferring completion from the
exit code. A broken output pipe never resubmits reads or deletes the retained job.

Recovery is for jobs created by `prepare`, not arbitrary partial one-shot export
directories. A torn, corrupt or partially written selection, page or checkpoint
refuses in place and is never automatically repaired, truncated or removed.
Missing initialization files likewise refuse. The checkpoint chain is local
integrity evidence, not server authentication or a defense against a hostile
same-UID writer. Keep the returned checkpoint and final archive hashes separately
when retaining independent progress/completion evidence.

## Bounds and failure model

Defaults/ceilings are 16,384 saved pages, 4,096 PRs, 65,536 reviews, 65,536 conversation comments, 64 MiB for pages plus manifest, 1 MiB per HTTP response/page, and 4 MiB for the manifest. The separate manifest envelope fits the advertised page inventory; it does not raise a response's allocation limit. Page size is 1–100, default 10. The operation deadline is at most 300 seconds. Page/request and aggregate bounds span the whole export. Exceeding any bound refuses the export; successful prefixes are never labeled complete.

Capture-job overhead is separately bounded to 16 KiB of selection data and 16,384 checkpoint files of at most 1 KiB each (at most 16 MiB of journal content), in addition to the archive limits. File contents, rather than filesystem block overhead, are counted.

SIGTERM/SIGINT cancel read work. A partial directory has no valid root manifest and must not be consumed as complete. Existing output paths are never overwritten or repaired automatically. Local page custody is not a retention lease for the server-side historical snapshot.

This archive does not include Git objects, candidate bundles, diffs, workflow checks, webhook delivery state, repository credentials, transaction-outcome records, or original canonical forge-event frames. Those remain separate surfaces. Reviews are each reviewer's latest API-visible state, not the original review event log. A source server's observation is not a cryptographic proof of canonical history. Filesystem checks do not establish protection from a hostile process with the same UID or hardware power-loss durability.

## Verification

Focused local validation:

```sh
bash scripts/verify_native_pull_archive.sh
```

The original injected-backend tests remain. Additional tests execute the unchanged production transport and native decoders against a real loopback HTTP response-schema peer and real private files, covering both Git hash domains, pagination, metadata consistency, semantic truncation with recalculated hashes, allocation bounds, cancellation and credential-free readback. A 128-PR/512-page case exercises HTTP export and inspection. A separate batched-file fixture validates the real traversal and offline reader at 4,096 PRs and all 16,384 page descriptors; it is not full-capacity HTTP export/fsync evidence. An attempted full-capacity HTTP run exceeded a 120-second test deadline, so no maximum-population export latency claim is made. Restart tests cover per-page pause/resume, cumulative bounds, credential and snapshot changes, concurrent collectors, page/checkpoint crash windows, offline finalization, and broken output. CLI tests start real Node child processes, send SIGTERM/SIGINT/SIGKILL during a stalled continuation response, then resume in a new process without re-downloading checkpointed pages. Torn-file refusals and the page/checkpoint write gap are separate controlled filesystem fixtures, not power-loss tests. None of these tests executes Rust `fg`, native admission/CAS, a deployed server, or the full workspace.
