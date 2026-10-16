# Native pull-request portability archive

`scripts/archive_native_pulls.mjs` exports a bounded, read-only observation of every visible native pull request at one retained repository snapshot. For each listed PR it also captures the exact PR metadata response, all review pages, and the complete append-only conversation. This is portability/read custody, **not** merge authority, a canonical repository backup, or permission to recreate reviews in another repository.

The exporter uses the shipped PR client and its native decoders. The first list page selects the snapshot unless `--head` supplies an independently retained snapshot token. Every later list, show, review and conversation request stays pinned to that same token. The archive refuses if repository identity, incarnation, object format, source head, or snapshot changes while walking.

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

The destination must be absent below an owner-private 0700 directory. The token is read from an owner-private singly linked regular file and is never copied into the archive. Every saved response is canonical JSON plus one newline. Pages are create-only and synchronized before the final manifest is published.

For every visible PR, the exporter saves the list row, an exact `show` response, all review pages, and all conversation pages through the discussion high-water mark. The archive manifest binds repository/incarnation/hash-domain identity, snapshot token, source head, counts, page order, page kinds/cursors, byte lengths and SHA-256 commitments. `archive.json` is written last only after a complete traversal and a second validation pass over every saved page.

## Offline inspection

Retain the returned `archive_sha256` independently. Later inspection needs no bearer credential and performs no network access:

```sh
node scripts/archive_native_pulls.mjs inspect \
  --workdir /srv/export/pulls \
  --confirm "$ARCHIVE_SHA256"
```

Inspection verifies the manifest hash, exact file set, every page digest/length, pinned repository identity, native list/show/review/conversation schemas, source-head consistency, and that every listed PR has exactly one saved `show` response. Unknown files, changed page bytes, missing pages, duplicate PRs, or inconsistent counts refuse the complete archive.

Review and conversation pages are observations only. A captured approval does not become a merge grant, and an archived actor identity does not authorize replay in another repository. Import/migration must make a separately authenticated destination request and must not reinterpret source review evidence as current destination approval.

## Bounds and failure model

Defaults/ceilings are 16,384 saved pages, 4,096 PRs, 65,536 reviews, 65,536 conversation comments, 64 MiB of saved page data and 1 MiB per response/page. Page size is 1–100, default 10. The operation deadline is at most 300 seconds. Exceeding any bound refuses the export; successful prefixes are never labeled complete.

SIGTERM/SIGINT cancel read work. A partial directory has no valid root manifest and must not be consumed as complete. Existing output paths are never overwritten or repaired automatically. Local page custody is not a retention lease for the server-side historical snapshot.

This archive does not include Git objects, candidate bundles, diffs, workflow checks, webhook delivery state, repository credentials, transaction-outcome records, or original canonical forge-event frames. Those remain separate surfaces.

## Verification

Focused local validation:

```sh
bash scripts/verify_native_pull_archive.sh
```

The operator tests exercise root-last publication, snapshot pin propagation, list/show/review/conversation traversal, digest commitments, corruption, unexpected-file refusal and resource bounds with explicit native-schema peers. They do not execute Rust `fg`, native admission/CAS, or a deployed server.
