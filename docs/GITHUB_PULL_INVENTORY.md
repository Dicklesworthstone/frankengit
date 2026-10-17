# Repository-wide GitHub PR selection

FG-049 (`frankengit-fg049-github-compat-xdo`), comprehensive plan §31.3.
The existing [GitHub PR migration](GITHUB_PULL_MIGRATION.md) captures at most
100 explicitly named PRs. This read-only operator discovers a bounded complete
visible membership and pins its partition into ordinary capture batches. It does
not create native requests, transfer Git objects, or import approvals.

## Discover, inspect, capture

```sh
node scripts/discover_github_pulls.mjs discover \
  --repository OWNER/REPO --batch-size 25 \
  --out /srv/import/pr-inventory.json --token-file /srv/import/github-reader.token

node scripts/discover_github_pulls.mjs inspect \
  --inventory /srv/import/pr-inventory.json --confirm "$INVENTORY_SHA256" --batch 1

node scripts/discover_github_pulls.mjs capture-batch \
  --inventory /srv/import/pr-inventory.json --confirm "$INVENTORY_SHA256" \
  --batch 1 --out /srv/import/pr-capture-1.json --token-file /srv/import/github-reader.token
```

Independently retain `inventory_sha256` returned by discovery. Membership consists
of native GitHub PR numbers and exact GitHub PR IDs, not the issue IDs returned
by the issues endpoint. Numbers are safe integers; IDs preserve their full u64
value as decimal strings. Repository numeric identity and canonical name are
retained. Batch size is committed with the membership; a later invocation cannot
silently repartition an existing inventory. Empty repositories have zero batches.

Discovery reads `GET /repos/OWNER/REPO/pulls` with `state=all`, `sort=created`,
`direction=asc`, `per_page=100`. It brackets each complete listing with repository
identity reads and requires two identical canonical membership observations.
Closed, merged and draft PRs remain members. It does not use GitHub search and
its result window, or infer PR membership from issues. A full final page without
a Link header gets an additional empty-page probe. Short/empty pages advertising
a successor, duplicate records, changed identities, pagination scope changes and
configured-bound exhaustion refuse rather than reporting a successful prefix.
Creation-time ties need not have numeric ordering; the observed set is sorted by
PR number only after the complete pass. Every pagination URL is validated, but
requests are constructed locally under the fixed api.github.com origin.

This is **two equal membership observations, not an atomic GitHub snapshot**.
It pins aliases and membership, not PR bodies or branch tips. Each subsequent
capture still performs the existing two complete metadata/discussion/review/
inline observations. The selected repository ID/name and every selected PR ID
must match the inventory before stream capture. Reusing a name or number for a
different repository/PR refuses. PRs created after discovery are not silently
added; deleted/inaccessible selected PRs cannot become successful empty captures.
Quiesce source edits during migration. These checks do not prove that nothing
changed between observations, nor prove completeness against a dishonest server.

A successful batch is the unchanged `frankengit-github-pull-capture-v1` format.
Use its separately returned `capture_sha256` with `migrate_github_pulls.mjs
prepare`. The inventory pin is not a capture pin or a native plan pin. Output
includes `first_index`, `total_batches` and `next_batch` so the caller can assign
non-overlapping destination number ranges explicitly. No native collision search,
renumbering, branch provisioning or destination write occurs here.

Each capture retains the original limits: 100 PRs, 2,000 combined discussion/
review/inline records, and 1 MiB of normalized content. An oversized batch refuses;
it is never truncated or automatically split into a different pinned partition.
Choose a smaller batch size before preparing downstream plans. Never regenerate
a native request merely to escape uncertainty about an already attempted write.

## Bounds and custody

Discovery is bounded to 10,000 PRs and a 1 MiB inventory. `--max-pulls` can lower
the population limit. Batch size is 1–100 (default 25). The existing shared source
transport bounds each response to 8 MiB, requests to 4,096 and total decoded
response bytes to 64 MiB by default (at most 256 MiB). `--max-requests` and
`--max-read-bytes` select those request/byte limits. Source HTTP reads never retry
automatically. The 1–300,000 ms command deadline includes private-file validation,
source reads, output publication and bounded output. SIGTERM/SIGINT cancel source
work. No source token is printed, stored in a capture/inventory, accepted as an
argument value or sent to a pagination-selected foreign origin.

Private output files are create-only, synchronized and read back through the
existing operator file helpers. No overwrite, repair or deletion is attempted.
The output path and token must be outside Git worktrees. Inspection is offline;
public source resources may be read without a token. Exit 0 means the selected
operation succeeded, 2 means refusal, and 4 means an error with retained or
potentially published custody/output. A broken output pipe retains the original
pin in its diagnostic rather than repeating source requests.

Library callers may use `createGithubPullCaptureSession`. One owner has a single
HTTP/deadline/decoded-byte allowance across all its sequential captures. Overlap
refuses, and a failed network capture closes the owner. `captureGithubPulls`
remains compatible and delegates to this same implementation. An optional
`expectedSelection` binds `{source:{id,full_name},pulls:[{number,id}]}`; it is
validated and detached before asynchronous work. It never supplies executable
code, a transport implementation or a new source endpoint from a file.

## Verification

```sh
bash scripts/verify_github_pull_inventory.sh
```

The focused suite includes the unchanged original PR-capture tests, real loopback
HTTP discovery and batch capture, the 10,000-member bound, identity substitutions,
foreign/duplicate/reordered pagination, exact-full EOF probes, numeric aliases,
shared capture budgets, caller mutation, private files, broken output and actual
Node CLI processes interrupted by SIGTERM/SIGINT/SIGKILL. A test-only fetch adapter
maps the fixed GitHub origin onto a response-schema peer; production exposes no
source URL override. This is not live GitHub, native Rust admission/CAS, a native
server capacity test, hardware durability or a full-workspace/release gate.

The source contract is GitHub's REST documentation for
[list pull requests](https://docs.github.com/en/rest/pulls/pulls#list-pull-requests)
and [pagination](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api).
The shared API version and transport are unchanged. The wider compatibility bead
remains partial; this inventory does not establish canonical forge history.

## Collect all batches with restartable custody

For a whole inventory, use the [restartable collection workflow](GITHUB_PULL_COLLECTION.md)
instead of manually tracking separate `capture-batch` files. It retains the pinned
inventory, validates every completed capture/checkpoint on restart, shares one
source request/byte budget across each invocation, and publishes a final content
commitment only when all batches are captured. It never changes an existing
native destination plan or claims an atomic GitHub snapshot.
