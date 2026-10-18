# Restartable repository-wide GitHub PR collection

FG-049 (`frankengit-fg049-github-compat-xdo`), comprehensive plan §31.3.
This read-only operator collects every batch of an independently pinned
[GitHub PR inventory](GITHUB_PULL_INVENTORY.md) into ordinary, bounded
[PR captures](GITHUB_PULL_MIGRATION.md). It never creates native requests or
replaces original destination keys, imports objects, provisions branches, submits
reviews or changes repository authority. It is source portability custody, not
an atomic GitHub snapshot or a canonical backup.

## Prepare once, collect in bounded invocations

First discover the repository membership with `discover_github_pulls.mjs` and
retain its `inventory_sha256`. Choose the batch size before collection: the
partition is part of the inventory pin, not a mutable per-invocation option.
Then prepare a new private directory outside Git worktrees:

```sh
node scripts/collect_github_pulls.mjs prepare \
  --inventory /srv/import/pr-inventory.json \
  --inventory-confirm "$INVENTORY_SHA256" \
  --workdir /srv/import/pr-collection

node scripts/collect_github_pulls.mjs run \
  --workdir /srv/import/pr-collection --confirm "$COLLECTION_PLAN_SHA256" \
  --token-file /srv/import/github-reader.token --max-batches 5

node scripts/collect_github_pulls.mjs status \
  --workdir /srv/import/pr-collection --confirm "$COLLECTION_PLAN_SHA256"
```

`COLLECTION_PLAN_SHA256` is the new `plan_sha256` returned by preparation.
Preparation is offline. It retains the original inventory and cumulative saved
capture/record limits, synchronizes the new directories and inventory, and
publishes `plan.json` last. It generates no native idempotency key. The original
inventory file can be removed after preparation.

`run` captures at most `--max-batches` batches per invocation (default 5, at most
10,000). A valid paused run returns exit **3** and `complete:false`. Invoke `run`
again with the same plan pin; do not prepare a replacement collection to avoid
an unresolved native request in a downstream migration. The collector checks the
whole retained prefix before reading a token or contacting GitHub. Completed
checkpointed batches are not downloaded again. A public repository needs no
token. Source credentials are read only from explicitly selected private files;
they are never retained in the collection or printed.

Each batch uses the existing capture algorithm and unchanged v1 format. It
checks repository identity and every selected PR number/ID against the original
inventory, brackets metadata and complete discussion/review/inline streams, and
requires two equal complete observations. The same capture owner shares its
HTTP request, decoded-response-byte and deadline allowance across all batches
within an invocation. It never renews that allowance merely because a batch
finished. A new explicit invocation has a new network allowance; saved capture
bytes and record counts remain cumulative across the entire collection.

## Completion is a separate content pin

A job contains only these fixed files and directories:

```text
plan.json
inventory.json
captures/batch-000001.json ...
journal/batch-000001.json ...
complete.json                 # published last, after all batches validate
```

A checkpoint binds the collection plan, batch number, predecessor checkpoint,
exact capture SHA-256, byte length, PR count and record count. The chain begins
at the plan pin. Every body and checkpoint is owner-private, create-only,
synchronized and read back through the existing operator file helpers. The
collector verifies exact file inventories, gap-free ordering, membership, all
commitments, cumulative bounds, and record-ID uniqueness within each stream
across all batches. No directory entry or file count alone proves completion.

Only a fully checkpointed collection can publish `complete.json`. Finalization
re-reads all retained files first. The final descriptor binds the inventory,
plan, final checkpoint, total batches/PRs/records/bytes and explicit non-atomic
consistency. Independently retain the returned **`complete_sha256`**: the plan
pin fixes membership and limits, while the completion pin also binds captured
content. A valid collection assembled in different invocation-sized batches has
the same final bytes when the source observations are identical.

`status` is credential-free and performs no network requests or explicit file
writes. It reports `checkpointed_batches`, `uncheckpointed_batch`, `next_batch`,
`ready_to_seal`, and `complete` separately. To verify an independently retained
completion commitment:

```sh
node scripts/collect_github_pulls.mjs status \
  --workdir /srv/import/pr-collection --confirm "$COLLECTION_PLAN_SHA256" \
  --complete-confirm "$COMPLETE_SHA256"
```

A completed collection returns offline. A job with all checkpoints but no final
descriptor can also finalize offline, without source credentials. Neither case
rechecks current GitHub state; it verifies the retained observations.

## Resume and failure boundaries

SIGTERM/SIGINT cancel source work. SIGKILL may leave the last capture without its
checkpoint. If that body is complete and valid, resumption runs a fresh full
two-observation capture of exactly that original batch. Only an exact byte match
allows its checkpoint to be added. The retained body is never replaced with a
newer observation. This single uncheckpointed body is reported separately and
counts against cumulative bounds. A torn, invalid, or changed body/checkpoint,
missing initialization file, extra file, gap, unsafe link, or replaced directory
refuses in place. No repair, truncation, deletion or stale-lock stealing occurs.

Concurrent collectors can perform duplicate source GETs, but create-only body/
checkpoint slots arbitrate publication. A loser refuses rather than overwriting
another collector. There is no global lock to abandon after process termination.
A failed invocation may have checkpointed earlier batches; `status` reports what
is actually retained. Output failure preserves its result and completion pin in
a bounded diagnostic instead of repeating source reads.

Each batch consists of two equal observations; **the collection is not two equal
whole-repository snapshots**. Batches may be captured at different times. Quiesce
source edits while collecting. Newly created PRs after discovery are not silently
added, and inaccessible selected PRs cannot become successful empty captures.
The final schema records `independent-two-equal-batches-not-atomic`. Hashes are
local integrity commitments, not signatures or proof against a dishonest source
or a hostile same-UID writer. File synchronization is not a hardware power-loss
durability guarantee.

## Handoff to the unchanged native migration compiler

Only a collection with the independently confirmed final root can select a batch
for handoff. This command revalidates the complete collection and returns an
existing ordinary capture path, its own capture pin, and its membership:

```sh
node scripts/collect_github_pulls.mjs batch \
  --workdir /srv/import/pr-collection --confirm "$COLLECTION_PLAN_SHA256" \
  --complete-confirm "$COMPLETE_SHA256" --batch 2 --number-start 1000
```

Optional `--number-start` is the destination start for the **whole inventory**.
The result's `destination_number_start` is that start plus the selected batch's
zero-based first member index. Arithmetic uses exact decimal u64 values and
checks the end of the entire inventory window for overflow. Use the same whole-
inventory start for every batch; using a different start is a new explicit caller
choice, not something the source collection authorizes. No collision search,
renumbering or native request generation occurs here.

Put the returned `destination_number_start` into that batch's destination
selection, then use `capture_file` and `capture_sha256` with the existing
`migrate_github_pulls.mjs prepare`. The existing compiler remains responsible for
native title/body/form limits, SHA-1 domain, explicit merged/draft consent, exact
historical branch requirements and attribution-only review comments. Source
collection success does not waive any destination precondition. Retain every
new native plan's independent pin and original keys; execute/recover those plans
through the existing migration workflow. Existing destination plans must not be
regenerated to obtain replacement keys after ambiguous sends.

This feature does not atomically prepare or execute all destination batches.
Git objects and exact branches must still be provisioned separately. It cannot
make hidden-only, deleted or fork-only objects available from an OID, convert
source reviewers into native principals, or restore active approvals.

## Bounds and verification

Inventory: at most 10,000 PRs and 1 MiB. Each capture retains at most 100 PRs,
2,000 combined discussion/review/inline records and 1 MiB. The collection limits
saved capture content to **64 MiB** and combined records to **200,000**. Preparation
may lower `--max-capture-bytes` or `--max-records`. These values cannot be changed
by a later run. An oversized batch refuses; it is never truncated or repartitioned.
Selection of a small enough inventory batch size remains an operator decision.

Control overhead is separately bounded to a 1 MiB inventory, 1 KiB plan, 1 KiB
final descriptor, and at most 10,000 checkpoints of 1 KiB each. These counts cover
file contents, not filesystem block overhead. One invocation accepts
`--max-requests` 1–4,096 and `--max-read-bytes` 1–256 MiB (default 64 MiB), sharing
those bounds across all batch captures. An individual response retains the
existing 8 MiB ceiling. There is no automatic source HTTP retry or custom source
endpoint. All commands accept `--timeout-ms` 1–300,000, including local preflight,
readback and bounded output; native destination operations are never started.

Exit **0** means the selected operation succeeded. Preparation/status can succeed
while the collection is incomplete. Run exit **3** means a valid paused prefix;
**2** means argument or preflight refusal; **4** means an error with a retained/
verified plan or output result. Read `complete` and the returned commitments,
not just the exit code. No output or local file grants repository authority.

```sh
bash scripts/verify_github_pull_collection.sh
```

The suite runs the complete original capture and inventory tests plus collection
success, corruption, cumulative budgets, source identity changes, cross-batch
record duplication, concurrent collectors, directory replacement, uncheckpointed
body recovery, source removal, deterministic final roots, and a real 101-PR HTTP
collection split across five captures. Actual Node CLI processes are interrupted
with SIGTERM/SIGINT/SIGKILL during a later batch and resumed without downloading
an earlier checkpointed batch. The unchanged downstream import compiler and
native request codec compile collected batches with exact u64 disjoint numbering,
byte-identical direct-capture plans, unchanged Git tips and explicit consent.

The peer is a loopback HTTP response-schema fixture, not live GitHub or native
Git/authority. A test-only fetch adapter maps the fixed GitHub origin to the peer;
the product exposes no endpoint override. Torn-file cases are controlled local
fixtures, not physical power-loss tests. No Rust server, native reachability/
admission/CAS, full-workspace, 10,000-PR full-content collection throughput, or
release gate is claimed. No Rust, dependencies, native retry formats or grant
rules change. The wider FG-049 feature remains partial.
