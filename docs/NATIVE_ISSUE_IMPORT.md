# Import a native issue archive as new issues

This external operator connects `readIssueArchive` to the existing native issue
request client and exact-key issue sender. It is an issue-data migration, **not
canonical backup/restore**, original audit-event replay, or an authority grant.
Related product work: FG-049 and the plan's import/export API surface.

The bounded archive reader shares the complete traversal, page commitments,
state/history consistency checks and original independent manifest pin with
`inspectIssueArchive`. It returns owned current snapshots and discussion comments
only after the ENTIRE archive validates. No caller callback sees a valid-looking
prefix. The existing inspector's result and archive format are unchanged.

`partitionNativeIssueArchive` compiles current issue title/body/labels, every
comment in source-version order, and final open/closed state into normal native
`open`, `comment`, and optional `close` commands. An explicit nonnegative number
offset selects destination numbers. Destination expected versions start at zero;
source versions and principals are never used as destination authority.

The opening body and each comment retain clearly labelled provenance: archive
pin, exact source endpoint/repository/snapshot, original issue number, source
version and actors. Source assignees are retained in that metadata, NOT applied
as destination assignments. Labels retain their names, not permissions. Prior
edit/reopen/assignment history remains in the original archive, not reconstructed
as destination audit history. The destination's authenticated caller owns new
events. Keep the original archive separately when that history is needed.

## Library path

`readIssueArchive({ workdir, confirm, signal, timeoutMs })` is exported from
`scripts/lib/forge-issue-archive.mjs`. `confirm` is the independently retained
archive manifest SHA-256, not one recomputed from an untrusted replacement.

Pass its complete result and the chosen offset to `partitionNativeIssueArchive`
from `scripts/lib/native-issue-source.mjs`. Every returned batch owns validated
`bytes`, `sha256`, issue membership and a step count. It uses the source-specific
`frankengit-native-issue-capture-v1` schema; it never pretends to be a GitHub
capture. Empty archives produce a typed refusal rather than an empty import.

Save each selected batch privately, then the APIs in
`scripts/lib/native-issue-import.mjs` expose:

- `prepareNativeIssueImport`: explicit destination URL ending in `/ui/issues/`,
  tenant/repository, native token file, absent private workdir, capture file and
  offset. Preparation contacts no server. Retain its returned `plan_sha256`.
- `inspectPreparedNativeIssueImport`: verifies all retained requests and source
  bytes against that plan and original credential without network access.
- `runNativeIssueImport`: `operation: 'run'` or `'status'` and the original
  `confirm` pin. Status makes outcome queries, never issue mutations. A run
  queries original keys before dispatch; `retryUnresolved: true` explicitly
  authorizes retrying an uncertain original request, never replacing it.

These are the same native request framing, key commitment, create-only custody,
per-step starts/terminals, sender ownership, budgets and recovery used by the
existing issue importer, factored in `issue-import-engine.mjs`. Native and GitHub
source schemas cannot be interchanged on restart. A known refusal stops later
commands. A missing reply is not non-commit. A parsed terminal is retained across
later cancellation/output errors. Do not delete an occupied or uncertain workdir
or its locks to obtain another execution identity.

## Bounds and validation

Complete source bounds remain 4,096 archived issues and 65,536 source events.
The import profile permits at most 128 batches and 10,000 NEW command steps.
Each batch permits 100 issues, 2,000 comments, a 1-MiB source package, a 1-MiB
compiled plan and the sender's 16-MiB saved-request allowance. Partitioning counts
actual encoded bytes including attribution expansion and delimiters. One issue
is indivisible. An oversized issue, comment or provenance-expanded body refuses;
no body is truncated or silently split into a different discussion. An archive
that can be exported is not guaranteed to fit the import envelope.

Source files must remain stable, private and owner-controlled. The output is
create-only. These are not hostile same-UID isolation or power-loss proofs.
Node.js 22.16 or later is the tested operator runtime. No Rust code, dependency,
Git object, PR, review, credential, outbox settlement or native protocol changes.

Run `node --test tests/operator/native_issue_import.test.mjs`. The tests execute
the complete production archive reader, native issue client, source compiler,
private-file operations and exact-key sender against a loopback response-schema
peer. They are not a Rust fg server, live deployment or whole-workspace test.

## Complete archive-to-destination command

The `scripts/migrate_native_issues.mjs` command runs the complete bounded
archive import without hand-writing capture files or calling each batch.
Use Node.js 22.16 or later with stable owner-private POSIX directories. Export
and independently review the source archive first using `archive_native_issues.mjs`.
Keep its original `archive_sha256` as `ARCHIVE_SHA`. The destination requires its
own current scoped native credential; source archive possession is never a grant.

```sh
node scripts/migrate_native_issues.mjs prepare \
  --archive /srv/migration/source-archive --archive-sha256 "$ARCHIVE_SHA" \
  --workdir /srv/migration/native-prepared \
  --url https://forge.example/repository/ui/issues/ \
  --tenant 11111111111111111111111111111111 \
  --repository 22222222222222222222222222222222 \
  --token-file /srv/operator/native-token --offset 1000
```

Replace the example path, URL, identities and offset with the selected deployment.
The exact URL ends in **`/ui/issues/`**, as required by the shipped issue client.
The output directory must be absent and disjoint from the archive and token.
One source issue remains indivisible: its entire discussion fits one batch or
preparation refuses, rather than silently dropping comments. The complete source
is validated and compiled before a destination request key is created.

Preparation owns copies of the selected current snapshots and discussion
comments in `capture-NNNNNN.json`. Each corresponding `batch-NNNNNN/` holds the
shared import engine's original requests, keys and immutable plan. After all
captures and child plans pass a second readback, `migration.json` is synchronized
last. Retain its returned `plan_sha256` independently as `PLAN_SHA`. A partial
preparation keeps diagnostic custody without a runnable root; the command never
overwrites it, automatically starts execution, or implicitly retries preparation.

```sh
node scripts/migrate_native_issues.mjs inspect \
  --workdir /srv/migration/native-prepared --confirm "$PLAN_SHA" \
  --url https://forge.example/repository/ui/issues/ \
  --tenant 11111111111111111111111111111111 \
  --repository 22222222222222222222222222222222 \
  --token-file /srv/operator/native-token

node scripts/migrate_native_issues.mjs run \
  --workdir /srv/migration/native-prepared --confirm "$PLAN_SHA" \
  --url https://forge.example/repository/ui/issues/ \
  --tenant 11111111111111111111111111111111 \
  --repository 22222222222222222222222222222222 \
  --token-file /srv/operator/native-token --max-mutations 100
```

`inspect` is offline. Every capture, ordered source population, original request,
credential binding, count and byte total is checked. `run` performs that complete
preflight before the first outcome query, then submits through the same issue
API and exact-key operator used by GitHub imports. Target number collisions
remain native refusals. The tool never overwrites an existing issue or refreshes
an expected version to evade a collision.

After preparation, no source server, source credential, or external archive path
is needed to run, inspect or recover. The import retains the selected snapshots
and comments, **not the original complete edit/assignment/reopen history**. Keep
the original full archive separately when historical evidence matters. Imported
body text contains a labelled provenance prefix followed by the complete source
body; it is not claimed to be byte-identical to an unprefixed source body.

## Restart, uncertainty and shared ownership

Run the same command after a mutation-budget stop to continue at the original
keys. Previously committed requests are queried rather than resent. A started
request with an unknown outcome stops execution unless the operator explicitly
adds `--retry-unresolved`. That choice queries and may resend the exact original
request through the native retry protocol; it cannot re-key or reprepare it.
A terminal refusal stops new sending, including with explicit retry.

Use the same destination flags and pin with `status` to query every prepared
batch. It does not submit issue mutations, including while the parent sender
lock is retained. Within each child it retains the original contiguous-prefix
outcome walk, not an independent query of every later unstarted request. It may
save newly observed terminal receipts locally; `remote_read_only` does not mean
that local custody is unchanged. Neither a missing key nor any exit code proves
non-commit. Results observed at different times are not one canonical snapshot.

A create-only `migration.sender.lock` owns a complete sending invocation, and
each child retains its existing `sender.lock`. Source-specific schemas distinguish
native from GitHub plans. The shared `issue-import-engine.mjs` and
`issue-migration-execute.mjs` own both lifecycles; the GitHub entrypoints are thin
compatibility wrappers preserving their original schemas and request bytes.
Do not independently run a child importer alongside the full coordinator:
legacy child callers do not acquire the parent lock.

SIGTERM/SIGINT cancel further work and drain the current HTTP operation. Known
terminal decisions survive late cancellation and output errors. SIGKILL can
leave both locks and original start markers; no PID-based lock stealing or
automatic lock deletion is implemented. Reconcile the original sender before
explicit repair. Directory/lock substitutions are refused, not cleaned up as
the original owner. Preserve the complete private directory and independent pins.

## Whole-migration limits and command outcomes

Preparation can lower `--max-steps` (10,000 maximum), `--max-capture-bytes`
(64 MiB) and `--max-request-bytes` (128 MiB). The latter counts all saved child
request records; every child receives only the remaining allowance, capped by
its 16-MiB ceiling. All source packages remain subject to the bounds above.
Each complete issue archive may still contain a discussion too large to import.

`--max-mutations` covers all children in one invocation (default 100, maximum
10,000). It counts calls to the existing retry operation, which may find a
committed outcome without an HTTP mutation; it is not a count of POST requests.
After exhaustion, only status queries are allowed. One absolute deadline covers
preflight and all children: `--timeout-ms` defaults to 300,000, capped at 300,000
for prepare/inspect and 3,600,000 for run/status. A child receives the remaining
time, never a replenished allowance. Unknown submission accounting is reported
as incomplete, never as zero work.

Output is one JSON row, bounded to 4 MiB and a ten-second write wait, with terminal
controls escaped. Exit 0 means the explicit offline phase completed or every
native step was observed committed; 1 means canonical refusal; 3 means bounded
incomplete/uncertain progress; 2 means invalid input or read failure before
validated progress (including an unavailable sender lock); 4 means a returned
operation or committed progress was known but later work, output or cleanup
failed. Error output preserves original pins, known progress and terminal
coordinates where available. A broken consumer does not restart execution.

## Reproducible evidence scope

```sh
bash scripts/verify_native_issue_import.sh
```

The tests run the full production archive reader, source compiler, child sender,
complete-migration preparer/inspector/executor, CLI, issue client and POSIX custody
without replacing those imports. Actual loopback HTTP peers supply native
response schemas, not Rust implementation or authority. Real CLI child-process
tests exercise restart, SIGTERM/SIGINT, SIGKILL after dispatch starts, locks,
collisions, deadlines and output failures. Source-only boundary tests check
4,096 issues and exactly 10,000 new commands; they are not a full native migration
throughput benchmark. One explicit coordinator compatibility test injects its
old inspector/child boundary to pin the GitHub wrapper's unchanged envelope.

The fixed-input GitHub golden is derived from original import source blob
`5772c2dfce213bb1e91d2e2278c70d38381a77d3`. With a test-only deterministic RNG,
every retained capture, request and plan byte hash is unchanged after extraction.
Production continues to use cryptographic randomness. Separate tests drive the
actual GitHub wrapper through native HTTP response-schema peers as well.

This is not a Rust fg server run, native admission/CAS proof, live deployment,
whole-workspace pass, canonical restore or filesystem power-loss evidence. No
Rust source or dependency changed. The broader import/compatibility work remains
partial; Git objects, PRs, reviews, permissions and original native audit identity
are not recreated by this issue-data migration.
