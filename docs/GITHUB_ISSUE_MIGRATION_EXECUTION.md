# Execute a complete pinned issue migration

`scripts/migrate_github_issues.mjs` runs every prepared batch from
[the complete GitHub issue migration](GITHUB_ISSUE_MIGRATION.md). It composes the
existing `runGithubIssueImport` operator, not another mutation codec, Git engine,
credential scheme or authority. The native issue API continues to authorize and
publish each original request. Related work: FG-049.

## Prepare and inspect without custom scripts

Node.js 22.16 or later and owner-private POSIX files are required. First obtain
and independently pin the complete inventory and all corresponding captures
using the existing capture workflow. Create a private selection file in one of
these encodings: `JSON.stringify(selection) + "\n"` or
`JSON.stringify(selection, null, 2) + "\n"` (one final newline). Arbitrary
formatting, duplicate keys, rounded counters and byte-order marks are refused.
The selection file is limited to 1 MiB and 128 uniquely numbered captures.

The shape is shown below; replace every placeholder with the actual independently
retained lowercase SHA-256 and every path with the selected absolute input path.
Do not infer source trust by merely hashing a newly downloaded unverified file.

```json
{
  "schema": "frankengit-github-issue-migration-sources-v1",
  "inventory": {
    "path": "/srv/migration/input/inventory.json",
    "sha256": "<independently-retained-inventory-sha256>"
  },
  "captures": [
    {
      "batch": 1,
      "path": "/srv/migration/input/capture-000001.json",
      "sha256": "<independently-retained-first-capture-sha256>"
    },
    {
      "batch": 2,
      "path": "/srv/migration/input/capture-000002.json",
      "sha256": "<independently-retained-second-capture-sha256>"
    }
  ],
  "offset": 1000,
  "maxSteps": 10000,
  "maxCaptureBytes": 67108864,
  "maxRequestBytes": 134217728
}
```

`offset` and all three limits are optional; omitting them preserves the existing
preparer defaults. Source selection cannot override a destination, credential,
operation, retry policy or expected repository version. Capture ordinals must
cover 1 through N exactly; file paths cannot repeat. The original preparer still
verifies complete population membership, cross-capture comment identities,
source pins, native request bounds and original credential binding.

Retain the selection file's own SHA-256 separately, then prepare into an absent
directory below a stable private parent:

```sh
node scripts/migrate_github_issues.mjs prepare \
  --workdir /srv/migration/prepared \
  --sources /srv/migration/input/sources.json --sources-sha256 "$SOURCES_SHA256" \
  --url https://forge.example/repository/ \
  --tenant 11111111111111111111111111111111 \
  --repository 22222222222222222222222222222222 \
  --token-file /srv/operator/token --timeout-ms 300000
```

This invokes the existing root-last preparer, copies the pinned sources and
creates the original requests, but sends no network request or native mutation.
Preparation never implicitly runs the migration. Save its returned `plan_sha256`
independently as `MIGRATION_SHA256`. Interrupted preparation leaves its custody
for inspection; the command never deletes it or repeats preparation into the
same destination. A partial preparation is not a runnable migration.

```sh
node scripts/migrate_github_issues.mjs inspect \
  --workdir /srv/migration/prepared --confirm "$MIGRATION_SHA256" \
  --url https://forge.example/repository/ \
  --tenant 11111111111111111111111111111111 \
  --repository 22222222222222222222222222222222 \
  --token-file /srv/operator/token
```

`inspect` revalidates retained sources and all original child requests without
network access. It is not remote `status` and cannot prove a canonical outcome.
The original external source files are no longer needed after complete
preparation; the migration's owned copies and original credential remain needed.
Preparation and inspection each have a maximum 300-second deadline. A completed
preparation followed by an output failure preserves the returned original plan
identity in error output where possible and never triggers a second preparation.

## Run and recover

Retain the complete private migration directory and the independently retained
SHA-256 of its `migration.json`. Use the same native destination, repository and
original credential used during preparation. The token file stays outside the
migration directory. Example paths and IDs below must be replaced with the
selected deployment and the actual returned migration pin.

```sh
node scripts/migrate_github_issues.mjs run \
  --workdir /srv/migration/prepared --confirm "$MIGRATION_SHA256" \
  --url https://forge.example/repository/ \
  --tenant 11111111111111111111111111111111 \
  --repository 22222222222222222222222222222222 \
  --token-file /srv/operator/token --max-mutations 100 --timeout-ms 300000
```

Every batch, captured population, original request and credential binding is
validated by the existing full-plan inspector before the first outcome query or
mutation. Execution then proceeds in exact inventory batch order. Each child
retains its original independent plan pin, request bytes, keys and expected
versions. There is no freshly generated retry namespace and no second progress
file that can override native terminal decisions.

Run the same command again after a mutation-budget stop. A completed child is
reconciled using its original outcomes; it does not spend another mutation call.
A started but uncertain request stops automatic progress. Read all batches first:

```sh
node scripts/migrate_github_issues.mjs status \
  --workdir /srv/migration/prepared --confirm "$MIGRATION_SHA256" \
  --url https://forge.example/repository/ \
  --tenant 11111111111111111111111111111111 \
  --repository 22222222222222222222222222222222 \
  --token-file /srv/operator/token
```

`status` visits every batch even when an earlier batch is incomplete or refused.
Within a child it retains the importer's contiguous-prefix recovery behavior; it
is not an independent scan of every later step. It sends no native mutation, but
may save newly observed terminal receipts locally. Thus `remote_read_only` does
not mean that local custody is untouched. Status is usable with a retained parent
sender lock, which it neither bypasses for writes nor deletes.

After independently reconciling the original sender, explicit `run` with
`--retry-unresolved` permits the existing importer to query and then, only if
still undecided, resend the original request. It does not reprepare anything,
refresh expected versions, change keys or turn absence into proof of non-commit.
A canonical refusal stops sending; it cannot be repaired by inventing a new key.

## Global bounds and ownership

The existing complete-plan limits remain: at most 128 batches and 10,000 native
steps. One `--max-mutations` allowance covers the entire invocation (default 100,
range 1–10,000), rather than resetting at each child. The counter measures calls
to the existing native retry operation; that operation can discover an already
committed outcome without sending a mutation. It is not a count of HTTP POSTs.
After exhausting the allowance, only child status operations are permitted.
Already committed later children can therefore still establish completion.

One absolute deadline covers inspection and all children (default 300 seconds,
maximum one hour). Each child receives the remaining time capped at its existing
300-second limit. Cancellation stops further work through that same signal;
a validated terminal remains visible even when cancellation arrives afterward.

A create-only, synced `migration.sender.lock` serializes these coordinators across
the entire migration. Each original child importer also keeps its own sender
lock. Do not independently run child importers alongside a full migration:
legacy tools do not acquire the parent lock. There is no automatic lock stealing
or PID-based recovery. Killing the operator can retain locks; stop and reconcile
the original owner before explicit operator repair. Never remove custody merely
to obtain a fresh execution. Root and child directories are pinned by identity,
and a replaced owner lock is never deleted as cleanup. Stable operator-owned
parents are required; this is not protection against a hostile same-UID actor.

## Progress and errors

Output is one bounded JSON row. It reports per-batch original pins, committed
prefixes, pending reasons and the shared mutation-call count. When a malformed or
missing child result prevents an exact count, `mutation_count_complete` is false;
the reported count is only the validated portion, not evidence of no submission.
`owner_present` records whether an owner existed at the initial observation.
These are historical observations at different instants, not one canonical
repository snapshot. The migration is **not atomic** across steps or batches.

For execution/status, exit 0 means every step was observed committed. For
preparation/inspection, it means the selected local operation completed; no
remote outcome is implied. Exit 1 means a canonical refusal;
3 means an incomplete/uncertain migration or exhausted work budget; 2 means an
input/read failure without known committed progress; 4 means committed progress
or a complete returned operation was known but subsequent work, output or cleanup
failed. Error output preserves known progress and terminal batch/step coordinates
where available. Broken output does not cause execution to restart. A complete
progress record plus an output error is not a successful command exit.

## Verification boundary

```sh
node --test tests/operator/github_issue_migration_execute.test.mjs \
  tests/operator/github_issue_migration_cli.test.mjs \
  tests/operator/github_issue_migration_sources.test.mjs \
  tests/operator/github_issue_migration_lifecycle.test.mjs
```

These tests run the production coordinator and CLI with real private files,
locks, directory replacement, streams, signals and deadline ownership. They
inject the existing importer/inspector boundary. The lifecycle tests replace
only the existing preparer/inspector module imports; private source selection and
the default CLI routing execute unchanged. They do not establish actual
native HTTP publication, Rust admission/CAS, GitHub capture correctness,
filesystem power-loss durability or a full-workspace pass. No Rust code, native
protocol or dependency is changed by this operator composition.
