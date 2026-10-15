# Execute a complete pinned issue migration

`scripts/migrate_github_issues.mjs` runs every prepared batch from
[the complete GitHub issue migration](GITHUB_ISSUE_MIGRATION.md). It composes the
existing `runGithubIssueImport` operator, not another mutation codec, Git engine,
credential scheme or authority. The native issue API continues to authorize and
publish each original request. Related work: FG-049.

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

Exit 0 means every step was observed committed. Exit 1 means a canonical refusal;
3 means an incomplete/uncertain migration or exhausted work budget; 2 means an
input/read failure without known committed progress; 4 means committed progress
or a complete returned operation was known but subsequent work, output or cleanup
failed. Error output preserves known progress and terminal batch/step coordinates
where available. Broken output does not cause execution to restart. A complete
progress record plus an output error is not a successful command exit.

## Verification boundary

```sh
node --test tests/operator/github_issue_migration_execute.test.mjs \
  tests/operator/github_issue_migration_cli.test.mjs
```

These tests run the production coordinator and CLI with real private files,
locks, directory replacement, streams, signals and deadline ownership. They
inject the existing importer/inspector boundary. They do not establish actual
native HTTP publication, Rust admission/CAS, GitHub capture correctness,
filesystem power-loss durability or a full-workspace pass. No Rust code, native
protocol or dependency is changed by this operator composition.
