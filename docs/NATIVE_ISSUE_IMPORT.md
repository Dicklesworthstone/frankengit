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
