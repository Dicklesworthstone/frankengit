# Native issue commands

`fg issue` connects the existing native issue event model, authority admission,
canonical replay, and node APIs to a complete trusted-local command surface.
There is no CLI-owned issue database, alternate event log, new dependency, or
production Git subprocess. These are FrankenGit repository issues, not operations
on the hosting GitHub repository's issue tracker.

## Open, discuss, edit, close, and reopen

All mutations supply an explicit positive issue number, principal, stable
idempotency key, and expected predecessor version. Opening uses version zero.
The node, not the command line, decides whether the predecessor is still current.
Numbers are supplied by the caller; this interface does not allocate one by a
racy read of the current maximum.

```sh
fg issue open "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local --principal "$PRINCIPAL_ID" \
  --idempotency-key issue-17-open --expected-version 0 \
  --title 'Fetch fails after reconnect' --body-file ./report.md \
  --label bug --label transport

fg issue comment "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local --principal "$PRINCIPAL_ID" \
  --idempotency-key issue-17-comment-1 --expected-version 1 \
  --body 'Reproduced using the exact supplied repository.'

fg issue edit "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local --principal "$PRINCIPAL_ID" \
  --idempotency-key issue-17-title-1 --expected-version 2 \
  --title 'Reconnect discards the negotiated fetch state'

fg issue close "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local --principal "$PRINCIPAL_ID" \
  --idempotency-key issue-17-close-1 --expected-version 3

fg issue reopen "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local --principal "$PRINCIPAL_ID" \
  --idempotency-key issue-17-reopen-1 --expected-version 4
```

These examples form one sequential history. Do not substitute guessed versions
when other writers may have advanced it. A genuinely changed command requires
its own key and deliberately selected predecessor; an uncertain retry does not.
Add `--object-format sha256` to every command for a SHA-256 node. SHA-1 is the
explicitly documented default, not an inferred conversion between repositories.

`edit` changes only supplied fields. Omitting `--body` preserves the body;
`--body ''` clears it. Omitting labels preserves them; repeated `--label` options
replace the complete label set, while `--clear-labels` replaces it with empty.
Label order is canonicalized before sealing. Duplicates are rejected, not silently
lost. Clearing and supplying labels together is rejected. An empty edit is invalid.

A comment retains its exact text as a versioned action. It does not overwrite the
opening body. Comments, edits, close and reopen all advance the same issue version,
so competing operations cannot silently lose one another. Closing an already
closed issue and reopening an open issue do not create invented transitions.

## Read current state and the exact discussion history

```sh
fg issue list "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --limit 25

fg issue show "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local --limit 25
```

`list` returns issues in numeric order. `show` returns the requested issue's current
snapshot plus a page of its original versioned actions, including comments and
which actor authored each action. The issue snapshot is at `source_head`, not at
the last event on a partial page. Missing numbers return `found:false`, a null
issue and no history; a neighboring issue is never substituted.

For a list continuation, pass `--after` with `next_after`. For a history
continuation, pass `--after-version` with `next_after_version`. Both require the
first response's exact `snapshot_token` in `--expected-head`. Page sizes are 1–100.
The CLI checks aggregate identity, numeric order, contiguous event versions,
limits, cursors and the supplied snapshot equality before emitting a result.

A token is an equality precondition on the selected current head, not permission
to read an arbitrary historical database snapshot. Any intervening canonical
repository change can invalidate continuation, including a change to another
issue. Restart a read at the new snapshot rather than merging pages from different
heads. Neither reading nor pagination mutates canonical state.

## Publication, retry, and lost responses

An issue action is encoded in the existing forge event batch and admitted through
the existing sealed transaction and authority-head CAS. The batch and actor are
bound into the request identity. Publication includes its existing outbox
obligation but does not modify Git refs. An outbox obligation is not delivery:
receipts deliberately report `delivery_acknowledged:null`.

Successful mutations return `issue_publication` JSON with `tx_id`, canonical
`decision_sequence`, repository commit or refusal identity, number, exact expected
version, action, and cleanup state. The raw idempotency key is not echoed. A retry
of the identical scoped command recovers its original result even after the issue
has changed. It cannot append a duplicate comment, reopen something again, or
rewrite an earlier canonical refusal into success. Changing bytes under an existing
key is an error, not permission to reuse that key for a different operation.

Historical decision recovery takes precedence over new-publication intake checks
inside the node API. The CLI does not discard such a decision merely because
entering service now refuses. New, undecided commands must still pass intake.

When the command body/file is no longer available, use the existing read-only
key recovery interface:

```sh
fg outcome "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --principal "$PRINCIPAL_ID" \
  --idempotency-key issue-17-open
```

A missing response, output failure or transport error is not proof of non-commit.
Write/flush and shutdown errors retain the known terminal transaction and decision.
Read results are emitted only after explicit node shutdown succeeds. The CLI never
reports successful cleanup merely because its business operation completed.

Exit codes are 0 for committed mutations/successful reads, 3 for canonical refusal,
4 for a missing issue, and 2 for input, infrastructure, cleanup or output failure.

## Input and authorization boundaries

Titles are bounded to 256 UTF-8 bytes. Bodies/comments are bounded to 65,536 bytes;
comments must contain non-whitespace text. At most 32 labels of 64 bytes each are
accepted. Body files must be stable, operator-controlled regular files, not links,
devices or directories. Actual opened-file metadata and a bounded read are checked
before opening the node; overflow, NUL and invalid UTF-8 refuse without lossy
conversion. CRLF, Unicode and a missing final newline are retained. This is not a
hostile-filesystem isolation API or a promise to interrupt an OS read in progress.

JSON quoting preserves decoded content while escaping control and bidi-formatting
characters that could otherwise alter terminal presentation. Text is never executed
or interpreted as authentication, policy or agent instructions.

`--trusted-local` is mandatory. This surface assumes an authorized local operator
controls repository access; it is not a remote identity provider or an issue-specific
ACL. Git hidden-ref policy does not grant or deny issue metadata access. Remote
adapters must supply authenticated repository metadata access before exposing it.

Canonical issue replay currently retains the admission layer's finite 4,096-event
and 32 MiB history envelope. This is not a claim of indexed large-forge scalability.
Repository-wide mandatory Git protection, remote ACLs, issue attachments, search,
assignment and a browser UI remain separate work.

## Native regression entrypoints

```sh
cargo check --locked -p fgit-cli --all-targets
cargo test --locked -p fgit-cli --bin fg issues::
cargo test --locked -p fgit-cli --test native_issue_smoke
cargo test --locked -p fgit-node --lib issues
cargo test --locked -p fgit-reference -p fgit-txn -p fgit-forge --all-targets
```

The process campaign uses a real built `fg`; every operation opens and closes the
file-backed node. It covers both native hash formats, complete lifecycle, preserved
fields, exact comments, historical retries, changed-key refusal, missing issues,
pinned issue/history pages, stale snapshots, invalid body files and artifact-free
outcome recovery. Presence of the campaign is not an execution claim.

The prerequisite repairs removed a duplicate `IssueChanged` enum insertion and
completed its missing normal-form encoding using the existing reference trace tag
6. Existing event tags 1–5 were preserved. Four new transaction regressions check
exact bytes, distinct entities/event kinds, ordered effects plus outbox application,
and each statement mismatch policy. Before CLI integration, source
`99dbd4679192ead4d95a09ede4b21146ca6dba78` passed CLI all-target checking, 348 tests
across reference/transaction/forge targets (one separately declared ignored test),
and all four existing file-backed issue tests. The admission `issue` filter matched
zero tests and is not counted as test execution. Later CLI execution must be
reported against its own source revision. No bead is closed by this guide.
