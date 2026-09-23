# Offline workflow result and evidence recovery

FG-095b now exposes saved custody through `fg workflow recover` on Linux.
Recovery never reopens a repository database, reads current source, recompiles
workflow text, launches a process, acknowledges delivery, or authorizes a merge.
The source run directory and its original marker/journal suffice; `report.json`,
`execution.owner`, the source checkout and a live node are not required for these
reads. Their absence does not prove that execution completed or no work ran.

This is a read-only view of the existing local custody records, not a new
canonical check schema or an alternative to the authority-selected forge outbox.
It complements [node custody recovery](NODE_WORKFLOW_CUSTODY.md),
[durable attempts](DURABLE_WORKFLOW_ATTEMPTS.md) and
[check delivery](WORKFLOW_CHECK_DELIVERY.md).

## Read both pending and acknowledged results

The operator supplies the **retained** tenant, repository and SHA-256 digest of
the original `attempt.json`. The run directory must be absolute, nonsymlink and
0700; the existing marker and journal must meet the private-file profile. A
journal held by a producer is locked and cannot be inspected concurrently.
Nothing is recreated when a file is absent, corrupt, truncated or mismatched.

```sh
fg workflow recover "$RUN_DIRECTORY" "$TENANT_ID" "$REPOSITORY_ID" \
  --journal-id "$ORIGINAL_MARKER_SHA256" \
  --limit 16 --page-bytes 1048576
```

The response includes the exact journal `snapshot`, retained/pending batch counts,
acceptance-ordered entries and `next_after`. Each entry retains native SHA-1 or
SHA-256 source identity, authority basis, run/attempt, graph, trust partition,
execution profile, job phases/conclusions, referenced evidence digests, and the
separate downstream delivery receipt, if any. Successful trusted workflows still
show `action_required`, not a protected-ref green check. Delivery status and job
status are different fields.

Acknowledged batches remain visible even when `pending_batches` is zero. Merely
reading history never moves a batch back into the pending queue. Metadata pages
exclude evidence payloads; recover those explicitly by batch membership below.
The journal is verified on reopen, and each returned proposal/acknowledgement
record is checked again. An index entry is not substituted for on-disk bytes.

Continue with **both** the returned snapshot token and batch cursor:

```sh
fg workflow recover "$RUN_DIRECTORY" "$TENANT_ID" "$REPOSITORY_ID" \
  --journal-id "$ORIGINAL_MARKER_SHA256" \
  --at-pin "$SNAPSHOT" --after-batch "$NEXT_AFTER" \
  --limit 16 --page-bytes 1048576
```

Pins use `<byte-length>:<64-lowercase-hex-tail-sha256>`. Appending even one
acknowledgement changes the snapshot; a continuation under the old snapshot
refuses rather than mixing pages. Restart a traversal explicitly. Unknown batch
cursors or a cursor without `--at-pin` refuse. `next_after: null` means this
traversal reached its end, not that all workflow work completed.

Defaults are 32 batches and 1 MiB of encoded proposal/acknowledgement bytes;
hard page ceilings are 128 batches and 8 MiB. The count/byte limit does not count
JSON escaping. A first entry that cannot fit refuses instead of returning an
empty page that looks complete. The acceptance-order index is rebuilt with the
journal's other bounded indexes; each page copies at most its limit plus one ID,
not the whole history. Existing journal total/evidence/record bounds still apply.

## Recover exact bytes

Export a retained encoded proposal batch, regardless of its delivery status:

```sh
fg workflow recover "$RUN_DIRECTORY" "$TENANT_ID" "$REPOSITORY_ID" \
  --journal-id "$ORIGINAL_MARKER_SHA256" \
  --batch "$BATCH_SHA256" --output "$PRIVATE_OUTPUT_DIRECTORY/batch.bin"
```

Export one evidence body **referenced by that exact batch**:

```sh
fg workflow recover "$RUN_DIRECTORY" "$TENANT_ID" "$REPOSITORY_ID" \
  --journal-id "$ORIGINAL_MARKER_SHA256" \
  --batch "$BATCH_SHA256" --evidence "$EVIDENCE_SHA256" \
  --output "$PRIVATE_OUTPUT_DIRECTORY/evidence.bin"
```

Export verifies the selected batch, any retained acknowledgement and the actual
selected evidence bytes. Unreferenced evidence, including orphaned evidence from
a refused submission, cannot be selected through this API. Export preserves the
exact bytes and returns their SHA-256, length, scope, snapshot and provenance.
It does not interpret opaque evidence as a passing check or render raw tool
bytes into the terminal. Paging options cannot be combined with export.

The destination must be new and its parent an existing nonsymlink 0700 directory.
Bytes are staged in a new 0600 sibling, synchronized and read back in fixed-size
chunks before a no-replace hard link publishes the output. An occupied path or
dangling symlink is never overwritten. Directory synchronization and stage removal
complete after publication without consulting cancellation. Failure may leave a
named private `.partial` stage, or an already-published output whose final sync,
cleanup or JSON response failed. Errors distinguish these cases. Inspect the
artifact; do not replay workflow commands because recovery output failed.

## Trust, rollback and cancellation

Supply `--minimum-pin "$INDEPENDENTLY_RETAINED_PIN"` to require a previously
observed prefix. Unlike `--at-pin`, this permits later valid appends. A minimum
pin can also constrain an artifact export selected from an earlier page. Neither
a marker digest nor a pin recovered only from the same untrusted storage is an
independent authenticity or rollback witness. Checksums establish integrity,
not producer authorization. Stable operator-controlled parent paths remain a
precondition; hostile same-UID mutation and lying filesystems are not covered.

`--timeout-ms` accepts 1 through 60000, default 30000. The same cooperative budget
covers journal reopen, page reads/rendering and staged artifact verification.
There are no background workers. Filesystem syscalls and stdout do not have hard
latency bounds. Cancellation before publication leaves no final output; after
linking, synchronization/cleanup finishes before a reply.

Exit 0 means the **recovery read/export succeeded**, not that a stored job passed.
Input, storage, lock, corruption, cancellation and output failures return 2.
Every JSON result explicitly disclaims authoritative checks and execution replay;
workflow completion is not inferred from custody history.

## Library composition and tests

`FileCheckJournal::read_history` provides the exact-pin bounded traversal;
`read_retained_batch` reads acknowledged as well as pending proposals;
`read_batch_evidence` enforces the selected batch's evidence membership.
`OneNode::trusted_workflow_history_json` and `trusted_workflow_artifact` compose
those readers with the original marker/scope verification. These associated
functions require no running node and expose no delivery mutation or execution
capability to the CLI. Existing execution commands, journal formats and canonical
receipt bytes are unchanged. No new dependency or lockfile change is needed.

The first increment adds eleven runner history regressions. The CLI/node
increment adds sixteen tests covering parsing, real saved-file reads in both
native domains, delivered history, exact binary exports, loss of output response,
wrong scope, stale pages, missing/corrupt files, cancellation, locks, orphaned
evidence, output collisions and no-overwrite publication. Node tests reuse the
existing coordinated-workflow fixture; CLI codec fixtures are explicitly not
claims of execution. All Rust tests require the repository's pinned toolchain.
Rust/Cargo are absent in this editing environment: Rust compilation and Rust test
execution remain outstanding. Independent reference/static checks are not a
substitute for them or evidence of power-loss conformance or hostile isolation.
