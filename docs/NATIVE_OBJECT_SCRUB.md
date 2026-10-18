# Native selected-object scrub

This is the read-only object-inventory slice of
`frankengit-root-doctrine-x2mv.4.10`, not completion of its GC, repair,
RaptorQ, compaction, or independent batch-verification requirements.

`fg scrub` uses `OneNode::scrub_selected_objects_local_in`, the existing
request-owned admission materialization, real object-fabric verified reads,
and exact authenticated authority revalidation. It does not call the
JavaScript backup/scrub plane or run an external Git implementation.

The operation inspects every selected native object in its requested page,
including admitted history no longer reachable from current references.
Membership comes from the authenticated selected closure, never a directory
listing or a derived reachability index. Objects outside that closure are
not read. This trusted-local interface requires whole-repository inspection
authority; it is not a remote disclosure endpoint.

## Use and continuation

```sh
fg scrub ./fgit-data \
  11111111111111111111111111111111 \
  22222222222222222222222222222222 \
  --trusted-local --max-page-objects 1000 --max-findings 100
```

For the next page, preserve the storage root, tenant, repository and object
format, and supply `next_cursor.snapshot_token` as `--expected-head` and
`next_cursor.after` as `--resume-after`. A cursor must name an actual selected
member under the exact current head. Changed authority refuses and requires
a fresh audit. Continuation seeks directly in the selected sorted set rather
than enumerating physical storage or rescanning the previous prefix.

A cursor is an untrusted position hint, **not evidence of previous work**.
Every page reports its start, checked/verified counts, findings and continuation.
`page_complete` means that page finished and the node shut down successfully.
`complete` requires starting at the beginning and exhausting the entire
selection in that invocation. `all_selected_object_bytes_verified` additionally
requires no findings. Even an empty resumed suffix cannot set either of those
whole-selection flags. A consumer aggregating pages must retain and inspect
every page; the last page cannot certify pages the consumer did not observe.

Exit 0 means all selected object bytes were verified in one fresh complete
page; exit 3 means this page contains findings; exit 4 means a clean page
without a whole-selection certificate. Exit 2 is a parse, authority, request,
resource, shutdown or output failure. Findings take precedence over exit 4.

## Failure and resource boundaries

An individual unreadable or invalid object becomes an `object_unverifiable`
finding, carrying its native OID and the original typed node refusal in the
library API. Diagnostics are not a claim of corruption: missing bytes,
permissions, a configured object-size refusal and failed commitments differ.
The CLI bounds diagnostic text and marks truncation. Other selected objects
continue until the page's object, finding or payload bound is reached.

Native identity, exact payload length, namespace and independent payload
commitments are checked by the existing object-fabric read path. The
per-object allocation ceiling is selected by the node configuration. Selection
materialization retains its existing node bounds; the query's selection-count
limit is checked before native object inspection. The query bounds included
payload, not total physical I/O. One additional bounded object read may be
needed to detect the next page boundary. That object is not skipped by the
continuation cursor. An object exceeding an otherwise empty page's byte
budget causes a typed resource refusal, not an infinite zero-progress cursor.

Cancellation, deadline and authority failure never turn into object findings
or a successful partial report. The same request controls selection, reads and
final head authentication. The cooperative timeout cannot interrupt a blocking
OS read. Head revalidation is an observation, not a lock against later writes
or later physical corruption. The CLI emits no page before successful shutdown.

This command does not repair, delete, create retention roots, check local graph
connectivity, validate signatures, or certify orphan files. `fg fsck` retains its
existing complete, all-or-error graph audit without implicit fallback.
