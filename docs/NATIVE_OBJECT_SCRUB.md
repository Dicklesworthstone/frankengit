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

## Complete bounded sweep

`fg scrub ... --trusted-local --all` drives native pages in one process, under
one request context and one exact authority head. `--max-page-objects`,
`--max-findings` and `--max-bytes` remain per-page limits. `--max-pages` (default
10,000, maximum 1,000,000) and `--max-sweep-bytes` (default and maximum 16 GiB)
bound the whole operation. `--timeout-secs` is one cooperative sweep deadline,
not a renewable per-page allowance. The same inherited runtime budget owns all
materializations, object reads and final authentication.

Each page is streamed as a `repository_scrub_sweep_page` JSON line with
`page_complete`, `complete`, `all_selected_object_bytes_verified` and
`node_closed` false. These are provisional observations, not successful
closed-node receipts. A single terminal `repository_scrub_sweep` line is
emitted only after exact coverage, final head revalidation and successful node
shutdown. It aggregates every page's findings; a clean last page never erases
earlier corruption or unreadable objects. Exit 0 means the whole selection's
object bytes verified. Exit 3 means a complete sweep with findings. Exit 2
means an incomplete operation, including exhausted aggregate budgets, an
oversized next object, output failure, changed authority or failed shutdown.
No terminal certificate is emitted after an operation failure. Consumers must
require the terminal record and successful output delivery, not infer success
from a page or a truncated stream. A terminal record cannot guarantee delivery
if the output sink fails while writing or flushing it; the process then fails.

`--all` refuses `--resume-after`: caller-supplied cursors do not prove coverage
of an earlier prefix. The existing single-page mode and explicit cursor
continuation remain available unchanged. This sweep does not repair storage,
verify graph edges or enumerate orphan files.

The sweep uses `OneNode::begin_selected_object_scrub_local_in` to retain one
authenticated selection for its entire request. Ref membership and object
selection are materialized once; every page still authenticates current
repository authority before and after its native object reads. A changed head
refuses even if its selected object identities happen to be identical. The
session never caches object health: newly damaged bytes remain detectable.

`SelectedObjectScrubSession::next_page` preserves the original request and
absolute deadline. Its payload allowance may be tightened, not widened, for a
sweep's remaining cumulative budget. A failed or interrupted page makes the
session unusable rather than resetting its cursor or minting a fresh budget.
The session owns no write authority or retention pin. Its per-page reports
cannot certify an unobserved prefix; only the CLI's completed full-sweep
accounting and successful shutdown permit the terminal receipt.
