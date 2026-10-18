# Page-scoped forge replay

Owning bridge work: `frankengit-root-doctrine-x2mv.4.7` (the repository-wide
4,096-event read cliff). Consumers are the existing node, HTTP and CLI issue/PR/
review read surfaces, named-reviewer gates and issue-command admission. This
documents an implementation slice, not a persisted projection service or
completion of the bridge bead.

## Issue pages, history and writes

The issue reader selects numeric page keys from the authority-selected forge
frontier before retaining or folding event histories. It retains histories only
for those keys. One lookahead key determines pagination; it does not cause an
extra issue's history to enter the page's memory budget. History reads replay
all selected versions to obtain current state at the same head, but retain only
the requested event window plus one lookahead event. Listing and write validation
retain no historical comment vector. The exact final event is still checked
against the selected frontier, independently of the requested history window.

The previous 4,096-entry repository check and repository-wide 32 MiB retained
history charge are removed. The bounded profile now allows 65,536 scanned events
and 128 MiB of scanned canonical event frames per replay. Selected unique events
have a separate 65,536-event / 32 MiB retention envelope. Repeated outbox payload
roots are visited once by replay; conflicting selected aggregate/version bodies,
missing predecessors, missing selected bodies, and invalid final versions still
refuse. All limits are checked with overflow-safe arithmetic. The canonical v1
forge/outbox map limits remain 16,384 entries each; no schema or identity changes.

This is not constant-time lookup or unbounded history. Projection reads
authenticate the forge and outbox maps selected by the head, then validate the
event commitments and complete frontier ranges they consume. They do not load
delivery effects or receipts, or validate unrelated frontier batches. Full
delivery and publication preflight retain those checks. Replay still scans
retained payload roots to find selected events; it cannot trust a local index or
object presence as authority. Missing or corrupt scanned payloads still refuse,
even if the payload would have contained only unrelated events. A selected issue
or page beyond its envelope refuses, and a missing stream is not invented from
unpublished objects.

## Pull-request pages

PR selection still checks both branch names against the caller's visibility
predicate before admitting a row. Numeric order, lookahead cursors and the
snapshot identity are unchanged. The replay pass deduplicates canonical payload
roots before reading them, so several destinations for one batch do not multiply
its event scan or metadata work. It charges all scanned events against the
65,536-event / 128 MiB scan envelope, including events outside the selected page.

Within the page, replay retains one latest full metadata event per PR, plus the
original opener and bounded per-version identity witnesses. Replacing an older
full state releases its byte charge; it does not repeatedly spend the live-page
32 MiB event-frame allowance on superseded descriptions. The selected frontier
and retained latest metadata are charged separately. The version-witness map is
bounded by the scan-event ceiling; this is not an allocator-wide memory meter.

Repeated identical event versions are ignored after commitment comparison;
conflicting versions still refuse. A merge must still match the immediately
preceding metadata's tips and branches, and the original opening actor must be
present in canonical payload history. Merely staging an opening body cannot
supply missing provenance. The existing explicitly merge-only receipt profile
remains distinct and does not invent metadata. Cancellation is checked within
batch replay as well as at the existing read boundaries.

## Review pages and required reviewers

Review enumeration uses the authenticated forge map's existing canonical bound;
it no longer imposes a separate 4,096-entry ceiling on the repository. After the
PR metadata lookup, a review page reads only the selected reviewer frontiers.
The named-reviewer gate likewise reads exactly the required reviewers, with no
second delivery replay. Each selected batch must contain the entire range
claimed by its frontier, including the exact predecessor and successor versions.
A matching final event alone is insufficient. Cancellation after the final
selected read still prevents a successful partial response or approval.

Numeric PR ordering, reviewer-ID ordering, page limits, freshness, opener
exclusion and source-only vote separation are unchanged. The canonical map's
16,384-entry ceiling still applies; this slice does not compact retained outbox
entries or increase publication capacity.

## Node selection and retained snapshots

Node issue, PR, review and workflow-check reads share the forge event feed's
lightweight authenticated head selector. It authenticates the head receipt,
repository/incarnation, native object format and current hidden-ref policy;
source-object materialization and retention/delivery projections are not
prerequisites for a metadata page. Missing or corrupt disclosure policy still
refuses.

An explicit snapshot continues through the existing retained-snapshot selector.
Review and workflow-check freshness use refs committed by that selected head,
while current hidden-ref policy controls disclosure. A historic token cannot
restore access to a branch that is hidden now. Mutation, delivery settlement and
recovery paths retain their complete admission materialization.

## Outbox reconciliation suffix

The runtime settlement reader now uses `history::latest_progress_for_entry`.
It authenticates the supplied entry against the exact selected outbox map and
verifies its stable delivery identity and lifecycle chain. It then verifies the
decision suffix through the transaction that created that entry. The creating
RCR must bind the original transaction, predecessor RCR and payload, and its
batch must select the same delivery binding, absent from the preceding outbox
map. The entire boundary microbatch, including any lifecycle/progress records in it, remains verified. A staged
creation or progress body cannot replace a missing canonical record.

The 4,096-batch / 65,536-record history limits are unchanged. They bound the
examined suffix rather than the repository's age, so recent obligations can be
reconciled even after more than 4,096 older decisions. An unresolved obligation
whose own suffix exceeds the budget still refuses. Historical genesis-seeded
obligations use a verified genesis fallback. A missing historical empty-outbox
sentinel retains the existing full-prefix bootstrap needed to prove its
unchanged authority history. The original `latest_progress` function remains the complete-history audit path; corruption before the selected
creation boundary is outside the runtime suffix lookup but remains visible to
that audit.

This changes neither canonical v1 bytes nor retention. It does not remove the
16,384-entry publication ceiling, compact settled obligations, or eliminate
complete outbox materialization or cumulative outcome collection elsewhere.
Outcome collection retains its own 65,536-batch limit. The owning bridge bead
remains open.

Model-store regressions count actual immutable reads and exercise a recent
obligation after 4,100 older batches, the exact suffix resource boundary,
full-audit equivalence, mixed creation/lifecycle microbatches, all terminal
dispositions and receipt dependencies, creation-coordinate tampering, missing
canonical progress, missing/corrupt boundary objects, and interruption at every
read boundary followed by retry. These are production-reader tests over
cryptographically linked fixture bodies, not runtime delivery, outcome-index,
filesystem durability, or latency evidence.

## Verification boundary

`cargo test -p fgit-admission merge::native::issues::replay_tests` exercises the
production issue reader over the non-durable reference authority store. Cases
include a 4,101-event issue, exact paged comments and current state, numeric
pagination, write-validation replay, an unrelated history larger than 32 MiB,
missing/conflicting history, cancellation, invalid limits and a frontier larger
than 4,096 entries. These are not filesystem durability or live HTTP tests.

`cargo test -p fgit-admission merge::native::pull_request::replay_tests` covers
long SHA-1/SHA-256 PR histories, superseded and unrelated large descriptions,
shared-payload fan-out, merge metadata, numeric/visibility paging, unselected
opening objects, conflicting versions, cancellation and invalid limits.

`cargo test -p fgit-admission --lib merge::native::metadata_read_tests` exercises
the real projection readers through the asynchronous reference authority store:
effect/receipt isolation, missing/corrupt/wrongly committed maps and payloads,
selected versus unselected malformed ranges, cancellation at every immutable
read, numeric pagination, visibility and unchanged heads in both native hash
domains. Full delivery refuses the same incomplete effects until they are
staged. These genesis-seeded fixtures are not durability or restart evidence.

`cargo test -p fgit-admission --lib merge::native::pull_request::reviews::read_tests`
covers a frontier with 4,097 unrelated streams, exact selected-review read counts,
paging and freshness, complete-range validation, missing/corrupt bodies and
cancellation after the final read.

The native-node regression
`native_current_and_retained_metadata_survive_an_unavailable_admission_cache`
publishes real PR/issue history, poisons only the derived admission cache, and
checks current/retained pages, caller visibility, cancellation, unchanged
authority and reopen behavior. Full materialization continues to refuse the
poisoned cache. This is separate from the reference authority fault fixtures.

Focused test results do not establish a complete workspace or release gate,
50,000-event publication capacity, or history-independent lookup cost.
