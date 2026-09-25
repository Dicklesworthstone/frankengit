# Page-scoped forge replay

Owning bridge work: `frankengit-root-doctrine-x2mv.4.7` (the repository-wide
4,096-event read cliff). Consumers are the existing node, HTTP and CLI issue/PR
read surfaces and issue-command admission. This documents an implementation
slice, not a persisted projection service or completion of the bridge bead.

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

This is not constant-time lookup or unbounded history. The existing delivery
reader still authenticates the complete selected delivery state and its retained
dependencies before replay. That verification work is additional to the replay
budget. Replay still scans retained payload roots to find selected events; it
cannot trust a local index or object presence as authority. A selected issue or
page beyond its envelope refuses, and a missing stream is not invented from
unpublished objects. Independent full-history consistency auditing is not the
same operation as reading one selected page.

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

The implementation session has no Rust toolchain: these tests were added, not
executed. Source/blob identity and patch whitespace checks do not establish a
Rust compilation, test, formatting or release gate pass.
