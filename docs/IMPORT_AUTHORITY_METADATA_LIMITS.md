# Import publication metadata: byte bounds, not a hidden timeout

The single-node source importer verifies and stages native Git objects, then
publishes the immutable permitted-object closure through ordinary sealed
admission and authority-head CAS. The closure lists native object identities;
it is not the pack, expanded payload, a cache, or permission to publish refs.

## The former object-count cliff

At `91382cb8dea0fb4f5eaa5f95d235ef8ac88f333d`, the default authority body limit
was 1 MiB, while ordinary canonical readers accepted frames through 16 MiB.
The current closure frame is 90 bytes plus 22 bytes per SHA-1 identity or
34 bytes per SHA-256 identity. Consequently the old profile accepted at most
47,658 SHA-1 objects or 30,837 SHA-256 objects. The next object failed the
store's `BodyTooLarge` check. Projection reduced that to the generic
`ResourceBudgetExceeded`, which incorrectly suggested that time was the issue.
Neither a larger timeout nor `--max-expanded-mib` could make that frame fit.

The regression test reproduces both exact old thresholds on the real
file-backed FrankenSQLite authority, alongside the permitted last-fitting twin.
A native 100,202-object SHA-1 fixture also reproduced the original CLI failure
in 198 seconds with an explicit 1,800-second timeout. This is a diagnostic
sample on an unoptimized isolated Linux VM, not a throughput target.

## One finite canonical-frame profile

`AuthorityLimits::default().body_bytes` now matches the decoder's existing
16 MiB envelope. Slot, head and token ceilings are unchanged. Explicitly supplied
smaller authority profiles remain smaller; no backend silently widens them.
Native body identities, codecs, immutable key derivation, transaction keys,
object verification and the root-last publication protocol are unchanged.
The default is a maximum single frame, not a preallocation or an unbounded
aggregate memory allowance. The existing bounded body cache is unchanged.

At the present codec version the default closure ceiling is 762,596 SHA-1
objects or 493,444 SHA-256 objects. Other graph, pack, payload, source, ref,
collection and runtime budgets still apply independently. The importer does
not claim that its 1,000,000-object graph ceiling guarantees a publishable
single closure; a future larger/segmented closure is a separate protocol change.

## Refuse oversized metadata before placement

After verifying the source graph, but before durable object placement, both
ordinary and explicit-byte-profile imports compute the exact encoded closure
and ref-state sizes. The bound is the smaller of the actual store body limit
and the canonical reader frame limit. A larger store therefore cannot create
metadata these readers would reject. Size calculation uses the real encoder's
empty envelopes, native algorithm widths and per-ref encodings, without
allocating an oversized closure frame. Tests compare those calculations with
actual canonical frames in both native hash domains, including raw-byte refs.

`PublicationMetadataTooLarge` names the body, required bytes and allowed bytes.
Its message explicitly says the refusal precedes object placement and that a
larger timeout or expanded-byte allowance will not change the metadata bound.
Codec failures remain `PublicationMetadataInvalid`, and cancellation retains
its own interruption kind. No replacement budget, silent partial import,
reduced closure, fabricated success or automatic overwrite is introduced.

An over-bound source can leave only its existing private validation/spool work
subject to normal cleanup. It cannot place new durable object files or publish
refs through this path. A native test configures a deliberately smaller store,
verifies every fixture object is absent after refusal, then reopens under the
normal profile and publishes the identical source successfully.

An import that failed under the old binary may already have staged verified
objects and sealed an undecided request. Retain the original source, principal
and idempotency key. The ordinary identical retry is the recovery route; do
not infer non-commit merely from a process error. This change neither removes
those records nor creates a replacement transaction identity.

## Evidence and limits

`crates/fgit-node/tests/import_metadata_limits.rs` exercises exact old limits,
100,202-member canonical frames in both hash formats, cold reads, identical
immutable retries, the new 16 MiB positive boundary and its one-byte-over twin.
The `loose_import::metadata` tests cover arithmetic equivalence, typed failures,
caller cancellation, a larger-store/smaller-reader mismatch, and genuine
pre-placement refusal with a successful native publication twin.

No full-workspace, release, physical power-loss or hostile-host claim follows
from these focused checks. The broad performance and import acceptance beads
remain subject to their independent revision-bound verification.

## Import obeys the leading global timeout

The CLI now intersects its local import timeout with an explicitly supplied
leading global `fg --timeout-secs ... import ...` timeout. When both are present,
the smaller ceiling wins; an import-local value cannot extend a stricter global
request. A fractional global value is retained without rounding to seconds.
With neither override, the existing bounded, work-proportional import default
is unchanged. The single request still covers source traversal, graph validation,
placement and publication without refreshing its deadline after staging.

`scripts/e2e/suites/node/import_metadata_scale.sh` drives a prebuilt actual `fg`.
Its default fixture has 100,000 distinct files and 100,202 reachable native
objects in each hash format. It checks strict global deadlines before source
I/O (including a conflicting local timeout and the explicit byte profile),
independent expanded-payload refusal, atomic import, identical-key retry,
outcome recovery with the original source path absent, cold native export,
stock Git strict pack admission, and every exported object's exact kind/body.
The ordinary installed Git version and binary fingerprints are recorded; this
is not the separately pinned Tier A conformance oracle. `FGE_IMPORT_FILES` may
select 64..100000 files for a smaller development run; results always record
the actual count, and smaller runs do not establish 100k-object scale.
