# Bounded group durability for local import

`fg import` retains the existing verified-source spool, complete graph validation,
object-file encoding and canonical admission path. Only immutable placement is
batched: at most 256 objects and 8 MiB of decoded payload per chunk. The next
spool entry's length is checked before reading it; a large object flushes the
chunk and uses the established single-object path. No extra whole-repository
payload copy, persistent placement cache, new dependency or format migration is
introduced.

Each file is fully written and synced before its immutable hard link appears.
Staging and target directories are prepared once per batch. The target directory
is synced after every batch, before successful placement receipts and before the
import can return to canonical admission. Per-object typed admission obligations
remain pending through that fence and are explicitly committed or aborted.
Returned cancellation, corrupt existing data and I/O failure settle all prior
reservations and remove owned staging files. Physical process death can leave
staging files and verified unreferenced objects; neither establishes authority.

A single-object writer racing a batch now establishes its own directory fence
before reporting an existing object durable. It cannot assume another writer
already finished that fence. Existing bytes are always reverified and never
repaired by overwriting their immutable names.

The underlying `LocalFilesystemFabric::put_batch_if_absent` API admits sorted,
unique identities, at most 256 objects and 64 MiB. Complete limits and resource
grants are checked before any placement. Grants retain the nonzero byte grade
required for zero-length objects; actual spending still records zero payload
bytes. SHA-1 and SHA-256 stay distinct, and returned placement receipts never
claim canonical visibility. The import consumer deliberately uses the narrower
8 MiB profile.

## Validation

`cargo test --locked -p fgit-object-fabric --all-targets` covers the storage API,
including all seven existing deterministic fault boundaries, bounded admission,
concurrent batches, zero-length objects, exact reopen/reuse and cancellation at
every batch checkpoint. Node placement tests compare complete envelopes with
the single-object encoder and exercise chunk bounds and oversized fallback.
The existing loose/packed import, large-object and cancellation suites remain
applicable.

`scripts/e2e/suites/storage/import_batch.sh` drives a prebuilt `FG_BIN` through
real SHA-1/SHA-256 imports of 400-commit histories (1,200 objects). It kills a live
import after partial immutable placement, cold-opens the node to verify unchanged
refs, retries the same import, checks every stored payload against its source and
proves repeat import leaves stored object bytes unchanged. This tests process
death, not physical power loss.

## Measured mechanism and remaining work

Measurements on a four-vCPU Linux VM, pinned `nightly-2026-08-31`, unoptimized
native binaries with debug information disabled, used fresh synthetic linear
histories of 1,200 commits and 3,600 objects. Filesystem and tmpfs trials used the
same history; source construction and node initialization are outside the timed
import. Traced numbers include strace overhead and are not mixed with untraced
measurements.

| Measurement | Individual placement | Batches |
|---|---:|---:|
| Traced filesystem import, seconds | 13.531 | 11.916 |
| `fsync` calls in that import | 14,418 | 3,663 |
| Sum of traced `fsync` seconds | 2.129 | 0.556 |
| Traced tmpfs import, seconds | 11.952 | 9.423 |
| Sum of tmpfs `fsync` seconds | 0.117 | 0.028 |
| Untraced filesystem samples, seconds | 8.759 / 8.151 / 8.354 | 7.727 / 7.578 / 7.704 |

The call reduction is 74.6%; the three-sample untraced median moves from 8.354 to
7.704 seconds. This is a bounded local observation, not a release-performance
claim. Same-binary baseline spread is 0.608 seconds, close to the 0.650-second
median difference; wider repetition and production-profile benchmarks are still
needed. The tmpfs control also shows that durable I/O is not the entire import
cost. One file sync per new object remains, as do graph decoding, hashing and
canonical admission. The original `frankengit-pc9g` throughput target versus a
pinned Git clone has NOT been established and the bead remains open. Multi-object
segment placement and further end-to-end profiling remain separate work.

Reproduce a sample with `python3 scripts/bench/import_durability.py FG_BIN NEW_ROOT
1200 sha1 trace`; omit `trace` for untraced timings. Run alternating baseline and
candidate binaries into separate roots, retain `result.json`, `import.out`,
`import.err` and optional `fsync.trace`, and compare exact binary fingerprints.
