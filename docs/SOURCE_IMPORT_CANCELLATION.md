# Caller-owned cancellation for local source import

`OneNode::import_loose_git_directory_durable_in` now carries its original
`NodeRequestContext` through local source preparation and canonical admission.
It no longer ignores that request or creates a fresh publication context after
source work. The existing `fg import` command already calls this entrypoint;
no new CLI flag is needed to connect the request boundary.

## One request, no deadline reset

Previously, directory and object processing used always-live probes. After
staging, the durable entrypoint allocated a new `request_context()` for the
publication phase. A canceled or expired caller could consequently lose control
of both the expensive source operation and the later mutation attempt.

The source path now borrows one sticky `ImportControl`. Directory enumeration,
ref and HEAD parsing, bounded file reads, loose-object inflation, idx checks,
pack decoding, CRC verification, delta resolution, whole-source graph validation
and placement consult the same control. Once it observes a stop it cannot
become live again, even if a generic caller's probe later returns true.

The request adapter uses the node's existing `checkpoint_pack_context` to keep
explicit cancellation distinct from runtime budget exhaustion. The latter
retains its exact `Exhaustion` value in `LooseGitImportRefusal::Interrupted`.
No unbounded context, detached task, background publication, new runtime,
additional dependency, or alternate source implementation is introduced.

The original request is passed directly to the existing asynchronous source
admission driver. Sealing, authority reads, materialization and publication
therefore do not receive a new time/poll/cost budget just because source
preparation finished. Callers must select an adequate finite request profile
before starting their operation; an operation cannot extend its own budget.

## Bounded blocking work

This remains a synchronous local-source preparation profile, called before the
asynchronous publication phase. It is cooperatively cancellable, not a promise
of nonblocking I/O or preemption of an OS operation already in progress.

File contents are read from one opened regular-file handle in at most 32 KiB
chunks. Cancellation is checked before and after each read, including EOF and
interrupted OS reads. The reader still stops at exactly the first byte beyond
the configured envelope. It never returns partial content as a successful read.
Metadata/open/directory operations are checked before and after; directory
entries and ref records also have per-item checkpoints. Existing filesystem
kind, symlink, source, byte and count restrictions remain in force. Hostile
filesystem replacement races are not solved by cooperative cancellation.

The existing native `ZlibLooseObjectDecoder` handles chunked compressed input
and final framing/checksum validation. Pure-CPU parser and resolver probes poll
the owning runtime once per 1024 callbacks, starting with the first callback.
This avoids consuming a scheduler poll for every decoded byte. Phase and I/O
checks remain unconditional, and native parser byte/work/expansion/delta
ceilings still apply at their existing granularity. Hashing, canonical parsing,
container operations and OS calls remain individually bounded operations, not
preemptible instructions. No fixed millisecond interruption bound is claimed.

Whole-source graph validation still uses the shared typed edge reader and
retains the original verified bodies. It does not reread mutable source files
for placement. Validation and canonical ref construction must finish before
any object is staged.

## Staged bytes versus publication

Cancellation before placement leaves no newly staged source objects. A stop
between placement calls may leave a verified, noncanonical prefix of the
source's immutable objects. That is not a partial published import: ref
publication remains exclusively through the existing sealed transaction and
exact-predecessor authority-head CAS.

A stop before admission prevents this invocation from attempting publication.
It does not prove that another invocation with the same key has not already
committed. After admission begins, authority failures retain their existing
uncertainty and terminal recovery semantics. No post-admission cancellation
check is added to discard a known committed/refused outcome or to report
rollback after a successful CAS. Same-key retries and `fg outcome` retain their
existing roles; cancellation is not permission to substitute a new key.

## API compatibility

`stage_loose_git_import` keeps its standalone hard-resource-bounded behavior.
It has no caller request and does not acquire one implicitly. New callers that
need a cooperative standalone control can use:

```rust
node.stage_loose_git_import_with_deadline(source_path, &mut deadline)
```

`deadline` implements the existing `fgit_pack::Deadline`, where true means
continue. The implementation explicitly adapts the opposite polarity of the
existing decompressor `CancellationProbe`. Request-handling code uses the
request-aware staging continuation, not the always-live standalone wrapper.

## Regression coverage and verification limits

Twelve Rust tests are registered: seven control/reader/decoder tests and five
node/graph tests. Coverage includes exact first-excess-byte reads, EOF and OS
Interrupted handling, sticky cancellation, the actual streaming decoder,
amortized CPU polling, shared read/decode control, both native hash domains,
loose and packed sources, original-entrypoint pre-cancellation with no I/O or
seal, live publication, shutdown/reopen/retry, noncanonical partial placement,
and pack-cache and graph-work cancellation. Existing graph and inline import
tests remain registered; the patch leaves the original inline tests untouched.

The editing environment has no Cargo, rustc, rustfmt, Clippy or built `fg`.
These tests and Rust compilation have not run. Lexical/delimiter checks and
patch/reconstruction checks are not native test evidence. The current patch is
based on `5eb3e339e27e61b440cc80a81efac1f4f62bb101`; a later application must
retain exact source guards rather than overwrite intervening edits.

This change does not activate repository-wide compiled policy protection,
implement multi-commit replay, provide remote authentication, or certify the
complete Git compatibility or native release gate. No bead is closed by it.
