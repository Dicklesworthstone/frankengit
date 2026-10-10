# Native offline Git bundle verification

`fg bundle verify` checks a complete local Git bundle without opening a node,
repository database, worktree, credential file, or network connection:

```sh
fg bundle verify /backups/repository.bundle
```

The implementation is Rust throughout. It composes the existing `fgit-pack`
full-bundle parser, native trailer verifier, `fgit-deflate` inflater, typed delta
resolver, `fgit-crypto` object hashing, and `fgit-treefs` object-graph audit.
It does not invoke Git, JavaScript, another VCS engine, or a subprocess. Existing
`fg bundle export`, `import`, `fetch`, `sync-export`, and `sync-import` retain
their own authority, credential, publication and retry semantics.

## Checked content

The command validates full bundle v2/SHA-1 and v3 with an explicit native object
format, optional HEAD advertisement and all direct refs. Prerequisites, filtered
bundles, unknown capabilities and external delta bases refuse. It validates pack
framing, the native checksum and compressed entries, resolves OFS_DELTA and
REF_DELTA (including forward/chained bases), and computes IDs from each object's
actual native type and bytes. A single resolver budget is retained across all
identity-discovery passes; deferred bases do not reset expansion/work accounting.

Every included object is supplied in native-ID order to the existing typed graph
audit. Commit trees and parents, tree entries and tag targets must be present in
the same bundle and have the right native type. Branch refs must target commits.
Malformed metadata, missing objects, duplicate native identities, wrong-type
edges and cycles refuse. Gitlink entries name other repositories and are counted
but never followed. Ref names are reported as exact hexadecimal bytes, not used
as local paths or interpolated into executable content.

The scope is **all included objects and all advertised direct refs**, not only
the current refs' reachable set. A transport-only object with incomplete local
history refuses too. This is deliberately stricter than an advertised-refs-only
backup check, but it is not every strict upstream `git fsck` diagnostic/policy.
The command does not prove a bundle contains every ref in an external repository;
it has no independent inventory of that repository.

Success exits 0 with one JSON `git_bundle_verification` report. It includes the
whole-artifact SHA-256, native pack checksum, hash domain, exact ref inventory,
object/edge/payload counts, optional advertised HEAD, external gitlink count,
and delta/discovery-pass counts. The output marks object and graph checks as
completed. Invalid, incomplete, unsupported or interrupted input exits 2 through
the existing `bundle_error` diagnostic on stderr, with no success on stdout.
A broken stdout pipe is an I/O failure, not proof the report was delivered.

## Resource and local-file profile

```sh
fg bundle verify repository.bundle \
  --max-input-mib 64 --max-expanded-mib 64 \
  --max-objects 50000 --max-refs 1000 --timeout-secs 600
```

The default in-memory profile has ceilings of 128 MiB input, 128 MiB expanded
object data, 100,000 included objects, and 4,096 advertised records (including
optional HEAD). The
native header cap is 1 MiB and per-object cap is 32 MiB. Native pack limits also
bound expansion ratios, inflater work, delta work, depth (64), fanout and cache.
The graph bounds local edges plus external gitlinks at 1,000,000. Limits count
payload/work, not total process RSS; the input, resolver input, cache and resolved
object bodies can coexist. Smaller object/ref limits apply before their owning
parser allocates corresponding tables.

The default whole read/verification timeout is 300 seconds, selectable from 1
through 3,600 seconds. The existing native termination-signal handler and a shared
monotonic deadline stop work cooperatively. Once a callback refuses, the verifier
remains stopped even if a later callback would allow work. SIGINT/SIGTERM request
stop on supported platforms. Cooperative checks cannot interrupt a blocking OS
read, an allocator, or an indivisible hash/parser call.

The path must be a quiescent nonempty regular local file, not a symlink. Reads use
one descriptor, bounded chunks and fallible reservations. Descriptor/path identity,
length and metadata are compared before and after reading; Unix checks include
inode/device and nanosecond timestamps. The verifier consumes the resulting owned
bytes, never reopens the path, and never writes source or repository files. This
trusted-local namespace is not an openat/no-follow sandbox against a malicious
same-user process replacing paths during an open. Non-Unix identity checks are
weaker. Keep the input and its parent under operator control. Use `--` before a
literal file path beginning with a dash.

## File-backed verification

An explicit file-backed profile reads a seekable source and keeps inflated and
resolved object bodies in a private scratch file. It removes the requirement to
retain the complete compressed input and complete resolved payload set in memory:

```sh
mkdir -m 700 /var/tmp/frankengit-bundle-scratch
fg bundle verify /backups/repository.bundle \
  --file-backed --scratch-dir /var/tmp/frankengit-bundle-scratch \
  --max-input-mib 1024 --max-expanded-mib 2048 \
  --expect-sha256 "$KNOWN_BUNDLE_SHA256" --timeout-secs 1800
```

`--file-backed` and `--scratch-dir` must be supplied together. Option order does
not change the selected limits. Without the explicit profile, input or expanded
limits above 128 MiB refuse during argument validation before opening a file.

| Resource | Default | File-backed CLI ceiling |
|---|---:|---:|
| Whole input | 128 MiB | 16,384 MiB |
| Total inflated entries and separately total resolved graph payload | 128 MiB each | 16,384 MiB each |
| One object or delta program | 32 MiB | 32 MiB |
| Included objects | 100,000 | 100,000 |
| Advertised records, including optional HEAD | 4,096 | 4,096 |
| Header metadata | 1 MiB | 1 MiB |
| Local graph edges plus external gitlinks | 1,000,000 | 1,000,000 |

The larger byte ceilings are explicit resource allowances, not a promise that
every bundle beneath them is accepted. Existing inflater work, expansion ratio,
delta work, depth, fanout, index, metadata, and deadline limits still apply.
Increasing `--max-expanded-mib` does not increase those limits. A single shared
resolution budget charges deferred and successful delta work. No external base
or alternate decoder is consulted when a limit refuses.

Scratch space is bounded by inflated bytes plus resolved payload bytes, so it
can require up to twice the selected expanded ceiling. The implementation still
retains object/index inventories and graph edges within their count limits, and
one object or a bounded delta base/program/result tuple uses memory. These
limits describe admitted payload and work, not total process RSS.

The input is opened once and its descriptor is used for all passes. Whole-input
and native-format/reference pins are checked before inflation; a matching pin
does not skip pack or graph verification. The content result binds the exact
pack range with both its native checksum and a SHA-256 commitment. Before a
success report, the CLI rechecks source device/inode, length, modification and
change timestamps, permissions, owner, links, and the current named path.

This profile requires a quiescent operator-controlled Unix filesystem. Input
and scratch paths must not contain symlink components or `..` traversal. The
scratch directory must already exist, belong to the invoking user, and permit
no group or other access. Each invocation creates a new mode-0600 file with
create-only semantics; it never reuses a previous attempt's contents. Normal
success, failure, and cooperative cancellation remove only that owned file.
Namespace substitution or an unexpected hard link refuses cleanup and identifies
the residue. A process crash can leave a private scratch file for the operator
to inspect and remove. The command does not scan or delete previous residue.

The original content report shape remains unchanged for the in-memory profile.
File-backed success adds `storage_profile` with
`file-backed-native-full-bundle-v1`, actual `scratch_bytes`, `scratch_removed`,
and `pack_sha256`. `scratch_removed: true` is emitted only after cleanup succeeds.
A cleanup error emits no successful verification report.

`--recovery-head-hex` also works with this profile. Its existing bounded recovery
layout report contains the pack offset, native index, selected HEAD and fixed
bare-repository metadata; it never embeds the pack bytes or creates a repository.
The metadata report remains capped at 16 MiB. The runtime-free public entry
points are `verify_git_bundle_reader` and `prepare_git_bundle_recovery_reader`
in the existing native bundle-verification module. Callers provide `Read + Seek`
input, fresh private `Read + Write + Seek` scratch, limits, and a cooperative
callback. The caller owns file stability and cleanup.

## Trust and integration boundaries

Content verification is not origin authentication, signature verification,
branch freshness, native admission, authority-head authentication, retention
selection, or restoration of forge state. `HEAD` is only reported, never installed.
No empty-store fallback, borrowed base, implicit repair or retry occurs. Streaming
bundle creation, signed capsule restoration and JavaScript decoder retirement
remain separate work. This command introduces no dependency or alternative Git
semantics; it does not silently change existing browser/Node tools or their claims.

The public composition entry is
`fgit_node::source_retrieval::integrity::bundle_verify::verify_git_bundle`, with
caller-selected `BundleVerifyLimits` and a cooperative work callback. Successful
reports are constructible only through verification and have read-only accessors.

## Focused validation

```sh
cargo test -p fgit-node --lib source_retrieval::integrity::bundle_verify
cargo test -p fgit-cli --bin fg bundle::verify
cargo test -p fgit-cli --test bundle_verification
cargo test -p fgit-cli --test bundle_file_ownership
```

The source tests cover native formats, typed closure, malformed/checksummed
inputs, delta encodings and forward discovery, shared resource limits,
cancellation, and deterministic results. CLI tests include independently generated
fixed pack fixtures and binary invocation with no Git on PATH. File-backed tests
also exercise disk/memory content agreement, independent index goldens, early
pin refusal, cancellation cleanup, source replacement and exact scratch ownership.
The std-only ownership suite can run directly with `rustc --edition=2024 --test`
on `crates/fgit-cli/tests/bundle_file_ownership.rs`. Running that suite establishes
the production file-owner behavior; it does not establish a complete CLI build
or execution. Revision-bound results must distinguish component execution from
the full `fg` binary and repository-wide gates.
