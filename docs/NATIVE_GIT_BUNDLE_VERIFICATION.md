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

Defaults/CLI ceilings are 128 MiB input, 128 MiB expanded object data, 100,000
included objects, and 4,096 advertised records (including optional HEAD). The
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

## Trust and integration boundaries

Content verification is not origin authentication, signature verification,
branch freshness, native admission, authority-head authentication, retention
selection, or restoration of forge state. `HEAD` is only reported, never installed.
No empty-store fallback, borrowed base, implicit repair or retry occurs. Larger
streaming backup, signed capsule restoration and JavaScript decoder retirement
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
```

The source tests cover native formats, typed closure, malformed/checksummed
inputs, delta encodings and forward discovery, shared resource limits,
cancellation, and deterministic results. CLI tests include independently generated
fixed pack fixtures and binary invocation with no Git on PATH. These tests were
**authored but not executed in the implementation environment**, which lacks
Cargo/rustc/rustfmt. No compilation, native command execution, real-Git
interoperability, repository-gate or production-readiness claim follows from
test presence. A native toolchain run remains required before verification handoff.
