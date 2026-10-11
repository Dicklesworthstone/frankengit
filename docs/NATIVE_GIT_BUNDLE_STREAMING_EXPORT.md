# Native streaming full-bundle export

The `fgit-pack` streaming exporter writes a complete native Git bundle without
retaining a payload-bearing `PackPlan` or a complete output buffer. It supports
bundle v2/SHA-1 and bundle v3/SHA-256 through the existing pure-Rust native object,
hashing, pack-header and DEFLATE implementations.

## Library contract

`fgit_pack::full_bundle::stream::write_full_bundle_stream` accepts direct ref
advertisements, optional HEAD, an exact selected object inventory, a
`CanonicalObjectSource`, independent limits, a cooperative deadline and a
caller-owned `Write` sink. The caller authenticates the repository snapshot and
authorizes disclosure before selecting those inputs.

The exporter sorts objects by their exact native identity and loads one body at
a time. It verifies the requested identity against the object's native type and
bytes, parses the actual bytes to discover typed edges, and compresses the body
with the existing deterministic no-delta compression policy. Source-provided
edge metadata is not accepted as a substitute for parsing. The profile identifier
is `git-pack-compressed-oid-no-delta-v1`; its OID ordering is intentionally distinct
from the materializing planner's ordering. Repeated exports with the same inputs
and profile produce the same bytes, but the two profiles need not produce
byte-identical packs.

Before completing the pack trailer, the exporter checks that every local edge
resolves to the required object kind, branch roots target commits, and every
selected object is reachable from an advertised ref. Missing objects,
unreachable extras, duplicate identities or refs, mixed hash domains and invalid
native bytes refuse. Gitlinks are foreign references and are never loaded, but
they still consume the graph-edge allowance.

Memory holds one source body and its bounded parsed view, one compressor's
buffers, bounded header bytes, and O(objects + edges) metadata. This is a payload
streaming contract, not a constant-memory or one-physical-storage-read guarantee.
Sources and writers remain responsible for bounding their own blocking I/O.

## Independent resource limits

`StreamFullBundleLimits` combines the existing `PackLimits` and
`FullBundleLimits` with an explicit graph-edge ceiling and a shared compression
work allowance. Pack output bytes, whole-bundle bytes, total expanded source
bytes, per-object bytes, object/index counts, ref counts and header bytes retain
independent checks. Increasing an output-byte limit does not increase another
allowance.

`Deflater::work_units()` exposes the exact deterministic work already charged by
each member. The stream subtracts it before starting the next member; neither a
new object nor a retry within an encoder replenishes that operation's budget.
The default graph allowance is 1,000,000 edges and the default aggregate
compression allowance is 1,000,000,000 work units. These are finite admission
limits, not elapsed-time or total-process-RSS promises.

Cancellation is sticky and is checked around source reads and parsing, between
hashing/encoding chunks, throughout graph traversal and around output writes.
Short writes and interrupted writes are handled without losing byte accounting.
An output I/O failure remains distinct from a source, graph or codec refusal.

## Artifact ownership

All emitted bytes are tentative, including bytes written before a later graph
or cancellation failure. The caller must provide private staging. Success
returns a constructor-restricted receipt with native checksum, whole-bundle
SHA-256, profile, object and payload counts, output sizes and charged compression
work. The codec does not flush, publish, close the node or claim durability.
The owner must complete those obligations before making a backup visible.

A native Git bundle contains Git objects and ref advertisements. It does not
restore forge events, authority decisions, access policy, credentials or signed
capsule state. This implements the streaming Git portion of
`frankengit-root-doctrine-x2mv.4.21`; that broader bead remains open.

## Focused validation

```sh
cargo test -p fgit-pack --all-targets --locked
cargo test -p fgit-deflate --test encode_work_accounting --locked
cargo test -p fgit-pack --test full_bundle_stream_file --release --locked -- --include-ignored --test-threads=1 --nocapture
```

The streaming tests exercise both native hash domains and independent native
decoding, deterministic output, malformed identities and graphs, each limit's
permitted boundary and refusal, shared compression work, cancellation, short
writes and output failure. A generated source requires output progress before
the next body is loaded and rejects a second load, making the streaming ownership
behavior executable. These are native component checks; they are not an upstream
Git differential result, a throughput benchmark or complete CLI verification.

The real-file target has an ordinary small case and an explicitly selected large
case. The latter generates 33 independent 4 MiB blobs plus their native tree and
commit, in each hash domain. It requires the source payload, encoded pack and
actual bundle file all to exceed 128 MiB. The generated source retains object
identities and small specifications and verifies that output reaches the file
before its next load. The native streaming reader then checks each recovered
body's identity, type and exact content, as well as the header, refs, HEAD,
trailer, EOF and whole-file SHA-256.

Set `FGIT_STREAM_BUNDLE_ARTIFACT_DIR` to an existing directory when retaining
these generated files for an independent consumer check. Each completed native
verification emits a matching `.expected.tsv` containing exact object inventory,
refs, HEAD and receipt commitments. Filenames are created exclusively; the test
does not replace existing artifacts. By default it removes only its own bundle
file. The large case is opt-in because it writes and verifies more than 128 MiB
per format. It exercises the payload streaming capability; it does not fulfill
the bead's real-CLI, signed archive, forge restoration or 1 GiB drill acceptance.
