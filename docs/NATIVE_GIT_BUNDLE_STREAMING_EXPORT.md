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

## Native CLI and operator contract

The explicit streaming command exports the current visible refs and their
complete native object graph from one authority-selected repository snapshot:

```sh
fg bundle export /srv/frankengit TENANT_ID REPOSITORY_ID /srv/backups/source.bundle \
  --streaming --trusted-local --object-format sha256 \
  --max-output-mib 256 --max-expanded-mib 256 \
  --max-compression-work 4000000000 --timeout-secs 600
```

Replace the IDs with the repository's actual 32-character hexadecimal IDs, and
choose the repository's actual object format. The example explicitly increases
both byte allowances and the separate compression-work allowance. It is an
operator-selected ceiling, not a promise that every repository of that size
fits the remaining independent limits. Omitting `--streaming` retains the
existing materializing export behavior. Streaming requires the explicit
`--trusted-local` disclosure grant; it accepts neither mutation credentials nor
an idempotency key. Canonical hidden-ref policy still applies.

| Option | Default | Accepted values |
| --- | ---: | --- |
| `--object-format` | `sha1` | `sha1` or `sha256` |
| `--max-output-mib` | 128 | 1 through 16384 MiB |
| `--max-expanded-mib` | 128 | 1 through 16384 MiB |
| `--max-object-mib` | 32 | 1 through 32 MiB |
| `--max-objects` | 100000 | 1 through 1000000 |
| `--max-refs` | 4096 | 1 through 1000000, including advertised HEAD |
| `--max-edges` | 1000000 | 1 through 8000000 |
| `--max-compression-work` | 1000000000 | 1 through 1000000000000 |
| Leaf `--timeout-secs` | 300 | 1 through 3600 seconds |

Numeric leaf options require positive canonical decimal integers; duplicate and
unknown options refuse. The independent header-byte limit remains 1 MiB and is
not widened by `--max-refs`. The expanded-byte allowance counts the selected
native object bodies. It does not measure physical rereads during selection
and emission. The per-object allowance also configures the node's object-read
bound before allocation. The streaming memory contract remains one bounded
object and compressor plus bounded object, edge and header metadata.

### Deadline and cancellation

The leaf timeout covers private staging, node startup, source selection and
streaming, shutdown and the prepublication checks. An explicitly supplied
leading global timeout narrows that allowance: for example,
`fg --timeout-secs 30 bundle export ... --streaming --trusted-local --timeout-secs 600`
has a 30-second effective budget. A larger global timeout does not widen the
leaf. With no explicit global override, the leaf's 300-second default applies.
The existing global parser also accepts fractional seconds; the streaming leaf
accepts whole seconds.

One monotonic clock tracks the effective budget. The node receives only its
remaining duration in both the request context and the streaming query.
Termination signals and deadline expiry become sticky cancellation. Pending
native work is requested to stop and drained, and an opened node is shut down
before the command decides whether publication is allowed. Cleanup continues
after cancellation. These checks are cooperative: a blocking operating-system
read, write or synchronization call is not preempted at an exact wall-clock
instant.

### Private file publication and refusals

This local publication profile requires Unix and an existing destination
parent. Every named parent component must be an ordinary non-symlink directory;
parent traversal is rejected. The local operator must control the source and
destination namespace and keep it stable during the operation. Descriptor and
path identity checks detect common replacement and alias races; they are not
an isolation boundary against an adversary with the same filesystem authority.

The command exclusively creates a fresh mode-0600 temporary file in the
destination directory and writes bounded chunks into that file. It does not
publish the requested output name until native export succeeds and the node
closes successfully. It then checks the receipt's byte count and file identity,
synchronizes the file, creates a hard link at the new output name without
replacement, removes its temporary name and synchronizes the parent directory.
The successful output remains mode 0600. An existing destination, including a
symlink or directory, is never replaced.

A failure before publication leaves no output at the requested name and
removes only this attempt's exact owned temporary file. Cleanup verifies both
the parent and file identities. A replaced parent, replaced or aliased file,
or changed ownership/mode can cause an `export_cleanup_incomplete` refusal with
the retained path; the command does not delete an unowned replacement. A crash
can also leave a private temporary file. Later attempts neither reuse nor
silently remove those residues.

After the create-only hard link succeeds, errors report
`publication_state=visible` and `bundle_created=true` until parent synchronization
completes. A receipt-output failure after synchronization reports
`publication_state=durable` and `bundle_created=true`. The final file is preserved
in either case. Exit status 0 means a complete locally durable export with its
receipt written; status 2 reports an input, source, cancellation, output or
cleanup failure. A nonzero exit by itself does not mean no file was created.

### Receipt and recovery scope

Success writes one JSON `git_bundle_export` receipt, schema version 1. Its
`streaming` flag is true and its `profile` is
`git-pack-compressed-oid-no-delta-v1`. The receipt contains:

| Fields | Meaning |
| --- | --- |
| `source_head`, `source_generation`, `tenant_id`, `repository_id` | The selected source authority snapshot and namespace |
| `object_format`, `object_count`, `total_object_bytes` | Native hash domain, selected object count and expanded body bytes |
| `pack_checksum`, `pack_bytes`, `header_bytes`, `bundle_bytes` | Native pack identity and exact encoded sizes |
| `bundle_sha256`, `compression_work` | Whole-file SHA-256 and aggregate charged encoder work |
| `publication_state`, `bundle_created`, `node_closed` | `durable`, true and true after completed local publication |
| `repository_changed`, `includes_forge_metadata` | Both false |

The source snapshot may cease to be the current head while the export runs.
The receipt identifies what was selected; it does not promise completion-time
freshness. Its whole-file SHA-256 is an artifact fingerprint and does not itself
authenticate an issuer. The resulting file is consumable by the native
file-backed `fg bundle verify` and `fg bundle recover` commands. This transfers
Git objects, direct refs and HEAD; it does not restore forge metadata, authority
policy, credentials, or a complete signed repository capsule.

### CLI validation targets

These commands select the implemented checks; their presence here is not a
claim that a particular checkout has passed them. Run them with the repository's
pinned toolchain and an isolated target directory:

```sh
export CARGO_TARGET_DIR=/data/frankengit-targets/streaming-cli
cargo test -p fgit-cli --bin fg bundle::stream_export --locked
cargo test -p fgit-cli --test bundle_stream_export_filesystem --locked
cargo test -p fgit-cli --test bundle_stream_export --locked -- --test-threads=1
```

The unit and real-filesystem targets cover argument boundaries, create-only
publication, partial-output cleanup, identity replacement, aliases, permission
changes, cancellation and truthful visible/durable failures. The real `fg`
process target exercises both hash domains through source import, streaming
export, file-backed verification and native bare-repository recovery, with no
foreign executable available on PATH. It also checks deterministic receipts
and bytes, narrowed resource refusals, destination collisions and a shorter
global deadline. Its ordinary fixtures are small; the separate native codec
large-file target above does not substitute for a large real-CLI recovery drill.
