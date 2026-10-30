# Native file-backed full-bundle import

`fg bundle import --file-backed` imports a self-contained Git bundle into an
initialized FrankenGit node while keeping large blob bodies in private files.
It uses the native bundle, pack, delta and typed graph validators, followed by
the same atomic source-import admission and authority publication as other
native imports. No external Git executable participates.

## Import a full bundle

Initialize the destination in the bundle's hash format. The following SHA-256
example permits a 512 MiB input, 1 GiB of expanded bodies, 256 MiB individual
blobs and 1 MiB individual metadata bodies:

```bash
fg init "$DESTINATION_ROOT" "$TENANT" "$REPOSITORY" sha256
printf '%s' 'full-transfer-001' | fg bundle import \
  "$DESTINATION_ROOT" "$TENANT" "$REPOSITORY" source.bundle \
  --file-backed --trusted-local --object-format sha256 \
  --principal "$PRINCIPAL" --key-stdin \
  --max-input-mib 512 --max-expanded-mib 1024 \
  --max-object-mib 1 --max-blob-mib 256 --timeout-secs 600
```

Use `sha1` for a SHA-1 repository. The command is a trusted-local operator
surface. Its Unix input must be a nonempty ordinary file with non-symlink path
components, held stable under the operator's control. One descriptor is used
throughout, and its identity/version is checked at completed source EOF.
Scratch is created privately under the node's existing fabric staging directory;
there is no caller-supplied scratch path or reuse of a previous process's files.

Every advertised direct reference is an expected-absent creation. All updates
belong to one atomic transaction. Any existing destination name refuses the
whole update, even if it already points at the same object. A HEAD advertisement
does not change destination HEAD configuration. Current policy and exact-basis
authority checks still decide admission.

This profile accepts full V2/SHA-1 and V3 native bundles, internal OFS and REF
deltas, and forward REF bases. Large blob bases/results use chunked scratch
reads; delta programs and commit/tree/tag bodies retain their bounded allocation
profile. Prerequisites, external delta bases, filtered bundles and implicit force
remain unsupported. Missing objects cannot be borrowed from destination storage.
Every supplied object is verified; only the selected reference closure and its
required transport delta bases are staged for admission. Gitlinks remain external
repository dependencies.

`sync-import` and mapped `bundle fetch` retain their existing buffered profiles.
This option does not turn an incremental or mapped transfer into a full import.

## Independent limits

| Option | Default | Accepted range and scope |
| --- | --- | --- |
| `--max-input-mib` | 128 | 1..16384 MiB for the whole bundle and pack input |
| `--max-expanded-mib` | 128 | 1..16384 MiB for aggregate expanded object bodies |
| `--max-blob-mib` | 32 | 1..16384 MiB for each streamed blob, including blob delta bases/results |
| `--max-object-mib` | 32 | 1..32 MiB for buffered metadata and delta programs |
| `--max-objects` | 100000 | 1..1000000 included objects and bounded inventory entries |
| `--max-refs` | 4096 | 1..4096 header records, including optional HEAD |
| `--max-edges` | 1000000 | 1..8000000 typed graph edges |
| `--timeout-secs` | 300 | 1..3600 seconds across this invocation; an explicit global timeout can narrow it |

Raising the blob limit does not raise metadata, aggregate bytes, graph work or
delta resolution work. Existing finite native decoder and resolution budgets
remain in force. These are independent resource ceilings, not a promise about
total process RSS or every possible delta layout. Allow disk space for verified
scratch plus private staged objects during preparation. Blob payloads are
authenticated through bounded chunks; metadata is retained only within its
separate limits and bounded staging batches.

Embedding callers use `StreamBundleImportQuery` and
`OneNode::import_full_git_bundle_reader_durable_in`, or its controlled variant
with a sticky cancellation probe. Configure `NodeConfig::with_bundle_import_blob_limit`
to permit larger imported blobs. This setting does not widen receive-pack,
metadata parsing, source browsing or selected-pack serving limits. The node
intersects each query with its configured policy. Callers retain responsibility
for their reader's blocking I/O and source stability.

## Private custody, publication and retry

Verification retains the original authenticated object inventory and span
checksums. Each selected blob is independently checked against its native ID and
the fabric's registered strong payload commitment while it is streamed into a
private synced file. The owner retains the original envelope and file identity.
Later publication reauthenticates that original custody; a substituted
self-consistent file or a healthy permanent copy cannot repair a corrupt private
candidate. Existing immutable names are compared with bounded reads.

Raw verification scratch is removed before admission starts. Private object
custody is linked into permanent storage only when ordinary admission prepares
a commit, and durability precedes its authority-head CAS. A canonical refusal
before commit preparation abandons the private objects. A failure after placement
starts, or a lost CAS followed by refusal, can leave unreferenced immutable
objects; their existence does not establish repository authority.

The output is the existing `git_bundle_import` JSON receipt. Exit 0 means a
committed terminal decision, 3 means a canonical refusal, and 2 means an input,
infrastructure, output or cleanup failure. A returned terminal decision remains
authoritative if later shutdown or receipt output fails. When no terminal outcome
is available, retry the original semantic commands and exact key or use
`fg outcome`; an error does not prove non-commit.

Buffered and file-backed imports share semantic transaction identity. The same
principal, exact key and advertised command set recover the same terminal result
before fresh payload, quota or serving gates. Reordered advertisements or a
different encoding of the same native commands do not create another operation.
The bounded semantic header still has to parse. Recovery of a known decision is
not a fresh verification of the artifact body. Stdin keys preserve exact bytes,
including newlines, and receipts never print the key.

## Focused validation targets

These commands select the regression coverage; listing them is not a claim that
a particular checkout has run them successfully. Use the pinned repository
toolchain and the repository's normal build runner:

```bash
cargo test --locked -p fgit-object-fabric --lib local::synced_blob
cargo test --locked -p fgit-node --lib source_retrieval::integrity::bundle_verify::file::tests::import_tests
cargo test --locked -p fgit-node --lib treefs_workspace::full_bundle::tests::file_import_tests
cargo test --locked -p fgit-cli --bin fg bundle::stream_import
cargo test --locked -p fgit-cli --test bundle_stream_export_large_blobs -- --test-threads=1
```

The cases cover both native hash formats, real file readers and node reopen,
internal blob deltas, exact closure selection, corrupt/missing typed dependencies,
limits, source or scratch substitution, cancellation during private staging,
same-key retry, atomic name collisions and cleanup. The process fixture uses a
real 33 MiB blob with an empty `PATH`, verifies the actual imported node's exact
closure and streamed body, and compares receipts across both import profiles.
