# Incremental Git bundle synchronization

`fg bundle sync-export` emits a native V2/SHA-1 or V3/SHA-256 incremental
bundle containing only the objects missing from its declared prerequisite
history. `sync-import` applies every advertised direct ref in one atomic
transaction using an explicit expected-old value for each destination.

```sh
fg bundle sync-export "$SOURCE" "$TENANT" "$REPOSITORY" change.bundle \
  --trusted-local --ref refs/heads/main --prerequisite "$BASE_COMMIT"
fg bundle sync-import "$DESTINATION" "$TENANT" "$REPOSITORY" change.bundle \
  --trusted-local --principal "$PRINCIPAL" --key-stdin \
  --allow-ref-updates --expect "refs/heads/main=$DESTINATION_OLD_TIP"
```

Add `--object-format sha256` for SHA-256 repositories. Repeat `--ref` and
`--prerequisite` on export and `--expect` on import, with up to 64 of each.
`--expect refs/heads/new=absent` requests creation. Duplicate, missing, extra,
zero, or cross-domain expectations refuse. No implicit refresh, deletion,
ref mapping, pruning, or remote identity system is supplied by these commands.
The expected tip need not be a prerequisite; it is a destination lease, not an
assertion about the transfer's contents. An exact lease plus explicit update
consent permits history rewrites subject to repository policy. The separately
existing mapped-ref full-bundle fetch API retains its fast-forward and tag rules.

The original `bundle import` remains self-contained and create-only. The
original `bundle export` remains a full export. Their existing bytes and
recovery identities do not change. A full bundle may also be supplied to
`sync-import`, but cannot borrow omitted dependencies without prerequisites.

Export verifies current visible history with the native upload-pack graph
reader and excludes the complete prerequisite closure. The original buffered
profile uses the native pack planner and writer; the explicit streaming profile
below emits each selected body through the existing bounded encoder. Export does not mutate canonical state,
and never replaces an existing output file. The current implementation still
verifies the complete visible graph, so reduced transfer size is not a claim
of reduced server-side read cost or larger repository capacity.

## Streaming incremental export

Add `--streaming` to select the incremental writer without a payload-bearing
pack plan or whole-bundle output buffer:

```sh
fg bundle sync-export "$SOURCE" "$TENANT" "$REPOSITORY" change.bundle \
  --streaming --trusted-local --object-format sha256 \
  --ref refs/heads/main --prerequisite "$BASE_COMMIT" \
  --max-output-mib 256 --max-expanded-mib 256 \
  --max-compression-work 4000000000 --timeout-secs 600
```

The streaming path keeps one bounded native object and compressor plus bounded
object, edge and header metadata. Output and expanded-body allowances each
default to 128 MiB and can be raised independently through 16384 MiB. The
per-object default and ceiling remain 32 MiB. It accepts the same byte, object,
reference, graph, compression-work and timeout options as
[full streaming export](NATIVE_GIT_BUNDLE_STREAMING_EXPORT.md). The independent
64-reference and 64-prerequisite frontier bounds still apply. The reference
ceiling also bounds all visible roots needed to prove the prerequisite history,
even when fewer refs are selected for export. Raising an output limit does not
widen another limit.

The node selects one authenticated starting snapshot and combines caller
visibility with its canonical hidden-ref policy. It checks all prerequisites
against that visible graph and requires commit targets. The existing native
graph reader supplies the verified metadata and typed closure facts for the
omitted history. The prerequisite and wanted walks reuse those facts rather
than rereading omitted bodies; all graph discovery remains independently
bounded and retains the native reader's 4,000,000-edge ceiling. Selected payload
sizes are bounded before emission, and the codec
checks each emitted object's native identity and actual typed edges.

An external closure is a transfer assumption: the receiver must possess the
declared history. This export does not certify the physical health of omitted
blob payloads. Typed-edge blobs need only their bounded stored headers during
discovery; emitted bodies receive full storage and native verification.
An advertised tip entirely within the prerequisite closure produces a valid
zero-object pack. Hidden-only or unrelated retained objects do not enlarge
the permitted frontier, and unrelated selected objects are rejected.

Objects are emitted in deterministic native-ID order with whole-object
compression and no delta window. Repeating the streaming profile at the same
snapshot and limits produces the same bytes; its bytes need not equal the
buffered profile's ordering. The receipt retains
`type=git_bundle_incremental_export`, adds `streaming=true` and the explicit
profile, and includes `reference_count`, `prerequisite_count`,
`external_object_count`, native pack checksum, whole-bundle SHA-256, byte counts
and compression work. `source_head` names the starting snapshot; it does not
claim that concurrent publication could not subsequently advance the source.

The command uses the full export's private-file owner: native completion and
successful node shutdown precede file synchronization, create-only publication
and parent synchronization. A prepublication refusal cleans only this attempt's
owned stage. An existing destination is never replaced. Errors after a file
becomes visible report that publication state and preserve the file. The same
Unix parent-directory ownership rules and cooperative cancellation limits apply.

An incremental bundle remains dependent on its declared originals.
`bundle verify` and `bundle recover` retain their self-contained full-bundle
contracts. Use a prerequisite-aware receiver for this transfer.
**The existing `sync-import` input limit remains 128 MiB**: raising the export
ceiling does not make this node's buffered import accept a larger artifact.

## Atomic incremental import
Import validates prerequisite reachability against the exact current visible
ref snapshot, including complete native dependency bytes and required kinds.
Only that declared history can supply omitted graph edges or external REF_DELTA
bases. Merely stored, previously admitted, hidden-only, disconnected, or visible
but undeclared objects cannot repair an incomplete transfer. Submodule gitlinks
remain foreign-repository data. A valid prerequisite is not a shallow boundary.
Native parsing, reconstruction, graph checking and staging share the existing
quarantine implementation; original-byte accounting continues across prerequisite
verification and external-base loading. Repeated phase-specific graph walks
remain separately bounded; no unlimited graph or fresh byte budget is introduced.

No upload is staged until its requested graph has passed. An interruption during
staging may leave verified noncanonical objects. Only the existing sealed
expected-old admission and exact-head CAS publish refs. Mandatory review policy
is checked through that same materializer: an incremental transfer is not a
merge approval or protection override. Any one refused ref refuses the complete
atomic operation. HEAD, repository configuration, forge metadata, and outbox
state are not imported.

Transaction identity describes the ref operation, principal, and byte-exact
retry key, not pack encoding, prerequisite comments, or temporary placement.
Known terminal recovery precedes fresh intake and may recover an earlier result
without verifying a replacement pack. This is not a claim that the replacement
pack was admitted. A changed expected-old field is a changed request. Shutdown
and output errors preserve known transaction outcomes in the existing receipt
path. `fg outcome` remains the artifact-free recovery mechanism.

The repository-owned verification command is:

```sh
bash scripts/verify_incremental_bundle.sh
```

It checks the real CLI, bounded parser cases, native file-backed transfer,
empty packs, thin REF_DELTA input, missing/wrong/undeclared/disconnected originals,
atomic stale-lease refusal, restart recovery, quota-independent replay, mandatory
protection, and the original full/mapped bundle regressions. The fresh-process
campaign independently decodes the exact emitted native objects for both hash
domains and both buffered and streaming export profiles. Its native commands run
with an empty executable search path. Streaming cases add source-limit refusals,
invalid outbound prerequisites, private-stage cleanup, deterministic repeats and
zero-object transfer checks. Test presence is not execution evidence; results must name a tested
revision. Full workspace, lint, release, external-Git conformance, and remote
transport authentication are not implied by this document.
