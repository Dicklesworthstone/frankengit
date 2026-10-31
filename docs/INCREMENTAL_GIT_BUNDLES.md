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
below emits each selected body through the existing bounded encoder. Export
does not mutate canonical state, and never replaces an existing output file.
The current implementation still
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

The streaming path keeps bounded native metadata, a blob input chunk and
compressor state plus bounded object, edge and header metadata. Output and
expanded-body allowances each default to 128 MiB and can be raised independently
through 16384 MiB. The
buffered object default and ceiling remain 32 MiB. The independent
`--max-blob-mib` allowance defaults to 32 MiB and accepts 1 through 16384 MiB;
large selected blobs use the checked native streaming reader. This does not
widen metadata, aggregate expanded-byte, output or work limits. It accepts the
same byte, object, reference, graph, compression-work and timeout options as
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

An emitted blob must finish at its declared length and pass the original stored
commitments and native hash before the bundle completes. Premature EOF, extra
bytes, corruption and cancellation cannot produce a successful receipt. Short
source reads are combined into the same fixed input chunks; small-object
ordering, compression bytes and both existing streaming profile identifiers
are preserved.

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
The default buffered `sync-import` input limit remains 128 MiB. Select the
file-backed receive profile below and set its independent limits explicitly
when receiving a larger artifact.


## File-backed incremental import

Add `--file-backed` to receive an incremental bundle without buffering the whole
input or its prerequisite blob bodies:

```sh
fg bundle sync-import "$DESTINATION" "$TENANT" "$REPOSITORY" change.bundle \
  --file-backed --trusted-local --object-format sha256 \
  --principal "$PRINCIPAL" --key-stdin --allow-ref-updates \
  --expect "refs/heads/main=$DESTINATION_OLD_TIP" \
  --max-input-mib 512 --max-expanded-mib 512 --max-original-mib 1024 \
  --max-object-mib 1 --max-blob-mib 256 --timeout-secs 600
```

The public node entry points are
`OneNode::import_incremental_git_bundle_reader_durable_in` and its controlled
variant. They take `StreamIncrementalBundleImportQuery`: an ordinary file-backed
bundle query plus an independent `max_original_bytes` allowance.

The input and uploaded expansion defaults remain 128 MiB and may each be raised
through 16384 MiB. `--max-original-mib` independently defaults to 128 MiB and
accepts 1 through 16384 MiB. It counts successful body reads while discovering
visible native metadata and capturing every object in the declared prerequisite
closure. Discovery reads and later capture share one ledger; revisiting a body
does not reset it. A larger original allowance does not increase uploaded pack
expansion, input, metadata allocation, or blob size limits.

Blob bodies default to 32 MiB and can independently be raised through
16384 MiB with `--max-blob-mib`. Metadata and delta programs default to 32 MiB
and remain capped there; `--max-object-mib` can narrow that allocation limit.
The object, ref-header, graph-edge, and timeout controls are shared with
[file-backed full import](NATIVE_GIT_BUNDLE_FILE_IMPORT.md). The CLI still
requires explicit update consent and at most 64 exact destination expectations.
Existing visible roots use a separate finite discovery bound; a small incoming
ref set does not make otherwise visible prerequisites unavailable.

The receiver first selects current visible history at one authenticated
authority basis. It checks typed metadata dependencies and requires every
declared prerequisite to be a visible commit. It then authenticates every
original body into private file spans. Large original blobs use bounded chunks
and must pass stored commitments, exact native identity, length, and
authenticated EOF before they become eligible dependencies or delta bases.
A merely readable header does not establish original-body health.

An independent original-only graph audit requires each declared prerequisite's
complete closure. Incoming objects cannot repair missing original history.
Original spans are separate from uploaded pack entries, offsets, indexes, and
receipt counts. Native internal OFS/REF deltas, forward REF bases, and
prerequisite-scoped external REF_DELTA bases are supported. Supplied objects
still pass native verification and graph checks even when their IDs overlap
original history. Duplicate pack identities refuse; a verified uploaded/original
overlap must agree in kind, length, and strong body commitment.

Only the selected uploaded closure and required uploaded transport bases enter
synced publication staging. The final permitted closure includes selected
originals, but their private verification spans are not represented as uploaded
pack objects. A full bundle with no prerequisites uses an empty original source
and cannot borrow from destination storage.

Admission consumes a basis-bound source-import proof. Its receipt records the
actual native pack checksum, strong pack digest, pack length, and prerequisite
closure commitment. Both initial planning and authority-CAS replanning reject a
changed selecting head; stale borrowed evidence cannot silently move onto a new
snapshot. The existing canonical driver still owns authentication, current
policy, exact old-tip leases, atomic refusal, and terminal publication.

Verification scratch is owned under the node and removed before admission.
Selected uploads use the existing synced private staging until normal admission
prepares object publication. Allow disk space for original verification spans,
uploaded verification spans, and selected staged uploads. The Unix input must
be a non-symlink ordinary file with stable components under the local operator's
control. The command does not accept an arbitrary scratch directory.

One sticky cancellation/deadline state covers discovery, source capture, pack
work, staging, and authority work. Pending admission drains with the original
request. Stdin credentials are collected before cooperative signal handling and
the native-work timer begin. Known terminal recovery precedes fresh original
health and payload validation, so the same canonical commands, principal, and
exact key recover the existing receipt across buffered and file-backed profiles.
A returned error still does not establish non-commit.

## Atomic incremental import
Import validates prerequisite reachability against the exact current visible
ref snapshot, including complete native dependency bytes and required kinds.
Only that declared history can supply omitted graph edges or external REF_DELTA
bases. Merely stored, previously admitted, hidden-only, disconnected, or visible
but undeclared objects cannot repair an incomplete transfer. Submodule gitlinks
remain foreign-repository data. A valid prerequisite is not a shallow boundary.
The buffered profile shares native quarantine validation. The file-backed profile
uses separate authenticated original and uploaded custody with the same native
parsers, delta engine, and graph rules; original-byte accounting continues across
prerequisite verification and external-base loading. Repeated phase-specific graph walks
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
zero-object transfer checks. The large-blob process target also exercises actual
file-backed incremental reception of a 33 MiB upload with 1 MiB metadata and
original allowances, then reuse of that blob through a zero-entry incremental
pack. It checks independent original/blob/expansion refusals, exact native bytes
and closures, private-stage cleanup, and buffered/file-backed terminal replay.
Focused admission tests cover stale basis, terminal recovery, and a real competing
publication during CAS retry. Test presence is not execution evidence; results must name a tested
revision. Full workspace, lint, release, external-Git conformance, and remote
transport authentication are not implied by this document.
