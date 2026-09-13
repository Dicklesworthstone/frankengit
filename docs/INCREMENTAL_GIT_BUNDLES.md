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
reader and excludes the complete prerequisite closure. The native pack planner
and writer produce the actual bytes. Export does not mutate canonical state,
and never replaces an existing output file. The current implementation still
verifies the complete visible graph, so reduced transfer size is not a claim
of reduced server-side read cost or larger repository capacity.

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
domains. Test presence is not execution evidence; results must name a tested
revision. Full workspace, lint, release, external-Git conformance, and remote
transport authentication are not implied by this document.
