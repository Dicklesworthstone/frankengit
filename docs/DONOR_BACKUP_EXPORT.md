# Export the current snapshot with object bytes from an older backup

`fg backup export` can use an independently pinned, fully verified historical
source backup to supply Git objects that the current source still selects. This
allows a new backup of the **current** repository when an older selected object
has become missing or corrupt in local storage. Newer refs, forge events,
transaction outcomes and retained checkpoint evidence come from the current
source. The command creates a new ordinary source backup and leaves live object
placements unchanged.

The current source must still open and authenticate its authority, exact selected
inventory, configuration and any selected retained checkpoint. A donor supplies
Git payloads; it cannot replace damaged authority or checkpoint evidence. Every
current object absent from the donor must remain readable and verifiable locally.

## Command

Use the SHA-256 that was retained independently when the older backup was made or
approved. A checksum supplied beside an untrusted archive does not establish
provenance. The source, donor, output and scratch paths below are separate.

```sh
fg backup export ./fgit-data ./current-recovery.fg \
  11111111111111111111111111111111 22222222222222222222222222222222 \
  --trusted-local --object-format sha256 \
  --donor-backup ./old-source-backup.fg \
  --donor-sha256 "$INDEPENDENTLY_RETAINED_DONOR_SHA256" \
  --donor-scratch ./new-donor-verification-root \
  --donor-verification-instance "$UNUSED_VERIFICATION_INSTANCE"
```

The same flags work with `fg-repository-backup export`. The four donor flags are
required together. `--donor-verification-instance` is a positive SQL integer for
the isolated verification store and must differ from the donor's original store
instance. Use an unused instance and a new scratch path. Ordinary export without
donor flags keeps its existing transport bytes and receipt fields.

The current backup's receipt reports its own SHA-256. Retain that checksum
independently, then use the ordinary restore command with a fresh destination:

```sh
fg backup restore ./current-recovery.fg ./recovered-current-node \
  --trusted-local --expected-sha256 "$INDEPENDENTLY_RETAINED_CURRENT_SHA256" \
  --destination-instance "$UNUSED_DESTINATION_INSTANCE"
```

The donor checksum and the resulting backup checksum identify different files.
The result uses the existing `FGSRC001` format, or `FGSRC002` when the current
source selects retained outcome evidence. An older `FGSRC001` donor can supply
Git objects for a current `FGSRC002` export. The current checkpoint's original
root, manifest and envelopes are preserved through the existing capture and
verification path.

## What must agree

The operation checks all of the following before publishing an output:

1. The donor matches its independently supplied whole-file SHA-256. The existing
   native preflight verifies its portable authority image, exact selected Git
   inventory, original independent payload commitments, native object identities,
   complete typed graph and any retained checkpoint evidence. Decoding alone
   cannot create the opaque verified donor used by the export.
2. Donor and source have the same tenant, repository, repository incarnation and
   native object format. A backup of a recreated repository cannot supply bytes
   merely because the namespace and native OIDs match.
3. The donor's exact canonical authority head is an ancestor of the current
   export capture. The existing authority-head ancestry reader follows exact
   predecessor identities with a finite hop bound. The result must bind the same
   head slot, version token, generation and body that selected the current
   authority image. Generation ordering alone does not establish ancestry.
4. Every selected output object has complete, verifiable bytes. Donor overlap is
   selected before any local payload read; current objects absent from the donor
   use the existing native source reader. A failed local record is never retried
   from another source after its output framing has begun.
5. The final private output file is independently decoded and checked against
   the current identity, authority image, exact selected inventory, typed graph,
   refs and checkpoint. The source head must still exactly match the capture
   after all donor and local reads finish.

The donor retains one opened input descriptor across preflight and composition.
The composition pass checks its original header, object commitments, whole-file
digest, length and exact EOF again. Even donor records absent from the current
selection are fully consumed and authenticated. A late donor failure prevents
publication; it cannot silently turn the operation into an ordinary local export.

The current output remains private until its complete graph and source-head
checks succeed, the source node closes, and the existing create-only durable
publication protocol finishes. There is no metadata rollback, authority-head
write, new archive format or new canonical identity in this operation.

## Bounds, cancellation and paths

Existing explicit `--max-archive-bytes`, `--max-blob-bytes`, `--max-objects` and
`--timeout-secs` flags apply to both the donor verification and current export.
The donor and current inventories must each fit the selected object allowance;
neither can be truncated. Their archives must each fit the byte allowance.
Repeated verification passes do not establish an aggregate disk-I/O allowance.
Metadata objects, authority rows, graph edges, refs and checkpoint evidence retain
their existing independent limits.

Ancestry defaults to **4,096 predecessor hops**. For an explicitly larger retained
history, select a bound from 1 through 65,536:

```sh
--donor-max-ancestry-hops 16384
```

A missing predecessor, a fork, a future donor, a moved source head or exhaustion
of this bound refuses the operation. No automatic retry or budget increase occurs.
All phases share the original cooperative command deadline, including donor
preflight. Native request cancellation and resource exhaustion also stop donor
streaming. Blocking filesystem calls remain subject to the existing cooperative
deadline limitation.

Git payloads merge in native-OID order with bounded reads of at most 64 KiB.
The composer retains the bounded selected identity set and one 64 KiB discard
buffer, not donor payloads. The existing encoder independently verifies each
selected payload and its exact EOF. Metadata parsing and authority/graph state
have separate bounded allocations.

This path currently requires the Unix directory-identity profile. Source and
donor leaf symlinks refuse. Canonical parent paths and held directory descriptors
detect path aliases, directory replacement and mode changes. Donor, output and
scratch cannot alias, contain one another, or reside inside the live source. The
output and scratch may share a stable existing parent outside the source.
Parents remain trusted operator-controlled paths; these checks are not a sandbox
against an adversarial process with the same user identity.

Output and scratch must not already exist. Successful donor preflight closes and
removes its own isolated scratch state. A failure after scratch creation may
retain it for diagnosis under the existing verification contract; an existing
scratch path is never reused or removed by a new attempt. Output publication
never overwrites an existing file. Keep any refused attempt's retained evidence
and choose new paths when retrying after resolving its cause.

## Receipt and operational scope

A successful donor export adds a `donor_backup` object to the existing export
receipt. It includes the original donor SHA-256, donor canonical head ID and
generation, verified ancestry hop count, selected object and payload-byte counts
supplied by the donor, and the count supplied by local storage.

`selected_objects_supplied` counts the selected donor route, including overlapping
objects whose local copies might still be healthy. It is not a damage count.
`source_objects_repaired` is always `false`: the original source's damaged bytes
remain damaged. The result is a new backup that can be restored and inspected in
an isolated destination through the existing recovery workflow.

The receipt does not approve service activation, routing, garbage collection or
live-placement repair. External artifacts, credentials, signing keys, runner
workspaces and other data outside the source-backup scope remain excluded. Review
restored outbox state and external dependencies before starting workers or
serving the recovered repository. See [repository source recovery](REPOSITORY_SOURCE_BACKUP.md)
for the complete transport and restore contracts.
