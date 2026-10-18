# Verify candidate pack bytes before saving or staging a source change

The source-authoring CLI has three explicit packed-candidate operations:

| Operation | Same input arguments as | Additional required verification |
| --- | --- | --- |
| `prepare-packed` | `prepare` | Decode and verify the actual received pack before saving the candidate. |
| `inspect-packed` | `inspect-candidate` | Repeat source, effect, root and pack verification offline. |
| `stage-packed` | `stage` | Verify the exact saved pack before creating the standard one-shot journal. |

Use these operations for the native source service's incremental candidate
profile. An internally consistent inspection report and updated artifact hash
are not proof that the pack contains its advertised objects. These commands
reuse `verifySourceCandidatePack` to reject corrupt, incomplete, substituted or
extra objects. They do not fall back to report-only checks on a refusal.

## Prepare and inspect

Use the independently retained package, expectation and reviewed draft from
`SOURCE_CHANGE_AUTHORING.md`, or the self-contained outputs of workspace capture
and explicit base replay. The target selection remains independent of the server.

```bash
node scripts/fg_source_changes.mjs prepare-packed \
  --package /private/session/source.json \
  --expect /private/session/expected.json \
  --changes /private/session/changes.json \
  --selection /private/session/native-selection.json \
  --confirm-draft-sha256 "$REVIEWED_DRAFT_SHA256" \
  --token-file /private/session/read-token \
  --output /private/session/candidate
```

An explicit `--ca-file PRIVATE_PEM` is available for authenticated HTTPS.
Preparation still performs only the existing prepare/inspect reads, not apply.
The reviewed draft is regenerated before network I/O. Source inputs, profile
choices, target and limits are owned before asynchronous work. The returned
original bundle is independently checked before claiming any candidate output
slot; a rejected pack never produces a report-only candidate in this command.

```bash
node scripts/fg_source_changes.mjs inspect-packed \
  --package /private/session/source.json \
  --expect /private/session/expected.json \
  --changes /private/session/changes.json \
  --confirm-draft-sha256 "$REVIEWED_DRAFT_SHA256" \
  --candidate /private/session/candidate \
  --sha256 "$RETAINED_CANDIDATE_MANIFEST_SHA256"
```

Inspection accepts no credential or network option and writes nothing. Saved
success flags cannot replace decoding or the independently regenerated expected
object inventory. Binary and multi-hunk source profiles remain explicit and
carry through this same pipeline without changing their reviewed draft hashes.

## Stage the exact independently selected target

```bash
node scripts/fg_source_changes.mjs stage-packed \
  --package /private/session/source.json \
  --expect /private/session/expected.json \
  --changes /private/session/changes.json \
  --selection /private/session/native-selection.json \
  --confirm-draft-sha256 "$REVIEWED_DRAFT_SHA256" \
  --candidate /private/session/candidate \
  --sha256 "$RETAINED_CANDIDATE_MANIFEST_SHA256" \
  --principal "$ORIGINAL_PRINCIPAL" \
  --confirm-candidate "$REVIEWED_CANDIDATE_COMMIT" \
  --journal /private/session/new-journal
```

Staging is offline and accepts no token or CA. It verifies the exact target,
principal/candidate consent, original source, intended effects, expected root
and actual pack. Only then does the existing verified-staging owner create its
standard self-contained journal. That owner reloads the same candidate manifest
hash; a changed pathname cannot substitute different unverified bytes.

The returned receipt adds `pack_verification`, including the original artifact,
base, candidate, expected tree, draft and object-inventory commitments. Its
`candidate_manifest_sha256` binds the evidence to the journal's candidate input.
The journal format and request/key derivation are unchanged. Pack evidence is a
returned verification result, not a new mutable permission record. Reproducing
the source proof later requires the original independently retained inputs.

Use `fg_source_edit.mjs apply`, `recover` and `status` on this journal exactly as
in `VERIFIED_SOURCE_STAGING.md`. Apply is a separate explicit operation. Recovery
uses the original key and retained candidate without needing the external source
or candidate path; it does not upload again. An unknown original outcome is not
permission to create a different journal or retry with a new base/key.

## Bounds, failure and compatibility

All commands retain normalized absolute owner-private POSIX input rules and
create-only outputs. One `--timeout-ms` budget (1..300000, default 30000) spans
source verification, network work, decoding and local handoff. The decoder also
retains its own at-most-30000 ms ceiling. No partial verification is accepted.
Once the existing local output owner starts a write, its sync/readback drain and
exit-4 retained-output semantics still apply. Lost stdout never erases a journal.
This is a trusted-local profile, not hostile same-user parent confinement or an
atomic filesystem snapshot.

The exact supported envelope and resource bounds are in `SOURCE_CANDIDATE_PACKS.md`:
one native SHA-1/SHA-256 base prerequisite, one selected branch, compressed
no-delta objects, an 8 MiB original candidate and at most 1024 unique asserted
objects. The underlying decoder bounds expansion, work and memory. No codec or
native acceptance policy is added here. Library consumers in
`source_candidate_pack_flow.mjs` may further narrow `packLimits`, never raise them.

Existing `prepare`, `inspect-candidate` and `stage` keep their broader report-only
behavior and do not acquire pack guarantees by association. They do not load the
decoder unless a packed operation is selected. A draft hash confirms the intended
change, not that a later caller selected the stronger command. Choose the packed
operation at each handoff; the command never downgrades itself automatically.

Pack object verification does NOT verify unchanged base closure, gitlink targets,
author signatures, currentness, authorization, or an authority's publication.
The original bundle is never rewritten for saving or apply. Native Rust retains
admission, policy and publication authority.

Run `bash scripts/verify_packed_source_flow.sh`. The added tests use full existing
modules, real files/CLI processes, HTTP/TLS peers and test-only Git-created packs.
They test corruption that passes report-only checks, consent/target substitution,
caller mutation, limits, cancellation, concurrent journal creation, binary
multi-hunk workspace capture, lost output and original-key recovery. The peers
model native schemas, not an executed Rust node. This lane is not Cargo, native
TreeFS/authorization/admission/CAS, hardware durability or whole-repository proof.
