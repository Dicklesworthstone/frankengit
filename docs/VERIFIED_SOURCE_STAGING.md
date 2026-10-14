# Stage an independently verified source change

`fg_source_changes.mjs stage` joins the verified authoring workflow to the
existing one-shot publication journal. It is an offline, trusted-local operation:
it has no token, CA, redirect, retry or network option and does not apply a
repository change. The reusable entrypoint is `stageVerifiedSourceChanges` in
`scripts/operator/source_changes_prepare.mjs`.

Use the original independently retained source package/expectation, explicit
changes, and native target selection from the draft/prepare workflow documented
in [SOURCE_CHANGE_AUTHORING.md](SOURCE_CHANGE_AUTHORING.md). Explicit file copies
and renames use [SOURCE_RELOCATION.md](SOURCE_RELOCATION.md). Review the patch,
manifest, candidate and target selection before confirming them. A server or an
imported package must not choose the independent expectation for the operator.

```bash
node scripts/fg_source_changes.mjs stage \
  --package /private/session/source-package.json \
  --expect /private/session/independent-expectation.json \
  --changes /private/session/changes.json \
  --selection /private/session/native-selection.json \
  --candidate /private/session/candidate \
  --sha256 "$CANDIDATE_MANIFEST_SHA256" \
  --confirm-draft-sha256 "$REVIEWED_DRAFT_SHA256" \
  --principal "$ORIGINAL_PRINCIPAL" \
  --confirm-candidate "$REVIEWED_CANDIDATE_COMMIT" \
  --journal /private/session/new-journal
```

All paths must be normalized absolute paths using the existing owner-private
POSIX custody rules. The candidate directory and journal must not overlap.
The journal must not exist. Every command still has one caller-selected
`--timeout-ms` budget, from 1 through 300000 milliseconds (default 30000).

Before creating any journal, staging:

1. Re-verifies source membership and complete original blobs, reconstructs every
   intended file effect and recomputes the whole expected root tree.
2. Requires the reconstructed draft to match the reviewed manifest hash, then
   loads and verifies the candidate under its separately retained manifest hash.
3. Checks explicit candidate-ID consent and compares the complete independent
   native selection with the candidate's request: endpoint, tenant, repository,
   incarnation, native hash domain, branch, original commit, effect paths,
   author, committer, timestamp and message.
4. Rechecks all intended effects and the candidate root before handing that exact
   candidate manifest hash and the explicitly selected principal to the existing
   `stageSourceApply` owner.

The principal is an explicit operator selection, not an authentication proof.
Actual native apply must authenticate the credential as that original principal
and perform its usual policy, admission and authority checks. The selected
source package proves native content commitments, not which repository currently
owns those objects or whether the operator has permission to publish them.

The returned standard `source_apply_staged` receipt includes `request_sha256`,
the original key, candidate ID and an additional `binding` describing the verified
draft/target/root. Keep the returned request hash independently. The standard
journal contains a self-contained candidate copy and a request committing to its
manifest hash, target and principal. The source-change binding is returned
context, not a new authority receipt or a separate mutable permission database.
Reproducing the source proof later still requires the original package,
expectation, changes, selection and reviewed hashes.

Publication remains a separate explicit command:

```bash
node scripts/fg_source_edit.mjs apply \
  --journal /private/session/new-journal \
  --request-sha256 "$RETAINED_REQUEST_SHA256" \
  --token-file /private/session/write-token
```

Use `fg_source_edit.mjs status` for offline journal inspection and its `recover`
command with the same journal and original request hash after an uncertain reply.
Recovery only looks up the original key. Do not stage a new journal to retry an
uncertain publication: per-journal one-shot ownership is not global deduplication.
Neither missing outcomes nor an interrupted process prove non-commit.

A failure before journal creation leaves no staged request. Once the underlying
owner has claimed the new directory, it drains its started writes, syncs and
readback even after a late cancellation. Exit 4 retains a result or unconfirmed
publication identity when local output may exist. A failed stdout write does not
remove or invalidate the journal. Reopening checks the exact candidate manifest;
changing its source pathname between verification and staging cannot substitute
different candidate bytes under the retained hash.

No canonical request, candidate, journal, dispatch or recovery format is changed.
The broader `fg_source_edit.mjs stage` remains available for independently
managed candidates; it does not acquire the stronger source-authoring checks by
association. No stage operation checks complete candidate pack closure, live
branch freshness, signatures, authorization or native policy independently.

Run `bash scripts/verify_source_changes.sh`. The staging regressions use complete
production modules, native-schema HTTP peers, Git-created candidate objects,
private files and real CLI processes. They cover target/consent substitution,
self-consistent hidden changes, mutable inputs, cancellation, competing staging
processes, public/corrupt files, lost stdout and original-key recovery after loss
of external source inputs. The peer is not a running Rust server. These tests do
not establish native authorization/CAS, power-loss durability, hostile-parent
confinement, browser behavior or full-workspace correctness.
