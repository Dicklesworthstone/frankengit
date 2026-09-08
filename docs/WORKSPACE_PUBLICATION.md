# Publishing reviewed workspace candidates

`fg workspace run` prepares a candidate; `fg workspace apply` is the separate,
explicit step that submits a saved, reviewed candidate through the node's real
quarantine, sealed-transaction and authority-head publication path. Preparation
still never moves a ref. See [the workspace command guide](TRUSTED_WORKSPACE_COMMAND.md)
for sparse inputs, trusted tool execution and bundle creation.

This is a Linux local-operator interface. The operator must be authorized to
mutate the repository and to act as the supplied principal. `--trusted-local`
acknowledges that boundary; it is not an authentication protocol, a remote agent
capability or a hostile-code sandbox.

## Apply the exact commit that was reviewed

After reviewing a candidate, retain its bundle and the source/candidate native
commit identities. Supply those identities independently of the bundle header:

```bash
fg workspace apply ./fgit-data \
  11111111111111111111111111111111 \
  22222222222222222222222222222222 \
  refs/heads/main \
  "$workspace_parent/candidate.bundle" \
  --trusted-local \
  --principal 44444444444444444444444444444444 \
  --idempotency-key 'reviewed-readme-change-1' \
  --expected-base "$REVIEWED_BASE" \
  --expected-commit "$REVIEWED_COMMIT"
```

`REVIEWED_BASE` is the original source commit and `REVIEWED_COMMIT` is the exact
native commit whose contents were reviewed. They are 40 lowercase hexadecimal
characters for SHA-1 or 64 for SHA-256. The persisted repository configuration,
not their spelling alone, decides the admitted object format. The repository
must already exist; this command does not initialize a replacement repository.

The command does not rerun the tool, derive approval from a bundle's own claims,
choose a new parent, resolve a conflict, create a branch implicitly or force an
update. The advertised branch, prerequisite and candidate must match the three
explicit expectations. The verified candidate must be a strict native Git
commit with exactly the expected base as its sole parent. Root commits, merge
commits, tags and blobs are outside this workspace-publication profile.

## What publication uses

The adapter reuses `ReceivePack`, `ProductionQuarantineValidator`, its exact
basis-bound validation witness and the existing durable receive admission
continuation. It does not implement another ref database or publication point.
The prerequisite must belong to authenticated selected history; a matching
object merely staged in the local object fabric is not sufficient. Candidate
pack checksums, native identities, object closure and resource checks run before
admission. Invalid candidate shape is refused before sealing, though verified
objects may already have been staged.

The expected-old ref condition remains in the canonical request and is checked
by admission, rather than only by a preliminary mutable-ref lookup. A competing
update cannot be silently overwritten. A successful head CAS publishes the
ordinary source-control RCR and its terminal decision through the same path as
a push. Refusal is a canonical terminal decision, not a source ref update.

This is ordinary source publication, **not** completion of `frankengit-asa3`:
PR aggregate transitions, durable forge-stream advancement and outbox delivery
remain separate unfinished integration. A workspace candidate is not relabeled
as a forge merge merely because it updates a branch.

## Results, retries and cleanup

A terminal result is emitted as one JSON object of type
`workspace_publication`. It includes `outcome`, `published_to_repository`,
`tx_id`, `decision_sequence`, `repository_commit_id`, `refusal_code`,
`refusal_record_id`, the supplied base/candidate, `reference_hex`, `node_closed`
and `cleanup_error`. Ref names are encoded as hexadecimal raw bytes. Native
commit identity and the internal RCR identity are separate fields and domains.

A committed decision with successful shutdown and receipt output exits zero.
A canonical refusal emits its receipt and exits nonzero. Shutdown or output
failure also exits nonzero but **does not reverse a known committed decision**:
when output is available, the JSON retains the decision and marks failed
cleanup. Diagnostics retain the known decision even when stdout cannot be
written or flushed. Consumers must not interpret every nonzero exit as proof
that nothing committed.

After an uncertain response, retry the **same saved bundle, branch, base,
reviewed commit, principal and idempotency key**. Do not rerun a potentially
nondeterministic tool and do not mint a new key just to recover the old attempt.
The same sealed request resolves to its original terminal outcome. Different
request semantics with a reused key are rejected rather than aliased.

An old successful retry reports the historical success even if a later commit
has moved the branch again. It must not move the branch back. A refused request
also keeps its original refusal; submitting a newly rebased and reviewed
candidate is a new operation, not recovery of that old request.

If no terminal decision is returned, diagnostics preserve that uncertainty.
They do not infer non-commit from missing output, staged objects, cancellation
or an infrastructure error. There is no automatic retry loop in this command.

## Input and support bounds

The command consumes a stable operator-owned regular bundle file, at most
128 MiB. It rejects symlinks/devices and checks the read bound during intake,
including file growth. The operator must prevent concurrent replacement or
mutation of the host input path; this is not an adversarial filesystem adapter.

Accepted envelopes are Git bundle v2 with SHA-1, or v3 with one explicit
supported object-format capability. Exactly one prerequisite and one branch
advertisement are admitted, with a 16 KiB header bound. Unknown capabilities,
filtered/partial-clone envelopes and multiple prerequisites or refs refuse.
The pack is processed under the existing bounded receive profile with a
128 MiB expanded ceiling and the node's per-object ceiling. Candidate commit
parsing is additionally capped at 2 MiB. This is not a general bundle importer.

## Executable verification

```bash
cargo test --locked -p fgit-node --test workspace_publication
cargo test --locked -p fgit-node --lib treefs_workspace::publication::tests
cargo test --locked -p fgit-cli --bin fg workspace_apply::tests
cargo build --locked -p fgit-cli
python3 scripts/e2e/workspace_publication_smoke.py --fg /path/to/built/fg
```

The smoke campaign starts from actual nonempty SHA-1 and SHA-256 repositories,
creates its candidates using the real `workspace run` command, independently
verifies the emitted native object bytes, and applies them using fresh CLI
processes. It checks corrupt input and incorrect review bindings, successful
publication, identical-request recovery, key reuse with changed semantics, a
competing candidate's exact typed refusal, refusal recovery, a real next
descendant, historical refs and replay of the earlier success without rollback.
It reuses the independent pack inspector from `workspace_tool_smoke.py`; neither
script invokes another Git engine or replaces the production authority.

**Implementation-time verification limit:** the Rust build/tests and complete
binary smoke campaign have not been executed in the editing environment, which
has no Rust toolchain. Python syntax and the new smoke helper's invocation and
receipt checks were exercised, including corrupted-receipt negatives. Those
checks do not establish Rust compilation, FrankenSQLite behavior, native E2E
success or independent batch acceptance. The implementation remains unverified
at those boundaries, and no bead is closed by this change.
