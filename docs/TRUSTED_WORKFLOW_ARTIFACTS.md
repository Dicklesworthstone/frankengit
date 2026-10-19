# Retained outputs from trusted workflows

`fg workflow run`, `dispatch`, `run-candidate` and `run-merge-candidate` can
retain explicitly selected output files through the existing immutable
`LocalArtifactStore`.
The runner copies and verifies these files after the job's processes have
settled and before its private TreeFS workspace is closed. A completed report
includes exact artifact IDs that can be inspected or exported after the
workspaces and producing node are gone.

This is the trusted local script execution profile. Review every script and
protect the run parent, artifact root and their ancestors against replacement;
scripts still run with the host user's privileges. Artifact custody provides
verified immutable bytes and bound producing-attempt provenance. It does not
create a BuildInputCapsule, authorize a cache hit, skip execution, transfer files
to dependent jobs, or independently attest that a job succeeded.

## Select the producing workflow, expanded job and file

For a trusted `ci/build.yml` whose `build` job writes `dist/program`:

```sh
# These are operator-supplied paths and the existing node's scope identities.
mkdir -m 700 -- "$RUN_PARENT" "$ARTIFACT_ROOT"
fg workflow run "$NODE" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local --workflow ci/build.yml --input ci --input src \
  --run-parent "$RUN_PARENT" --run-id 95c2b893f2af47cba2f89bdd9ec9e220 \
  --artifact-root "$ARTIFACT_ROOT" \
  --artifact ci/build.yml:build:dist/program
```

The root must already be an absolute, nonsymlink, private directory with mode
`0700`. Each repeated `--artifact` names exactly
`workflow-path:expanded-job-id:relative-output-path`; selectors are not globs.
A matrix expansion uses IDs such as `build__matrix_007`. Jobs must exist in the
compiled selected workflow. Use `--artifact-hex` for raw-byte or colon-containing
paths: its syntax is `workflow-path-hex:job-id:output-path-hex`, with the job ID
still literal. Paths use the same bounded TreeFS path policy as native sources.
They cannot be absolute, contain traversal, or name the workspace ownership
marker.

Select up to 64 distinct files. Each path is at most 4096 bytes; workflow and
output path bytes across all selectors are at most 64 KiB. Defaults are 16 MiB
per file and 64 MiB of raw output payloads per invocation. Configure these with
`--max-artifact-mib 1..64` and `--max-artifact-total-mib 1..512`. Zero-length
regular files are valid. Provenance is bounded separately to 1 MiB per producing
job, with at most 64 selected jobs. These limits bound this collection operation;
an operator-managed filesystem quota is still needed for total retained data.

The same options work with `fg workflow dispatch`. Its exact source head/commit
pins, workflow-directory selection, event matching and input-prefix flags remain
mandatory as described in `TRUSTED_WORKFLOW_CHECK_AUTOMATION.md`. Every artifact
selector must name an event-selected workflow and an expanded job in that graph.
The whole contract is checked before reserving the batch or starting a child.
The total output allowance is shared by every workflow in the dispatch; it is
not reset for each child.

Capture is opt-in: calls without a contract keep their original attempt identity
and result fields. Candidate modes use the same file validation, custody and
job-settlement code, not an alternate artifact store or publication path.

### Retain an unpublished candidate's build output

```sh
fg workflow run-candidate "$NODE" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local --workflow ci/build.yml --input ci --input src \
  --expected-commit "$BASE_COMMIT" --candidate-commit "$CANDIDATE_COMMIT" \
  --bundle "$CANDIDATE_BUNDLE" --run-parent "$RUN_PARENT" --run-id "$RUN_ID" \
  --artifact-root "$ARTIFACT_ROOT" --artifact ci/build.yml:build:dist/program
```

The candidate's workflow and input tree, not the base script, produce these
bytes. The native bundle, exact base and candidate, current ref, optional head
and output contract are checked before an attempt starts. Each output manifest
records `input_kind: "unpublished_candidate"`, actual executed commit/tree and
bundle SHA-256 separately from canonical base head/RCR/commit/tree. Capture
neither imports the candidate objects nor creates a temporary reference.

The same output options work with `fg workflow run-merge-candidate`; its exact
source/target tips, common base, ordered parents and bundle prerequisites remain
mandatory. Provenance records both parents and the actual merged candidate.
All selectors must name the one selected workflow and existing expanded jobs.
See `TRUSTED_CANDIDATE_WORKFLOW_CLI.md` and `TRUSTED_MERGE_WORKFLOW_CLI.md` for
candidate input flags and their trust boundary.

After job cleanup, use the ordinary artifact inspect/export commands below.
Neither the candidate bundle nor the original import directory is needed to
export retained bytes. `fg workflow recover` reads the unchanged attempt marker
and journal, including the output contract, without executing the workflow.
An occupied run ID still refuses execution. Artifact custody and offline
recovery never promote a candidate observation into a canonical green check.

## What is retained

A successful capture adds an `artifact_contract` to the immutable attempt and
an `artifacts` array to the run report. Each array member contains a
`job_id_hex`, a `manifest_id_sha256` and output entries with:

| Field | Meaning |
|---|---|
| `path_hex` | Exact relative path in the producing job's workspace. |
| `artifact_id_sha256` | Immutable identity used for inspect/export. |
| `payload_sha256` | SHA-256 of the raw payload bytes. |
| `payload_bytes` | Exact payload length. |
| `executable` | Whether the captured regular file was executable. |

The immutable provenance manifest binds the full producing attempt identity,
its SHA-256, tenant/repository/incarnation, canonical source head/RCR/commit/tree,
source ref, workflow path/blob, graph and source commitments, run ID, declared
inputs, output contract and exact expanded job. It lists the retained output IDs
and raw digests. The complete algorithm-qualified source RCR is always present
in provenance; the optional payload identity RCR field is populated only when
its digest is compatible with the existing store's SHA-256 profile.

The manifest explicitly records `cache_reuse_authorized: false` and
`job_success_asserted: false`, with no BuildInputCapsule or CheckReceipt ID.
Files may come from a contained job whose command failed, so a manifest alone
does not claim success. The final workflow report and existing durable job
journal own execution outcomes and later explicit check publication.

Each job also leaves a synced, create-only `job-NNN-artifacts.json` receipt in
its attempt directory. That receipt links the full immutable provenance manifest
only after all selected payloads and the manifest itself have been stored and
verified. It precedes the durable successful job observation. Raw staging files
are removed after each verified store operation; ordinary cleanup removes the
workspace even when collection refuses.

## Inspect or export after cleanup

Use the producing run's exact tenant, repository and incarnation, together with
the fixed trust domain `trusted-workflow-local-owner`. Both payload and manifest
IDs use the same store and scope:

```sh
fg artifact inspect "$ARTIFACT_ROOT" "$TENANT_ID" "$REPOSITORY_ID" "$INCARNATION_ID" \
  --trusted-local --trust-domain trusted-workflow-local-owner \
  --id "$ARTIFACT_ID"

fg artifact export "$ARTIFACT_ROOT" "$TENANT_ID" "$REPOSITORY_ID" "$INCARNATION_ID" \
  --trusted-local --trust-domain trusted-workflow-local-owner \
  --id "$ARTIFACT_ID" --output "$EXPORT_PARENT/program"
```

The export parent must already exist with mode `0700`, and its destination must
not exist. Export verifies the whole retained payload before installing the new
file. Export the `manifest_id_sha256` in the same way to read its exact JSON
provenance. The raw file payload stores no executable filesystem mode; consumers
can review the report's executable flag before applying their own permissions.
See `NATIVE_ARTIFACT_COMMANDS.md` and `LOCAL_ARTIFACT_STORAGE.md` for the storage
identity, verification and no-overwrite rules.

Artifacts use the existing `CiArtifact` payload kind; manifests use
`Provenance`. Their retention identity is `HotEphemeral` with 86400-second TTL
metadata. This feature does not automatically delete files or register retention
authority. Repeated exact payload custody verifies an existing immutable object;
it never skips the producing scripts or treats an object name as authorization.

## Failure, cancellation and recovery

Missing outputs, per-file or aggregate overflow, symlinks in any output path
component, hard links, directories and other nonregular files refuse capture.
Reads remain relative to the owned workspace descriptor, validate the ownership
marker and file identity, and poll cancellation between chunks. A poisoned or
truncated retained artifact refuses verified storage; it is never healed by
overwriting the immutable name.

A capture or storage failure makes the job non-successful before its durable
observation is saved. Dependent jobs skip; independent diagnostic jobs may
continue under the normal workflow policy. Cancellation and timeout keep their
non-green outcomes. Output reads never begin when process containment is
uncertain, and workspace settlement remains non-cancellable.

Completed raw payloads or a final receipt can remain if a later operation fails
or the process crashes. They are immutable custody observations, not evidence of
a completed job or permission to replay. A missing report is still unknown
execution progress. Retain the original attempt slot and inspect its receipt,
journal and any external effects with `fg workflow recover`; do not remove it
or change the run ID merely to repeat execution after a lost response.

The complete root, sorted selectors, limits and retention/trust profile are bound
into attempt and dispatch identity. Changing a contract cannot reuse an occupied
run or batch slot. Existing offline journal inspection authenticates the exact
marker bytes, including this contract.

## Implementation and validation

The node embedding API exposes `TrustedWorkflowArtifactConfig` and exact
`TrustedWorkflowArtifactSelection` values through
`run_trusted_workflow_with_artifacts_in` and
`dispatch_trusted_workflows_with_artifacts_in`. Candidate embeddings use
`run_trusted_candidate_workflow_with_artifacts_in` or
`run_trusted_merge_workflow_with_artifacts_in`. Existing entry points delegate
with no contract. `TrustedWorkflowRun.artifacts` and dispatch `runs()` expose
completed custody observations.

Focused tests cover real SHA-1/SHA-256 imports and child processes, binary and
executable outputs exported after workspace cleanup/reopen, exact provenance,
poisoned stored bytes, missing and unsafe files, refusal before successful
journal evidence, source stability, occupied-attempt contract changes, whole-batch
preflight and a shared dispatch byte budget. Runner and workspace tests cover
capture/cancellation/containment ordering and descriptor-relative refusal;
staging tests preserve cleanup responsibility after cancellation.

```sh
cargo test --locked -p fgit-runner --lib workflow::settlement_tests
cargo test --locked -p fgit-runner --test sparse_workspace
cargo test --locked -p fgit-node --lib treefs_workspace::trusted_workflow::artifacts
cargo test --locked -p fgit-node --test trusted_workflow
cargo test --locked -p fgit-cli --bin fg workflow_command::
cargo test --locked -p fgit-node --test candidate_artifact_custody
cargo test --locked -p fgit-cli --test workflow_candidate_artifacts
```

These commands identify the focused checks, not a full-workspace release gate.
The candidate suite executes native SHA-1 and SHA-256 single-parent and merge
inputs, exports payload/provenance after reopen, checks actual changed candidate
scripts, and pairs missing/oversized/mismatched/cancelled cases with permitted
runs. The CLI suite invokes real `fg` processes for capture, retained export,
offline recovery and no-replay checks after original inputs move offline.
Source refs and authority generations must remain unchanged, and the candidate
commit must remain absent from admitted object storage. Run IDs, root paths and
artifact identities in these fixtures are test-local, not service configuration.
Broader BuildInputCapsule-based reuse, remote artifact authorization, canonical
retention management and hostile execution remain separate capabilities.
