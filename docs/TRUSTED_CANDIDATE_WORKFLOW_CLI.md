# Run trusted checks before publishing a candidate

`fg workflow run-candidate` connects the ordinary workflow CLI to the
[unpublished candidate execution boundary](TRUSTED_CANDIDATE_WORKFLOW.md).
This is a **Linux trusted local-owner command**, not remote CI or a sandbox.
Review the candidate's workflow and every script it invokes: the candidate can
change those scripts, and they run with your host-user privileges.

## Invocation

Given an independently inspected single-parent candidate bundle, an existing
node, and a private existing `0700` run directory:

```sh
fg workflow run-candidate "$NODE" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local \
  --expected-commit "$BASE_COMMIT" \
  --candidate-commit "$CANDIDATE_COMMIT" \
  --bundle candidate.bundle \
  --workflow ci/local.yml \
  --input ci --input src \
  --run-parent "$RUN_PARENT" \
  --run-id 725f2b60ad8046f4a97bca856074b11c
```

Use a fresh nonzero 32-lowercase-hex run ID for a deliberately new attempt.
Never choose another ID merely to bypass an uncertain earlier execution.
The bundle must contain the named candidate, advertise the named branch, and
use exactly the named base as its prerequisite and sole commit parent.
`--expected-commit` is mandatory and names the canonical base, **not** the
candidate. A supplied `--expected-head` additionally pins the authority snapshot;
`--expected-incarnation` rejects a different repository incarnation.

All ordinary workflow input controls still apply. `--object-format sha256`
selects a SHA-256 node (SHA-1 is the default). Native IDs must have the exact
selected width and use lowercase hex. `--ref-hex`, `--workflow-hex`, and
`--input-hex` retain byte-exact repository names. Input prefixes are distinct
top-level names and must include the workflow path. They select copied inputs,
not host access restrictions.

`--bundle` is a stable local regular file, bounded at 128 MiB; symlinks, devices,
empty files and oversized files refuse. Intake completes before opening the
node. Native pack and closure validation, source freshness, workflow compilation
and host-plan preflight still precede any attempt directory or process.
Ordinary `workflow run` rejects candidate-only flags rather than silently
switching execution modes. Non-Linux hosts retain explicit unsupported execution.

## Results and recovery

Stdout is one JSON `workflow_result` after explicit node shutdown. Its nested
`run` is the same report saved locally. For candidate execution, inspect:

```text
run.source_commit                canonical base
run.source_rcr                   canonical base's repository record
run.executed_commit              actually executed candidate
run.executed_tree                actually executed candidate tree
run.candidate.bundle_sha256       exact submitted bundle checksum
run.workflow_blob                actual workflow blob from candidate inputs
run.input_kind                   unpublished_candidate
run.candidate.admitted            false
run.authoritative_check           false
run.published                     false
```

The native candidate/tree and exact bundle checksum also appear in the synced
`attempt.json` written before processes start. Each job receives fresh copied
inputs; steps within one job share its workspace. The workflow can be tested
without importing its candidate objects or advancing repository authority.

Exit `0` means all jobs succeeded and cleanup completed; `1` means a completed
non-green execution report; `2` means input, infrastructure, receipt-output or
node-cleanup failure. An exit code or local report is not canonical check evidence,
a signed attestation, or authority to publish. Publishing the exact inspected
candidate still requires the separate native admission operation and its current
policy and expected-old checks. No check-to-merge promotion is added here.

An occupied `workflow-<run-id>` directory refuses, including after restart.
A broken output stream does not erase the saved report. Missing `report.json`,
interruption, or shutdown failure does not prove that no command ran; inspect the
attempt and reconcile external effects before another execution. Unproved
containment retains the workspace and prevents later jobs from starting.

## Regression targets

The CLI `workflow_command` parser tests cover mandatory trust, independent base
and candidate coordinates, missing/duplicate fields, hash domains and refusal of
candidate flags in canonical mode. `fgit-cli --test workflow_candidate` invokes
the actual binary with native SHA-1/SHA-256 candidate bundles, verifying receipt
binding, unchanged authority/object storage, restart/replay refusal, corrupt
input refusal, and the distinction between a failed job and an input failure.
Node and host-adapter targets are listed in the execution contract.

These tests were authored but not executed in the implementation environment.
Compilation, formatting, Clippy and repository gates remain unverified. This
profile does not support merge/rebase series execution, hostile isolation,
secret injection, automatic triggers, or authoritative check publication.
