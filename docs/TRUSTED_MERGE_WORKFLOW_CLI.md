# CLI: check an unpublished merge result

`fg workflow run-merge-candidate` connects the existing trusted local workflow
command to [native two-parent candidate execution](TRUSTED_MERGE_WORKFLOW.md).
The older `run` and `run-candidate` modes retain their existing contracts.

## Invocation

```sh
fg workflow run-merge-candidate "$NODE" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local \
  --expected-commit "$TARGET_BEFORE" \
  --source-ref refs/heads/topic \
  --expected-source "$SOURCE_TIP" \
  --merge-base "$COMMON_BASE" \
  --candidate-commit "$MERGE_COMMIT" \
  --bundle merge.bundle \
  --workflow ci/local.yml \
  --input ci --input src \
  --run-parent "$RUN_PARENT" \
  --run-id 36f83bc790a54deda07011d55f9b23fa
```

`RUN_PARENT` must already exist as an absolute private `0700` directory. The
bundle must be a stable local regular file, at most 128 MiB. These host paths
are explicit trusted-operator inputs, not paths provided by repository text.
The workflow file must be inside the declared input prefixes and use the
existing supported workflow subset with `runs-on: fgit-trusted-local`.

Review and trust the candidate's actual scripts before passing
`--trusted-local`. They run with host-user privileges. Source selection and
fresh per-job copies are not hostile-code isolation, network isolation, or a
secret sandbox. No remote execution listener is added.

The target-before, source tip, common base and candidate are independent
native OIDs. The node verifies the actual bundle against these expectations.
Both refs must still select their expected tips at the same authenticated
snapshot. A source-only check, final-tree reconstruction, preparation receipt,
or stale expectation does not stand in for the actual merge artifact.

`--object-format sha256` selects SHA-256 instead of the SHA-1 default. Native
OIDs are exact lowercase hexadecimal in that domain. `--expected-head` and
`--expected-incarnation` retain the ordinary workflow command's snapshot and
repository-incarnation checks. The positional target supports `--ref-hex`;
`--source-ref-hex` replaces `--source-ref` for byte-exact source refs.
`--workflow-hex` and repeated `--input-hex` preserve byte paths.

All four merge selectors are explicit. There is no default incoming branch,
implicit merge base, force flag, ambient principal or automatic mode switch.
Canonical and single-parent modes reject merge-only fields. Option values are
consumed with their options, so data spelling `--source-ref` cannot silently
replace the actual source selector.

## Result and recovery

The command reuses the ordinary bundle reader, node opening/shutdown and JSON
result writer. Standard output is one `workflow_result` after explicit node
shutdown. Exact script output and repository paths use hexadecimal encoding.
The embedded run distinguishes canonical target provenance from the executed
candidate and records a `merge` object with both branch refs/tips, common base,
candidate and ordered parents.

Exit statuses remain 0 for successful jobs and complete cleanup, 1 for a
completed non-green execution report, and 2 for input, infrastructure, receipt
output or node-shutdown failure. A failed check still has a saved report; an
infrastructure error is not evidence that no process ran.

The synced attempt marker precedes all processes, and report installation does
not replace an earlier result. Occupied run IDs refuse after restart. Reconcile
an interrupted attempt's effects and descendants before considering any new
execution; do not remove its slot to bypass the no-replay rule. Workspaces with
uncertain containment remain retained, and later jobs do not start.

Execution stages no candidate objects, creates no temporary ref, and changes
no canonical source or forge state. These observations do not attest PR
version, reviewer independence, hostile isolation or an authoritative green
check. Any later publication uses the existing separate merge admission path
with fresh policy/PR/source checks and its own idempotency key.

## Verification targets

```sh
cargo test -p fgit-cli --bin fg workflow_command
cargo test -p fgit-cli --test workflow_merge
cargo test -p fgit-node --test trusted_merge_workflow
cargo test -p fgit-runner --test merge_candidate_workspace
```

The CLI scenarios spawn the actual `fg` binary against real imported nodes and
native merge bundles. They cover both hash formats, byte-encoded source refs,
exact result binding, unchanged refs/fabric, restart/no replay, explicit trust,
stale incoming tips, corruption and a persisted non-green report. The node's
custom-pack tests are factored separately from its shared import fixture, so
the CLI introduces no new dependency just to reuse that fixture.

These tests were authored but not executed in the implementation environment.
Compilation, formatting, Clippy and repository verification gates are unverified.
