# Publish a saved workflow observation

`fg workflow publish` connects a completed trusted-local job to the canonical
workflow checks shown on pull requests. It reads the original private run
journal, verifies one selected job and its evidence, and submits the observation
through the repository's existing sealed transaction and authority-head CAS.
Both native SHA-1 and SHA-256 repositories are supported.

The command requires explicit local-owner trust and an explicit reporting
principal. A successful local job is published as **`action_required`**. Failed,
cancelled and timed-out jobs retain those conclusions. Publication does not
establish an independently verified passing check or grant merge permission.

## Select a completed job from the saved run

Run a reviewed workflow with `fg workflow run`, `run-candidate`, or
`run-merge-candidate` and retain its private run directory and the original
`attempt.json` SHA-256. Recover the saved history:

```sh
fg workflow recover "$RUN_DIRECTORY" "$TENANT_ID" "$REPOSITORY_ID" \
  --journal-id "$ORIGINAL_MARKER_SHA256"
```

Choose an entry's `batch_sha256` and the **zero-based position** of the desired
completed job in that entry's `facts` array. The fact must have referenced
evidence. Queued or in-progress facts cannot be published. The optional
`--minimum-pin` can retain the recovered history's `snapshot` as a required
journal prefix; later valid appends are allowed. Continue history pagination
with the exact snapshot and batch cursor when `next_after` is present.

The original marker digest must be retained from the trusted run. Computing a
fresh digest from already untrusted storage does not authenticate its producer.
The existing run directory must be absolute, nonsymlink and private (0700), with
its original private marker and journal. A missing final `report.json` does not
prevent recovery of an already completed job or prove the entire run completed.

## Publish one exact observation

```sh
fg workflow publish "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/topic \
  --trusted-local --principal-id "$PRINCIPAL_ID" \
  --idempotency-key "$PUBLICATION_KEY" \
  --run-directory "$RUN_DIRECTORY" \
  --journal-id "$ORIGINAL_MARKER_SHA256" \
  --batch "$BATCH_SHA256" --fact-index "$FACT_INDEX" \
  --minimum-pin "$SAVED_JOURNAL_PIN" \
  --object-format sha1
```

Use `--object-format sha256` for a SHA-256 repository. `--ref-hex` interprets
the positional reporting reference as hex-encoded bytes. Supply
`--expected-incarnation` when the operation must bind a previously retained
repository incarnation. `--timeout-ms` accepts 1 through 60000, default 30000,
for cooperative saved-run intake before admission. Canonical admission retains
the node's own request budgets. Filesystem syscalls and receipt output do not
have a hard latency bound.

The reporting branch must currently be visible and name the exact commit that
the selected evidence says was executed. It may be another branch at that same
commit. A run against an unpublished candidate becomes publishable only after
that exact candidate is independently admitted and the reporting branch names
it. Running a candidate does not import it or move a branch.

The saved batch, selected fact, referenced evidence, tenant, repository, native
hash domain, run, attempt, job, graph and original execution limits are checked.
Evidence is bounded to 1 MiB before it is loaded for canonical publication;
larger local observations refuse without truncation. The journal remains locked
during recovery and is released before repository admission.

Each command publishes one job. Choose a distinct idempotency key for a distinct
job publication. Multiple jobs are separate canonical transactions; a completed
publication is retained even if a later job's publication fails.

## Read the result and retain its receipt

The JSON publication response identifies the transaction, terminal decision,
check, reporting principal, exact source commit and job. It summarizes evidence
by SHA-256 and byte length. Raw job output is not printed. A committed response
means the observation and its forge delivery obligation became canonical
together. It does not mean delivery has been acknowledged or the job passed.

Read a PR whose recorded source reference and commit match the observation:

```sh
fg pr checks "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" "$PR_NUMBER" \
  --trusted-local --object-format sha1
```

The same result is available through the existing HTTP, MCP and browser
[PR check reads](PULL_REQUEST_WORKFLOW_CHECKS.md). If the branch has moved since
the PR's recorded source tip, current reads suppress stale checks. Refreshing PR
metadata to a new tip includes only observations for that exact new tip.

Keep the original publication arguments and canonical terminal receipt. If the
response is lost or shutdown/output fails after publication, retry the **same
principal, idempotency key, reporting reference, saved batch and fact**. The
existing terminal decision is resolved before new source-freshness admission,
including after a later branch move. Changing the key or the submitted
observation is a new request and cannot overwrite an existing immutable check.
An error alone is not proof that no transaction committed.

Publishing never reruns a workflow, marks a journal batch delivered, consumes
saved custody, acknowledges the forge outbox, or fabricates a runner signature.
Automatic push/PR scheduling and independently trusted passing checks remain
separate integration work.

## Verification

The focused integration test launches the actual Cargo-built `fg` binary in
fresh processes and exercises the run, recovery, publication and PR-read path.

```sh
cargo test --locked -p fgit-node --lib saved_check_record
cargo test --locked -p fgit-cli --bin fg workflow_command::publish::tests
cargo test --locked -p fgit-cli --test workflow_publication
```

These are test commands, not a claim that a particular revision has passed.
The workflow-observation GitHub Actions job runs them for publication changes.
