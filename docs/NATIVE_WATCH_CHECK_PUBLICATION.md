# Native watcher: execution to canonical checks

`fg workflow watch` remains execution-only by default. A trusted local operator
can explicitly connect its durable ref-event runs to ordinary check admission:

```bash
fg --timeout-secs 300 workflow watch NODE TENANT REPOSITORY refs/heads/main \
  --trusted-local --workflow ci --input ci --run-parent /private/runs \
  --publish-checks --principal-id PUBLISHER --expected-incarnation INCARNATION \
  --polls 100 --interval-ms 1000
```

Use `--object-format sha256` for a SHA-256 repository. Explicit artifact capture
and producer-to-consumer inputs retain the normal dispatch flags and budgets.
The operator supplies the publisher identity and pins the repository incarnation;
repository text cannot choose an actor, mint authority, or opt itself into checks.
This whole-repository trusted-local profile does not authenticate remote callers
or isolate hostile scripts from host-user privileges.

## Durable handoff, not another execution engine

Before a newly dispatched ref event receives its `settled` marker, the node
writes and syncs `check-sources`. The `FGWCS001` frame binds the watch scope,
canonical event identity, actual native commit, and every actual child run's
original attempt-marker digest and exact check-journal snapshot. It has fixed
widths, a SHA-256 checksum, at most 32 children and a 4096-byte read ceiling.
No caller-controlled path or report JSON is interpreted as a source of authority.

`publish_trusted_ref_workflow_checks_in` holds the same scope-owner lock as the
native poller. It prepares all child check sets of one event before that event's
first canonical submission. The shared envelope is 128 jobs and 16 MiB evidence;
all existing journal, provenance, native-format and individual evidence checks
still apply. Events are processed in deterministic custody-name order, not as an
all-events chronological queue. Earlier events may have terminal decisions when
a later event refuses; known decisions remain observable.

Publication uses `prepare_trusted_workflow_check_set` and
`publish_trusted_workflow_check_set_in`, not synthetic check events. Consequently
ordinary authority, idempotency, source-tip freshness, hidden-ref and policy
checks remain the decision makers. Each job is a normal canonical transaction;
the whole workflow/event is not one atomic transaction.

A private creation-only `publisher` record binds the reporting identity to this
watch scope. Changing `--principal-id` cannot produce replacement keys on restart.
A private creation-only per-event `reported` record is written only after every
selected check has an observed canonical terminal decision. It suppresses future
submissions, not execution policy, and cannot manufacture a green check. A
canonical refusal is terminal too and remains visible in its decision receipt.

## Interrupted publication and source movement

The opt-in CLI drains pending reporting before each new native poll, and reports
newly settled work after that poll. Missing or corrupt handoffs, unresolved
execution, or incomplete admission stop the loop before later work. A broken
receipt stream also stops admission; completed decisions are not rolled back.
Restart the same watcher, publisher, incarnation and custody namespace to resolve
its original child keys. Never rerun scripts or invent replacement run IDs merely
to recover lost check receipts.

If a branch moved after a partial publication, already-decided child keys resolve
their historical decisions. Still-undecided stale checks are ordinarily refused.
Once all decisions are terminal the watcher may select the new ref event; an
unresolved outcome is not promoted to a terminal refusal. Acknowledgement never
changes a source ref or merges a pull request.

Each emitted `workflow_check_set` is a verified plan; each
`workflow_check_set_decision` is a real historical canonical outcome.
`workflow_watch_publication` summarizes observed commits/refusals and local
suppression. The final `workflow_watch_result` includes opt-in state and counts
of observed canonical check decisions. Retried historical decisions can appear
again; these counts are not counts of new writes. An exit of zero means the
requested lifecycle completed, not that previously settled builds passed. Consult
the check conclusions: committed failure or action-required evidence is not green.

## Retention and compatibility boundary

Existing events without `check-sources` are not automatically reconstructed from
reports or rerun. Auto reporting refuses them; the existing explicit
`workflow recover` / `workflow publish-run` path remains available for independently
pinned saved evidence. No force-retry, pruning, publisher reset or guessed migration
is added. Retain the complete private watch and child-run directories across
backup/restore. Deletion, rollback or a new explicit namespace defeats local
suppression. Checksums detect corruption, not malicious owner rewriting.

This feature does not complete hosted CI, hostile runner isolation, universal
process containment, signed independent evidence, all-events queuing, atomic
whole-event publication or exactly-once arbitrary external effects. A crash before
handoff/settlement can deliberately leave execution unresolved. Full-workspace,
release and physical power-loss verification are separate gates.

## Native coverage

`trusted_ref_workflow` pairs real canonical publication with restart, publisher
substitution, corrupt/legacy handoff, journal pin and source-movement refusals.
The framing unit test rejects every truncation and single-byte corruption of its
valid SHA-1/SHA-256 examples.

`scripts/e2e/suites/workflow/watch_publication.sh` drives a prebuilt `FG_BIN`:
24 jobs in two workflows for each hash format, failed/skipped conclusions,
all-child preflight, lost output, a real SIGKILL after an admitted check, original
transaction recovery, canonical PR check reads, no duplicate scripts/checks,
new ref events, and zero matched workflows. This is native functional evidence,
not a mock backend or a pinned upstream Git differential campaign.
