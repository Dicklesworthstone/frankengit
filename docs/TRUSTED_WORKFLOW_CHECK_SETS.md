# Snapshot-bound publication of saved workflow checks

The native node can prepare and publish all completed jobs in one exact saved
workflow journal snapshot. This is explicitly authorized trusted-local operator
reporting, not a new runner, remote authentication scheme, or repository authority.

`prepare_trusted_workflow_check_set` takes the original attempt-marker digest,
exact journal snapshot, reporting branch, publisher and job/evidence ceilings.
It reuses the private marker and exclusive journal reader. Every selected body is
verified with the existing trusted-job verifier before any canonical submission.
The lock is released after complete preflight, before admission. Queued and
in-progress history is counted but never promoted; a set does not assert that a
run completed, that all possible jobs ran, or that descendants were contained.

The profile permits at most 128 unique completed jobs, 16 MiB total evidence,
1 MiB per check, 1024 retained batches and 8 MiB of batch/ack metadata. These are
hard upper bounds; callers may lower the job and evidence limits. A wrong pin,
invalid scope, foreign execution binding, repeated completed identity, corrupt
body, oversized input or cancellation refuses the entire preparation. No
partially verified set is returned. Appending a journal record requires a new
explicit snapshot selection, including when only an acknowledgement changed.

`publish_trusted_workflow_check_set_in` submits each job through the existing
`admit_trusted_workflow_check_in` boundary. Each observation and its forge outbox
effect publish in one ordinary authority decision. The whole set is NOT atomic.
Per-check keys bind the tenant, repository incarnation, full native check identity
(including publisher/run/attempt/job), and exact reporting branch. The key does
not include current authority, journal pagination, a replacement nonce, or the
evidence body: a changed report cannot evade the existing seal's key-reuse rule.

Results retain every known terminal decision even when cancellation, unavailable
admission or a failing receipt consumer stops later submissions. Retry the same
original snapshot and publisher. Earlier children recover their exact historical
outcomes before current-source checks; undecided children must still pass current
admission. Moving the branch after partial publication therefore cannot erase an
earlier commit or authorize a stale later check. Canonical refusals are also
stable terminal decisions. No journal is acknowledged or rewritten, no execution
is retried, and no code ref is moved by publication.

The manifest and per-check receipts omit raw evidence. Their set digest is a
versioned, length-delimited hash of scope, selectors, child keys and evidence
hashes; it is not authentication. The manifest's `idempotency_key_hex` is the
hexadecimal representation of a binary key, not a textual key to substitute in
an unrelated command. Retain original scope and snapshot pins independently.
Local rollback or malicious same-UID replacement is not covered. The raw node
interface assumes a caller authorized to report as the supplied publisher.

The native `trusted_workflow_check_set` tests exercise actual shell jobs,
verified disk custody, complete preflight, both Git formats, cancellation,
receipt loss, source movement, fresh-node retry, exact decision identity and
unchanged source/custody. These are focused tests, not full-workspace, release,
physical power-loss or hostile-runner isolation claims.

## Native CLI

`fg workflow publish-run` exposes that same node implementation, rather than
parsing a report or running one subprocess per job:

```bash
fg workflow publish-run /node TENANT REPOSITORY refs/heads/topic \
  --trusted-local --run-directory /private/workflow-RUN_ID \
  --journal-id ORIGINAL_ATTEMPT_SHA256 --at-pin BYTES:TAIL_SHA256 \
  --principal-id PUBLISHER --expected-incarnation INCARNATION --plan-only
```

Use the original scope and `snapshot` token returned by `fg workflow recover`.
The required incarnation prevents a restored or replaced repository from silently
becoming a different publication destination. `--object-format sha256` selects a
SHA-256 repository; `--ref-hex` preserves raw reference bytes. `--max-checks` and
`--max-evidence-mib` lower, never widen, the native limits.

Remove `--plan-only` to publish. Optional `--expected-set SET_SHA256` binds the
whole verified set to its previously reviewed manifest. Both paths completely
preflight saved evidence before any check submission. Keep the same original
snapshot, reporting principal and branch on retry. No user-selected replacement
key, force retry, arbitrary fact selector, workflow execution or automatic check
publication is accepted through this command.

Output is newline-delimited JSON: the verified set before any submission, each
canonical terminal decision as it occurs, then a summary after node shutdown.
The summary distinguishes an operation failure from observer/node cleanup.
SIGTERM/SIGINT reach the existing runtime-owned request observer; cancellation
stops later admissions but cannot revoke earlier commits. SIGKILL is abrupt;
retry recovers original canonical outcomes without a local publication cursor.
A lost output stream does not imply that the last submitted check did not commit.

Exit 0 means the requested check observations were committed, or a successful
plan-only/empty selection. It does NOT mean the jobs passed: failures, skipped
jobs and other non-green outcomes retain their evidence conclusions. Exit 3
means at least one canonical refusal; exit 2 means invalid input, incomplete
outcome, output or cleanup failure. A previously manually published check under
an unrelated key can produce `EvidenceStale`, not an invented successful receipt;
use that original manual request to resolve its original outcome.

The discovered `scripts/e2e/suites/workflow/publish_run.sh` campaign drives a real
prebuilt `FG_BIN` with 24 jobs in each hash format. It independently encodes check
IDs, binary child keys and set fingerprints, kills the publisher after receiving
a real committed decision, reopens and completes the same set, and checks the
canonical PR view for exactly the original conclusions. Repeated publication
adds no authority, source movement preserves historical outcomes, and new stale
checks refuse. Corrupt snapshots and bad independent pins cause no admission;
no source checkout or final execution report is required. The campaign creates
only local native test repositories, not GitHub pull requests.
