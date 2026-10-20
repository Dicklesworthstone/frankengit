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
