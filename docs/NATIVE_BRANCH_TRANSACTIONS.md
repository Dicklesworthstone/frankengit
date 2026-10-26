# Atomic native branch transactions

`fg branch transaction` publishes up to 4,096 distinct branch changes through one
ordinary atomic receive admission, one sealed request and one authority-head
publication. It does not loop over separate branch commands. This extends the
native branch bootstrap surface for coordinated branch creation, advancement
and removal; it is not multi-repository publication or a new authority model.

```sh
fg branch transaction ./fgit-data "$TENANT" "$REPOSITORY" \
  --trusted-local --principal "$PRINCIPAL" --idempotency-key release-branches-1 \
  --update refs/heads/release "$OLD_RELEASE" "$NEW_COMMIT" \
  --create refs/heads/release-copy "$NEW_COMMIT" \
  --delete refs/heads/obsolete "$OLD_OBSOLETE"
```

Every referenced new tip must already be a verified, visible native commit.
Creation requires absence; update and deletion require an exact nonzero old
OID. Updates must fast-forward. Existing default-branch, hidden-reference,
mandatory review and required-check protection remain in the shared admission
path. A stale, conflicting, protected or otherwise refused member cannot leave
another member published. A canonical refusal may advance the decision stream,
but not the selected reference state. No force or unspecified-old option exists.

The node API is `OneNode::admit_branch_transaction_durable_in`; its public
`MAX_BRANCH_TRANSACTION_COMMANDS` is 4,096, matching the canonical authority
request bound. The existing single-branch and
exact-rename API retains its original validation and request identities.
The ordinary `branch create`, `update`, `delete` and `rename` commands keep their
existing semantics. This command does not upload objects, rewrite pull-request
metadata, change the default branch, or add remote authentication.

## Exact input and recovery

The operation operands are `--create REF NEW`, `--update REF OLD NEW`, and
`--delete REF OLD`, repeated in the same invocation. `--create-hex`,
`--update-hex`, and `--delete-hex` take lowercase hex reference bytes instead of
text; non-UTF-8 names are preserved exactly. Every name is a full `refs/heads/`
reference, not a short branch name. `--object-format sha256` selects SHA-256;
the default is SHA-1. OIDs are nonzero lowercase hex in that exact hash domain.
Duplicate target references refuse, even when one spelling uses hex encoding.

The parser admits at most 16,400 arguments, 8,192 bytes per argument, 1 MiB of
argument text and 4,096 bytes per reference; the node also enforces command,
object, wire, ancestry and inherited request limits. These are refusal bounds,
not performance or whole-operation memory guarantees. Long branch names may
hit the wire envelope before the 4,096-command ceiling.

Keys are explicitly supplied with `--idempotency-key` or byte-exact
`--key-stdin`, never both. They are bounded to 256 bytes, and trailing newline
bytes are significant. No transaction manifest is read from stdin.

Commands are canonicalized in the native request. Reordering distinct commands
with the same principal, repository and exact key recovers the same transaction
and terminal decision. Reusing that key for different semantics refuses. The
receipt retains the caller's command order; compare its transaction and RCR
identities, not array order, for reordered retries. Recovery precedes current
object availability and quota checks. `fg outcome` remains the read-only
recovery surface. An infrastructure failure after admission does not prove
non-commit: retry the identical request/key or resolve its existing outcome.

## Output and evidence boundaries

A `branch_publication` receipt has `action:"transaction"`, `atomic:true`, all
commands, one transaction ID and one terminal decision. Exit 0 is committed,
3 is a canonical refusal, and 2 is invalid input/infrastructure/cleanup failure.
The explicit trusted-local principal is an operator assertion, not remote IAM.

Native tests exercise both Git domains, mixed three-command publication,
reordered and restarted retries, stale-tip refusal, default-branch/non-commit/
non-fast-forward guards, mandatory review protection, pre-cancellation, quota
and the 4,096-command permitted/4,097-command refusal boundary. The real-process
campaign in `scripts/e2e/branch_transaction_smoke.py` uses independently encoded
native objects and an empty executable PATH for each `fg` process. It checks
atomic state, one decision, exact private-key recovery, raw reference bytes and
retries after the original import source moves offline. Its Rust launcher is
`native_atomic_branch_transaction_cli_in_both_hash_formats` in
`crates/fgit-cli/tests/native_branch_smoke.rs`.

This is not a concurrency proof, full Git compatibility claim, hostile-filesystem
containment guarantee or completion of the broader team-day/identity work.
