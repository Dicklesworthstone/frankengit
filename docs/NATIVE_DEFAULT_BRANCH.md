# Changing the canonical default branch

`fg branch default` reads the exact symbolic HEAD selected by the canonical
repository authority. `fg branch set-default` selects an existing branch through
the normal sealed transaction, RCR and conditional head replacement. No direct
branch tip moves. Clone advertisements, historical ref reads and the existing
default-branch deletion guard consume the resulting canonical HEAD.

## Read, then submit exact expectations

Use the same explicit storage directory, tenant, repository and object format
as the existing node:

```sh
fg branch default ./fgit-data \
  11111111111111111111111111111111 22222222222222222222222222222222 \
  --trusted-local --object-format sha1

fg branch list ./fgit-data \
  11111111111111111111111111111111 22222222222222222222222222222222 \
  --trusted-local --object-format sha1
```

The first command emits a `default_branch` JSON document with the authenticated
`source_head`, `snapshot_token`, `default_reference_hex`, `tip` and `unborn` flag.
A null reference is an absent symbolic target. A non-null reference with a null
tip is a named unborn target. The command never substitutes `main` for either
state. Names are exact hexadecimal bytes, so non-UTF-8 Git ref names round-trip.

Choose the new branch's tip from the independently read branch listing. For
example, when the current target is `refs/heads/main` and `TOPIC_TIP` is the exact
listed commit ID of `refs/heads/topic`:

```sh
fg branch set-default ./fgit-data \
  11111111111111111111111111111111 22222222222222222222222222222222 \
  --trusted-local --object-format sha1 \
  --principal 33333333333333333333333333333333 \
  --idempotency-key choose-topic-1 \
  --expected-default refs/heads/main \
  --ref refs/heads/topic --expected-tip "$TOPIC_TIP"
```

Use `--expected-default-hex` and `--ref-hex` for raw-byte names. Use
`--expect-no-default` only when the read reported a null target; an unborn
`refs/heads/main` still requires that named expectation. SHA-256 repositories
require `--object-format sha256` and a SHA-256 target ID. The destination must
already exist as a visible branch pointing to an admitted native Commit. The
operation does not unset HEAD, create an unborn destination, change a pull
request's base branch or rename a direct ref.

Both expectations are checked against each actual publication basis. A concurrent
HEAD change or target-tip update produces a canonical refusal; the command does
not refresh either value. A same-target command remains valid and receives its
own audited terminal decision after the same authorization and tip checks.

## Administrator authority

This CLI is an explicitly trusted local operator boundary. Supplying a principal
ID is not remote authentication. When no review-protection policy exists, the
local operator may select the default. Once a policy exists, its currently
selected administrators authorize this operation, including when its branch
protection list is empty. Rotate administrators with the existing
[`fg protection set`](MANDATORY_REVIEW_PROTECTION.md) operation.

Canonically declared agents, remote Git credentials and narrowed ref-write
sessions cannot use this path. Administrator status does not disclose hidden
HEAD or branch names. The read also checks caller and canonical visibility of
HEAD and its target before returning either the name or tip.

## Terminal receipts and recovery

A successful `default_branch_publication` document includes the stable `tx_id`,
`repository_commit_id`, decision sequence and original expectations.
`head_changed_by_transaction` describes that historical transaction; it is
false for a committed same-target no-op. `direct_refs_changed` is always false.
A retry's receipt does not claim that the selected branch is still today's
default. Read it again when that current-state fact is needed.

Exit 0 means a completed read or committed command. Exit 3 is a canonical refusal
with a refusal record and code. Exit 2 is an input, infrastructure, output or
cleanup error. If stdout or cleanup fails after publication, the diagnostic
retains the known committed/refused TxId. Delivery acknowledgement remains null;
writing bytes is not proof that the client received them.

After an interruption, retry the identical command with the original scoped key,
or use `fg outcome` for read-only recovery. Do not replace the old target or tip
with values read after the interruption. Exact terminal retries remain available
after administrator rotation, target deletion, later default changes or a new
quota restriction. `--key-stdin` reads 1–256 exact bytes, including any trailing
newline; keys never appear in receipts. A leading global `--timeout-secs` chooses
the finite request deadline. Signal cancellation drains admitted work before
node shutdown, and a timeout alone cannot establish non-commit.

## Canonical evidence and supported layouts

The operation supports the default whole-body ref layout, `RefStateMerkleV2`
and `RefStateAndObjectClosureMerkleV2`, in both native hash formats. Historical
V1 Merkle repositories remain refused for live use; this feature performs no
in-place migration. See [authenticated HEAD](AUTHENTICATED_HEAD_REF_LAYOUT.md).

The HEAD-change body binds the exact sealed request, authenticated basis, layout,
old/new ref roots and selected administrator-policy witness. It serves as the
RCR's actual symbolic-ref delta and invariant evidence. Configuration, policy,
forge, outbox, retention and direct-ref state are preserved, with no new Git
objects admitted. The normative schema and verification obligations are in
[protocol contract §16.6](NORMATIVE_PROTOCOL_CONTRACTS.md#166-canonical-default-branch-changes).

Focused admission tests cover canonical bytes, stale expectations, administrator
and agent restrictions, policy/CAS races, cancellation, staged-body failures and
original-key recovery. Native tests exercise real imported objects, all three
live layouts, advertisements, history, cold reopen and deletion protection.
`scripts/e2e/default_branch_smoke.py --fg /absolute/path/to/fg` drives fresh CLI
processes through SHA-1/whole-body and SHA-256/V2 repositories, including policy
rotation, raw-byte targets and a failed stdout write. The same campaign is wired
into `native_branch_smoke` and the discovered e2e smoke suite. These test
definitions do not by themselves claim that a particular revision passed.
