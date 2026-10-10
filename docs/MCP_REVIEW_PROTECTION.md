# MCP required-review protection administration

The separate `--protection-admin` profile lets a trusted repository operator
inspect, replace and recover canonical required-review protection over the
existing MCP stdio server. It calls the same native authority reader and durable
admission used by `fg protection`. The existing code-agent profile gains no
policy-administration capability, and no canonical schema or dependency changes.

This is a bounded part of `frankengit-root-doctrine-x2mv.4.20` and the explicit
operator-principal boundary in `.4.13`. It does not complete either bead.

## Launch and independent grants

```sh
fg mcp --protection-admin "$STORAGE" "$TENANT" "$REPOSITORY" \
  --trusted-local --expected-incarnation "$INCARNATION" \
  --principal "$ADMIN" --allow-read --allow-write --allow-outcomes
```

`fg-mcp --protection-admin` accepts the same arguments. The repository must
already exist; its incarnation is always pinned. Use `--object-format sha256`
for a SHA-256 repository. `--max-messages` retains the existing 1–100,000 bound
and defaults to 1,024.

| Launch grant | Exposed tool | Principal required |
|---|---|---|
| `--allow-read` | `frankengit_protection_show` | No |
| `--allow-write` | `frankengit_protection_set` | Yes |
| `--allow-outcomes` | `frankengit_transaction_outcome` | Yes |

At least one grant is required. All three grants are independent: a write-only
process cannot inspect the current policy or recover outcomes; an outcome-only
process cannot change or inspect the policy. A principal is accepted only with
a write or outcome grant. Unknown grants, duplicate flags and a mismatched
repository incarnation refuse before a usable session is opened.

The operator authorizes local access and supplies the principal at process
launch. The principal ID is not a remote credential. Do not proxy this process
to untrusted clients. Tool arguments, repository text, client capabilities and
new administrator lists cannot choose a principal or widen launch grants.
Mutation receipts identify this boundary as
`authority_profile: "operator_authorized_local"` and
`principal_source: "operator_asserted_at_launch"`; the canonical event records
the launch principal as its actor.

## Read the exact policy

`frankengit_protection_show` retains its existing optional `expected_head`
snapshot-token argument. It returns the complete policy, singleton version,
policy epoch and authority head. An absent policy differs from an installed
policy with an empty branch list. An explicit head pin that has moved refuses
without selecting a newer head.

Reading requires its own `--allow-read`; replacement does not perform a hidden
read to fill missing expected values.

## Replace the complete policy

`frankengit_protection_set` requires all five fields:

```json
{
  "idempotency_key": "install-protection-1",
  "expected_version": "0",
  "expected_epoch": "1",
  "administrators": ["11111111111111111111111111111111"],
  "branches": [
    {
      "reference_hex": "726566732f68656164732f6d61696e",
      "required_reviewers": ["22222222222222222222222222222222"]
    }
  ]
}
```

The example branch is `refs/heads/main`. The example version and epoch apply
only to an initial policy at epoch one. The installing process must use the
example administrator as its launch principal, or supply the actual selected
principal in the policy.

Versions and epochs are exact canonical unsigned decimal strings. Version
`"0"` requests first installation; later replacements require the exact
positive predecessor version. Epochs must be positive. Exhausted values,
numeric JSON values, leading zeros, omitted predecessors and implicit “latest”
selectors refuse before admission.

Principal IDs are canonical 32-character lowercase hexadecimal strings. Both
administrator and reviewer lists must be strictly sorted, unique and nonempty.
The policy accepts at most 32 administrators, 64 exact branches and 32 reviewers
per branch. Branches are strictly sorted by raw reference bytes and must name
`refs/heads/*`; the `reference_hex` encoding preserves non-UTF-8 names and uses
the native 1,024-byte reference limit. The adapter rejects duplicate entries
instead of deduplicating or reordering a changed retry.

The existing MCP envelope limits also apply: 64 KiB per input, bounded JSON
depth, item count and node count. A policy whose complete representation exceeds
those limits must be managed through another admitted surface. Individual
native collection limits do not waive the transport budget.

An explicit empty `branches` array disables required reviews while retaining
administrator ownership and immutable history. Omitting `branches` never
disables protection. Every listed reviewer remains mandatory; this surface adds
no quorum, wildcard, required-check or override semantics.

First installation is authorized by the explicit trusted-operator write grant;
the installing principal must be in the first administrator set. For every
subsequent replacement, disabling or ownership rotation, the **current
canonical administrator set** authorizes the actor at the exact publication
basis. Adding oneself to the proposed administrator list confers no authority.

## Publication, retries and recovery

The adapter passes the complete `ProtectionCommand` and original client key to
`OneNode::admit_review_protection_durable_in`. Native admission owns the stable
transaction seal, exact version and epoch validation, current-administrator
authorization, forge event, outbox and repository-head CAS. No Git refs move.

Use a new JSON-RPC request ID but the **same durable key and identical complete
command** for a retry. The key is 1–256 printable ASCII bytes without spaces.
Never refresh the version, epoch, administrator list or branch requirements
while retrying an uncertain request. Changed semantics under an existing key
cannot become a second accepted command.

A successful response is a historical terminal fact, with transaction ID,
decision sequence, RCR or refusal identity, expected version and epoch, and
the requested policy. `resulting_version` and `resulting_policy_epoch` describe
that committed command and are null for a refusal. The response performs no
follow-up current-policy read: a later policy change, including removal of the
original administrator, cannot invalidate an already committed command's retry.
`delivery_acknowledged: null` makes no claim of downstream delivery.

Canonical refusals retain their terminal fields and set MCP `isError: true`.
After entering admission, infrastructure failures retain
`outcome_unknown: true`; they do not fabricate a terminal refusal or prove
rollback. With an independent outcome grant, query
`frankengit_transaction_outcome` using the original `idempotency_key`. Recovery
is read-only and scoped to the launch principal's original key binding. An
unobserved key is not proof of non-commit. Recovery never submits the requested
policy or updates its expected values.

The existing serial MCP protocol continues to own initialization, request IDs,
bounded input/output, notifications and cancellation. Notifications never
execute a tool. Late cancellation cannot undo a canonical decision. EOF,
message-budget completion and output failure end the session through explicit
node shutdown. Existing terminal retries and outcome reads remain available
before new-publication intake checks; a fresh mutation still hits the native
intake gate.

## Verification scope

Parser tests in `mcp/backend/protection/write_tests.rs` exercise canonical
policy input, forbidden identity selectors, malformed fields, resource bounds
and permitted boundary twins. The persisted-node tests in
`mcp/backend/protection/integration_tests.rs` exercise SHA-1 and SHA-256 policy
installation, current-administrator ownership rotation, unauthorized replacement,
disabling, exact retries, stale predecessors, changed-key ambiguity, independent
grants, restart and principal-scoped recovery. The protocol tests check mutation
annotations, notifications, malformed keys, and stopped-intake ambiguity.

`crates/fgit-cli/tests/mcp_protection_admin.rs` drives the built `fg` process
over stdio, then opens its persisted node to check that a duplicate request
produced one policy version and that a fresh outcome-only process recovered the
same transaction without changing the authority head. These test definitions
are not a claim of a completed batch gate or of the full PR-workflow bead.
