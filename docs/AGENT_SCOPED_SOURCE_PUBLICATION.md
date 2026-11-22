# Scoped source publication by sponsored agents

A canonical agent credential can independently grant `source-publish`. This
profile advances one existing branch from an exact old commit to an exact
single-parent candidate. The public native API, HTTP candidate Apply operation
and MCP `frankengit_source_publish` tool share ordinary quarantine, transaction
sealing, branch protection and authority-head publication.

Candidate preparation and source publication have separate grants. A host may
give an agent source reading and candidate preparation without permitting a
write. Publishing also requires the host's existing source-write deployment or
launch switch. Granting this operation does not grant Git receive-pack.

## Issue an explicit ref and path ceiling

The trusted-local `fg agent-credential issue` command accepts:

- `--operations source-publish`, independently combinable with source-reading,
  candidate, PR metadata and outcome scopes.
- `--source-ref-scope` with finite native ref selectors: exact names or
  slash-terminated namespace prefixes, encoded as lowercase hex.
- One or more `--source-path-hex` native path prefixes. A component prefix
  `src` includes `src/file` and excludes `src-other/file`. A sole empty path
  explicitly permits the complete tree.

For example, `--source-path-hex 737263` permits the `src` subtree. Both scope
options are mandatory when issuing `source-publish`. The canonical grant root
binds the scope, agent, sponsor, tenant, repository, incarnation and lifetime.
Tokens keep the existing private-file handling and are never publication input.

The target branch must already exist when publishing. An agent can provision
its own task branch with the independent `source-branch-create` grant described
in [sponsored agent credentials](SPONSORED_AGENT_CREDENTIALS.md#create-an-independently-scoped-task-branch),
or an administrator can provision it. A publication grant alone excludes
initial history, branch creation or deletion, forced updates, tags, multi-commit
rebase publication, reviews and merges. An agent can publish a candidate to its
existing branch and open or update a PR using an independent PR metadata grant.

## Native boundary and current authorization

`AgentRequest::source_publication(&node)` returns a borrowed
`SourcePublicationRequest` only for the authenticated operation and exact
repository namespace. `OneNode::apply_agent_workspace_bundle_in` takes this
proof, the original request context, the branch, exact base and candidate OIDs,
and a bounded Git bundle. Identity, sponsor, retry key and lifetime come from
the request rather than caller-supplied publication attribution.

The publisher validates the bundle in private staging. It verifies the
candidate's single parent and compares actual native commit/tree bytes to
construct a complete path-delta witness. Deletions, mode changes, both sides of
renames, directory replacement and gitlinks participate in this comparison.
Caller path lists and rendered patch summaries do not authorize writes.

The ordinary admission projection checks the current canonical credential at
each exact publication basis, including after a lost CAS. It verifies the same
scoped grant root, revocation, incarnation, requested ref and every changed path.
The same decision then evaluates normal branch protection and principal-kind
policy. Required review, checks and queue policy remain mandatory. A policy or
scope refusal creates one stable canonical refusal; it does not publish the
staged candidate objects.

The native publisher retains the actual supplied context and its consumed
resource ledger. One owned Asupersync timer cancels that same context at the
original monotonic request deadline, even during pending authority I/O, and
continues awaiting the same operation to completion. It does not create an
unbounded sibling context, detach a task, discard a pending CAS, or report a
timeout as proof that nothing committed.

## Retry and recovery

Reuse the original key with the identical branch, expected base and candidate.
A terminal result is recovered before new quarantine, mutable grant scope or
current branch freshness can reinterpret the old command. A replacement live
credential for the same agent can therefore recover an old result even when
its scope is narrower. Recovery retains the original immutable agent/sponsor
witness; it does not claim that newly supplied bundle bytes were validated.

A changed semantic command under the same key remains an idempotency conflict.
Transport failure after entering admission may leave the result unknown; use
the normal own-principal transaction outcome lookup. Revocation prevents new
requests and is checked again for already authenticated, undecided publication.

## Relationship to the agent protocol

This path uses canonical sponsored credentials and bounded request ownership.
The ECC-checked trusted-local broker publication flow in `agent_publication.rs`
retains its independent approval, responsibility and reconciliation contracts.
Neither path converts public provenance or a prepared candidate into authority.

Native regression cases cover both Git hash domains, exact ref and path
ceilings, deletion and component-prefix boundaries, independent candidate
scope, generic-publication refusal, revocation after authentication, branch
protection, credential rotation, retained original provenance, restart,
cancelled contexts and deadline cancellation while an awaited phase is pending.
HTTP and MCP adapter regressions additionally exercise their closed operation
classification, host switches, original keys and public publication receipts.
