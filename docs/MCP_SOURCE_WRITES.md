# Native source publication through MCP

`--allow-source-writes` selects source mutations. The trusted-local profile
enables ten narrow, operator-sponsored operations:
`frankengit_branch_create`, `frankengit_branch_update`,
`frankengit_branch_delete`, `frankengit_branch_rename`,
`frankengit_branch_transaction`, `frankengit_source_publish`,
`frankengit_source_publish_rebase`,
`frankengit_tag_create`, `frankengit_tag_annotate`, and `frankengit_tag_delete`.
See [MCP tags](MCP_TAGS.md) for the tag lifecycle and exact outer-object deletion
lease. None launches Git, a shell or a host-file reader.
Every command uses the existing node quarantine/admission/recovery boundary.

```sh
fg-mcp "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local \
  --allow-source-writes --allow-source --allow-pull-writes --allow-pulls \
  --allow-outcomes --principal "$PRINCIPAL" --expected-incarnation "$INCARNATION"
```

All five grants in this example are independent. Source writes alone do not
permit reading code, reading/writing PRs, writing issues, or querying outcomes.
All writes require the exact launch-bound principal and repository incarnation.
The operator explicitly sponsors the stdio client with repository-wide source
write authority. This is NOT remote authentication or a path-scoped Intent Run
broker. Do not forward the channel to an untrusted remote principal.

## Sponsored agent publication

A sponsored launch may also select `--allow-source-writes`. Its closed inventory
contains only `frankengit_source_publish`, with an exact existing branch, base
and single-parent candidate. The canonical credential must independently grant
`source-publish` and carry its bounded ref and changed-path scope. The launch
flag cannot supply or widen that authority. See
[scoped source publication](AGENT_SCOPED_SOURCE_PUBLICATION.md) for the native
grant and admission contract.

```sh
fg-mcp "$STORAGE" "$TENANT" "$REPOSITORY" \
  --agent-token-file "$PRIVATE_TOKEN_FILE" --expected-incarnation "$INCARNATION" \
  --allow-source-writes --allow-source --allow-outcomes
```

The three launch ceilings in this example remain independent. Publication needs
only `--allow-source-writes` and the scoped `source-publish` credential. Add
`--allow-source` with `source-candidates` to prepare and inspect an uploaded
candidate; ordinary source reads need their own canonical grants. Add
`--allow-outcomes` with `outcomes-read` for own-principal durable recovery.
Existing metadata, source-read and candidate grants gain no publication power.
A sponsored launch cannot supply `--principal`; identity and sponsorship come
from its current canonical credential.

The agent schema requires `expected_base` and does not advertise `initial`.
Any presence of that field, including `false` or `null`, refuses before
credential lookup. Initial history, branch creation/update/deletion/rename,
multi-branch transactions, tags and `frankengit_source_publish_rebase` remain
outside the sponsored profile. Candidate output is untrusted handoff data and
never authorizes any of these operations.

The adapter retains the original authenticated request, key and deadline while
the native publisher verifies the complete candidate and current ref/path
scope, then applies ordinary branch protections at the deciding authority
basis. It does not substitute a trusted-local principal or grant Git receive.
All changed paths, including removals, are subject to the native scope check.
A refused canonical decision leaves refs unchanged and is returned as a
terminal mutation refusal; an unknown outcome retains the original retry key.

The source-publication receipt keeps the existing schema below. Its
`principal_id` identifies the authenticated agent, but it does not synthesize
an agent/sponsor witness from the current bearer. Query
`frankengit_transaction_outcome` with the same key and independent outcome
permission to retrieve the original canonical `principal_provenance`. That
historical sponsorship remains the original credential's evidence after
rotation, revocation and reopen. A successful same-key replay is a historical
decision, not a fresh scope, ref-state or replacement-bundle attestation.

## Branch lifecycle

The four lifecycle tools require `reference` and `idempotency_key`. `reference_hex` is the
lossless alternative for non-UTF-8 ref names; exactly one encoding is required.
Refs must be full `refs/heads/...` names, bounded to 1024 bytes. Native OIDs
are nonzero lowercase hex in the repository's SHA-1 or SHA-256 domain.

| Tool | Additional fields and conditions |
|---|---|
| `frankengit_branch_create` | `target`; destination must be absent. |
| `frankengit_branch_update` | `expected_old`, `target`; exact old-tip condition, different target. |
| `frankengit_branch_delete` | `expected_old`; exact old-tip condition. |
| `frankengit_branch_rename` | `expected_old`, and exactly one of `destination` / `destination_hex`; distinct, absent destination. |

Read the exact current tip to pin with `frankengit_ref_list`
([MCP_READ_ONLY_SERVER.md](MCP_READ_ONLY_SERVER.md)) rather than another surface.

Targets must already be identity-verified commits reachable through the native
visible-ref boundary. A guessed OID or object already in local storage confers
no authority. Branch commands do not import new objects. All updates are
non-forced and use native receive admission. Current hidden-ref, protection,
resource and default-branch rules remain mandatory.

Rename submits one atomic transaction: delete the exact old tip AND create the
absent destination at that SAME tip. It cannot overwrite a destination or leave
only half the rename published. A default-branch delete/rename refuses rather
than silently rewriting HEAD. Branch operations do not retarget PR metadata.
Unknown fields, force flags, caller principals and implicit latest-tip selectors
are rejected before native admission.

## Atomic multi-branch transactions

See [MCP branch transactions](MCP_BRANCH_TRANSACTIONS.md) for the bounded
`commands` array and whole-transaction key. It shares the native publication
and recovery path with these tools, but takes its reference operands per command.

## Reviewed single-parent bundle publication

`frankengit_source_publish` requires `reference` / `reference_hex`,
`expected_base`, `expected_candidate`, `idempotency_key`, and
`bundle_hex_chunks`. Base and candidate are independently supplied native commit
IDs, not inferred from an untrusted bundle header. They must differ.

`bundle_hex_chunks` is an ordered array of ONE to THREE nonempty lowercase hex
strings, each at most 16384 characters (8192 decoded bytes). Concatenation is
ONE complete native Git bundle, at most **24 KiB**. Every chunk and the aggregate
size are validated before the complete body allocation. No input limit is
raised: this envelope, one maximum-width ref, ordinary IDs and the retry key
fit the existing 64 KiB JSON frame and 16 KiB per-string decoder limits.
Arbitrary extra client metadata still shares the global frame bound.

Chunk boundaries have no semantics and are not independently stored uploads.
No path, URL, filesystem handle or ambient file is accepted. Larger bundles
must use the existing CLI/HTTP/native interfaces, not silent truncation.

The native workspace-bundle contract requires a Git v2/v3 bundle in the correct
hash format, one advertised branch, one prerequisite equal to the expected base,
and a candidate whose single parent is that base. New requests pass production
quarantine, pack/object identity checks, closure/visibility checks, native commit
validation and the ordinary exact-old ref transaction. Staging objects does
not publish a ref. No canonical source state lives in the MCP process.

This is code publication, not a review approval or coupled PR merge. It cannot
bypass mandatory protection, force a non-fast-forward transition, accept a
multi-parent merge through the source-only path, or create an initial root
commit. Candidate construction, richer bundle intake, approvals and coupled
merge admission retain their separate native interfaces and authority rules.

## Reviewed linear-rebase publication

`frankengit_source_publish_rebase` publishes a complete, independently inspected
native linear-rebase bundle through the existing dedicated rebase owner. It
requires the ordinary source-write grant and launch-bound principal/incarnation.
Source read and outcome recovery remain independent grants. Sponsored-agent
profiles exclude this operator adapter.

| Argument | Required meaning |
|---|---|
| `reference` or `reference_hex` | Exactly one encoding of the SOURCE branch being replaced. |
| `expected_source` | Exact old SOURCE tip; the branch lease. |
| `onto` | Exact commit named by the bundle's sole prerequisite. |
| `expected_candidate` | Exact independently inspected final candidate tip. |
| `bundle_hex_chunks` | Complete bundle under the same three-chunk, 24 KiB envelope above. |
| `idempotency_key` | Original durable key for this publication. |

The old source tip and onto commit have distinct roles. A rebase onto another
branch does not replace the old-source lease with that branch's tip. Native
quarantine verifies the advertised source branch, hash domain, prerequisite,
candidate, closure and a bounded single-parent chain of at most 256 rewritten
commits reaching onto. A zero-commit series may move the source directly to onto,
including with an empty pack; `expected_candidate == onto` is permitted.
The original one-commit workspace publisher retains its own contract.

Obtain and independently inspect the complete artifact using the
[complete MCP rebase workflow](MCP_SOURCE_REBASE.md),
[native rebase workflow](NATIVE_LINEAR_REBASE.md), or
[rebase inspection API](SOURCE_REBASE_INSPECTION_HTTP.md). Preparation and an
inspection report do not grant publication or bypass protection. The mutation
uses ordinary atomic receive admission, current policy, visibility and quota.
It does not set a force flag, manufacture review approval, or rewrite PR metadata.

The result is the same canonical `source_publication` receipt described below,
with `action:"publish_rebase"`, `publication_profile:"linear-rebase-v1"` and one
submitted source-ref command. `submitted_onto` reports the caller's input.
Neither the pack encoding nor onto is added to the native ref transaction's
seal: a terminal retry recovers the historical old-source/new-candidate decision.
It does not validate a new pack or establish replay equivalence. Accordingly,
`bundle_validation_receipt` remains null and `replay_equivalence_verified` is
false. Preserve the exact original publication inputs on retry.

The adapter makes no preliminary current-head read. Original-key recovery
therefore remains available after a successful rebase, later source movement,
or reopening the node. An uncertain native failure does not establish non-commit;
retain the original key and use the normal outcome-recovery workflow.

## Terminal facts and recovery

A returned `source_publication` has ONE transaction ID and canonical terminal
outcome for all submitted ref commands. The adapter checks that an atomic
rename cannot be represented by mismatched or partial command outcomes.
`submitted_commands` records the exact requested lease and proposed new IDs.
`ref_transaction_committed` records the historical decision, while
`current_refs_asserted=false` avoids implying that these remain today's refs.
There is no read-after-write dependency that can erase a known terminal result.

Keep the original key and identical semantic request on retry, using a new
JSON-RPC ID. Historical decisions remain recoverable after later publications,
branch removal or stopped new-write intake. Native recovery binds the scoped
key and semantic transaction, not a mutable MCP cache. A successful historical
retry of bundle publication does not re-attest a newly supplied pack encoding;
`bundle_validation_receipt=null` makes that distinction explicit. Preserve the
original bundle when retrying, or use the independently granted outcome tool.

A canonical refusal is an error with its terminal receipt. Corruption, resource,
quarantine or infrastructure errors are not invented committed/refused outcomes
and do not prove that an earlier attempt failed to commit. Broken stdout stops
before the next request. The existing protocol retains known decisions even
when full result rendering exceeds the response envelope.

## Verification scope

Unit tests cover exact ref leases, atomic same-tip rename construction, both
OID domains, raw ref bytes, forbidden authority/force fields, chunk validation,
maximum framed input, schemas and inconsistent atomic outcomes. Native-node
tests seed actual Git objects and exercise branch creation, bundle publication,
PR opening and code review, stale/corrupt inputs, occupied rename destinations,
default-branch refusal, non-fast-forward refusal, rename/delete/reopen recovery,
independent grants and a lost-stdout reply followed by original-key recovery.

Run `cargo test --locked -p fgit-cli --bin fg-mcp` using the pinned toolchain.
The focused source suite also runs under `--bin fg mcp::`. The transaction
campaign in `MCP_BRANCH_TRANSACTIONS.md` drives real stdio clients through the
new atomic tool. These checks are not a full Git compatibility result, release
gate, or completed broker-backed FG-096 acceptance.
