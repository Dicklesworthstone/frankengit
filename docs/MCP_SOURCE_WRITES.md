# Native source publication through MCP

`--allow-source-writes` enables five narrow, operator-sponsored source mutations:
`frankengit_branch_create`, `frankengit_branch_update`,
`frankengit_branch_delete`, `frankengit_branch_rename`, and
`frankengit_source_publish`. None launches Git, a shell or a host-file reader.
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

## Branch lifecycle

All commands require `reference` and `idempotency_key`. `reference_hex` is the
lossless alternative for non-UTF-8 ref names; exactly one encoding is required.
Refs must be full `refs/heads/...` names, bounded to 4096 bytes. Native OIDs
are nonzero lowercase hex in the repository's SHA-1 or SHA-256 domain.

| Tool | Additional fields and conditions |
|---|---|
| `frankengit_branch_create` | `target`; destination must be absent. |
| `frankengit_branch_update` | `expected_old`, `target`; exact old-tip condition, different target. |
| `frankengit_branch_delete` | `expected_old`; exact old-tip condition. |
| `frankengit_branch_rename` | `expected_old`, and exactly one of `destination` / `destination_hex`; distinct, absent destination. |

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
Rust/Cargo were unavailable in the development session introducing this slice;
tests are written, not executed. This is not an end-to-end live-client campaign,
a full Git compatibility result, or completed broker-backed FG-096 acceptance.
