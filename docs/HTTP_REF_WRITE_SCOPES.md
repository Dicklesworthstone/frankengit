# HTTP credential ceilings for code-reference writes

The loopback HTTP credential profile can restrict a token to named references or
slash-delimited reference namespaces. The selected credential carries the ceiling
through Git receive-pack and every HTTP endpoint that publishes code references.
Ordinary repository policy, exact-old leases, candidate validation, and service
permissions still apply.

This is an operator-owned deployment feature. It does not define canonical agent
identity, sponsor/delegation chains, account membership, or IntentRun authority.
It does not change the repository authority format or transaction identity.

## Credential file format

Existing `frankengit-http-credentials-v1` files and static-token configurations
retain their existing unrestricted reference ceiling. To opt into explicit
ceilings, use this versioned format:

```text
frankengit-http-credentials-v2 <tenant-id> <repository-id> <incarnation-id>
<sha256-of-ASCII-token> <principal-id> <service-scopes> <ref-write-ceiling>
```

Generate the incarnation-bound header with `fg serve-http ...
--print-credentials-header`, then replace the header's `credentials-v1` marker
with `credentials-v2`. The identifiers stay unchanged. Every v2 row requires
exactly four single-space-delimited fields. A v1 row still requires exactly three;
adding selectors to a v1 file fails validation.

Tokens, digest calculation, private regular-file requirements, service-scope
ordering, and repository-incarnation binding are unchanged. See
[HTTP_ISSUE_API.md](HTTP_ISSUE_API.md) for the credential-file deployment profile.
Store the hash of the token's 64 lowercase hexadecimal ASCII characters, not the
hash of its decoded bytes. Neither the token nor the grant belongs in repository
content.

The last field is exactly one of:

| Value | Write ceiling |
|---|---|
| `all` | All references permitted by ordinary admission and the other grants. |
| `none` | No code-reference writes. Read and metadata services remain independently grantable. |
| `exact:<hex>` | One complete reference, encoded as lowercase hexadecimal native bytes. |
| `prefix:<hex>` | Descendants of one complete, slash-terminated namespace, encoded as lowercase hexadecimal native bytes. |
| Comma-separated `exact:` / `prefix:` entries | The finite union of those selections. |

For example, this field grants descendants of `refs/heads/agent/` and the exact
reference `refs/tags/agent-release`:

```text
prefix:726566732f68656164732f6167656e742f,exact:726566732f746167732f6167656e742d72656c65617365
```

The prefix permits `refs/heads/agent/work` and
`refs/heads/agent/nested/work`. It does not permit the distinct reference
`refs/heads/agent`, the adjacent namespace `refs/heads/agents/`, or any tag. The
exact tag selector does not grant its descendants. There are no wildcards, regular
expressions, substring matches, URL decoding, or locale-dependent comparisons.
Hexadecimal encoding preserves Git-valid non-UTF-8 reference bytes exactly.

Every selector must be rooted in `refs/`. An exact selector must pass the native
reference grammar. A prefix must end in `/`, and the part before that slash must
pass the same grammar. Pseudoreferences such as `HEAD` and `FETCH_HEAD`, malformed
reference names, uppercase hex, odd hex lengths, duplicate selectors, empty
selectors, and unknown selector kinds fail validation. `all` and `none` cannot
be combined with selectors.

A row may contain at most **64 selectors** and **4,096 decoded reference bytes**
in total. Native per-reference length limits still apply. The existing complete
file bounds of **256 rows** and **64 KiB** still apply. A malformed row invalidates
the complete table, including otherwise valid rows. There is no fallback to v1,
a cached credential table, or an unrestricted grant.

## Enforcement across publication routes

A reference write includes creation, update, and deletion. A rename writes both
its source and its destination. Every destination of a multi-reference request
must be permitted before publication starts.

| HTTP operation | References checked |
|---|---|
| Git receive-pack, atomic or non-atomic | Every command in original wire order, before any child retry key or microbatch is admitted. |
| Branch create, update, delete | The named branch. |
| Branch rename | Both the deleted source and created destination. |
| Branch transaction | Every branch in the complete transaction. |
| Lightweight/annotated tag creation and tag deletion | The exact tag reference. |
| Initial commit apply | The new branch. |
| Source edit apply, including prepared patch/cherry-pick/revert candidates | The destination branch. |
| Rebase apply | The rewritten destination branch. |
| Bundle import | Every reference declared by the bundle. |
| Bundle fetch | Every explicit destination mapping; an allowed source does not authorize a different destination. |
| Reviewed merge or squash | The target branch. |
| Pull-request fast-forward | The target branch. |

A mixed request containing one denied reference is refused as a whole. In
particular, a non-atomic Git push cannot publish an allowed first command before
a denied sibling is discovered. This credential check does not create a terminal
authority decision or consume the command's retry identity.

REST refusals use HTTP `403` with `ref_write_scope_denied`. A complete Git
receive-pack request receives an HTTP `200` Git protocol `ERR` explaining that
the credential does not permit every requested reference and that no reference
decision was attempted. A protocol refusal is not a successful Git push.

## Independent reads, metadata, and repository policy

The reference ceiling is **write authorization**, not a read-disclosure filter.
A token with `read` may still fetch, browse, inspect, and prepare candidates using
the repository's existing visibility profile, including references outside its
write ceiling. A `none` ceiling can therefore accompany a read-only or
metadata-only token. Do not use this feature to promise branch confidentiality.

The ceiling also does not grant a service. For example, selecting a branch without
`receive` cannot push it; selecting a merge target without `merges-write` cannot
merge it. Issue/PR metadata, reviews, check reads, protection administration, LFS,
and workflow-artifact reads retain their existing independent service grants.
Deployment enablement switches remain additional ceilings.

A permitted reference still must pass canonical admission, branch protection,
expected-old checks, candidate validation, and object-format checks. The selected
scope is request-local authentication evidence; it is not added to shared
admission snapshots or used to replace repository policy.

## Rotation, retries, and recovery

Atomically replace the private credential file to narrow, expand, rotate, or
revoke grants. Each new request reloads the complete table. Missing, invalid, or
foreign-incarnation files fail closed. A valid v2 header with no rows revokes all
tokens. Already authenticated in-flight requests retain their originally selected
bounded grant, as in the v1 deployment profile.

A narrowed credential cannot resubmit a now-denied write, even when its original
key already committed. Use independently granted `outcomes-read` with the
original principal and key to recover the historical result; this does not grant
write access again. Conversely, a request refused solely by this reference
ceiling may reuse its original key after the operator grants the needed refs,
because the refusal did not bind or publish a transaction. Credential scope is
not part of the canonical principal/key identity.

The tests in `crates/fgit-node/tests/ref_write_scope_http.rs` exercise real TCP,
native quarantine, both Git object formats, atomic and non-atomic Git pushes,
full native reference transactions, deletes, raw-byte tags, narrowing, revocation,
and read/outcome independence.
