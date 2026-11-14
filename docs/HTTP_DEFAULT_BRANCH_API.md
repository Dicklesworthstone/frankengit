# HTTP default-branch administration

The repository endpoint `/api/v1/default-branch` reads and changes the canonical
symbolic `HEAD`. Selecting an existing branch determines what ordinary clones
check out and which branch the native deletion guard protects. The operation
uses the existing sealed default-branch command and authority-head CAS; it does
not move a direct branch, create Git objects, rewrite a PR base, or change policy.

## Enablement and credentials

For the single-repository HTTP profile, add
`--enable-default-branch-admin` to `fg serve-http` and use
`--credentials-file`. The flag is disabled by default and grants no identity or
permission. Default-branch writes have the independent `default-branch-write`
scope. Append it after the existing scopes in the credential row's canonical
order, for example:

```text
<token-sha256> <administrator-principal-id> read,outcomes-read,default-branch-write
```

The token's principal must be an administrator in an **already installed**
canonical review-protection policy, even if that policy protects no branches.
Install initial ownership through the existing trusted-local policy operation.
Every actual CAS preparation checks the currently selected administrator set.
The HTTP profile cannot bootstrap policy ownership. `receive`, `merges-write`
and `protection-write` do not imply the new grant. Sponsored agent credentials,
canonically declared agent principals, SSH provenance and narrowed v2 ref-write
scopes cannot administer the default. A v2 row with `all` retains the unscoped
operator profile; `none` or specific reference selectors do not.

Reads require `--allow-source` and a `read` token. They do not require the
administrator flag or write grant. The browser selector also needs these reads;
optional outcome recovery needs `--allow-outcomes` and `outcomes-read`.
Canonical visibility of `HEAD`, its current target and the proposed target
applies independently of administrator status. Hidden names are not disclosed
through this endpoint. Existing multi-repository CLI catalog service choices
are unchanged; this administrator enablement belongs to the explicit
single-repository profile.

The public static selector is `<repository-route>/ui/default-branch/`, linked
from branch management and initial-history setup. It reads the current default
and candidate branches at the same authenticated snapshot, preserves byte-only
names, and freezes an exact command for separate confirmation. Credentials stay
in memory. Export the original retry receipt before closing a page with an
unresolved request; the receipt contains the scope, command and recovery key,
not the bearer token.

## Read the current default

```http
GET /tenant/repository.git/api/v1/default-branch HTTP/1.1
Authorization: Bearer <read-token>
```

An optional `expected_head=alg:<algorithm>:<64-lowercase-hex>` query pins the
read to an observed authority head. A moved head returns `409
source_snapshot_moved`; the server never silently refreshes the pin. The GET
accepts no body, idempotency key, additional query field or Git protocol header.

The complete JSON observation has `type: "default_branch"`,
`schema_version: 1`, `tenant_id`, `repository_id`, `repository_incarnation`,
`principal_id`, `object_format`, `source_head` and `snapshot_token`, plus:

| Field | Meaning |
| --- | --- |
| `default_reference_hex` | Exact lowercase hexadecimal branch-name bytes, or `null` when symbolic HEAD is absent. |
| `tip` | Native object ID in the response's `object_format`, or `null` when absent or unborn. |
| `unborn` | `true` exactly when a symbolic target exists but has no direct tip. |
| `read_only` | Always `true`. |
| `transaction_created`, `published` | Always `false`. |

An absent target and an unborn named target are different states. The endpoint
does not assume `main` or another conventional branch name. Reference names are
bytes; the hex field is authoritative, including names without a UTF-8 display.
Native OIDs use 40 lowercase hex characters for SHA-1 or 64 for SHA-256.

## Select an existing branch

```http
POST /tenant/repository.git/api/v1/default-branch HTTP/1.1
Authorization: Bearer <default-branch-write-token>
Idempotency-Key: <original-request-key>
Content-Type: application/x-www-form-urlencoded

expected_default_hex=<old-branch-bytes-hex>&reference_hex=<new-branch-bytes-hex>&expected_tip=<native-commit-hex>
```

When symbolic HEAD is absent, replace `expected_default_hex` with
`expect_no_default=true`. Exactly one of these fields is mandatory; absence
never means “accept whichever branch is current.” Both old and new names must
be full `refs/heads/*` names. The destination must already exist and point to the
specified nonzero native Commit. The original expected target and tip are
revalidated on every CAS attempt. A same-target request is an audited no-op and
still requires current administrator authority.

Only these three form fields are accepted. Duplicate fields, a caller-supplied
principal, force flags, policy changes, wrong-format/zero OIDs and non-branch
targets refuse. A command is at most 24 KiB; chunked framing has independent
wire-byte and chunk-count bounds. Complete request framing precedes admission.
Intake and awaited authority work retain the accepted request's original
deadline. Reads use source-read quotas; writes use mutation quotas and the
existing bounded writer admission.

## Decisions and recovery

The terminal response has `type: "default_branch_publication"`,
`schema_version: 1`, the repository/incarnation/principal scope, `object_format`,
`operation: "set-default"`, `authentication: "http-token"`, `terminal: true`,
`tx_id`, `decision_sequence`, and the exact echoed command:
`expected_default_reference_hex`, `default_reference_hex`, `expected_tip`.

Committed decisions return HTTP 200, `outcome: "committed"` and
`repository_commit_id`. Canonical refusals return HTTP 409,
`outcome: "refused"`, `code`, `code_point` and `refusal_record_id`.
`head_changed_by_transaction` is true only for a committed change between
different symbolic targets; `direct_refs_changed` is always false. These fields
describe this transaction, not a fresh assertion of the repository's current
default. No post-decision policy or source read can replace a historical receipt.
The response's `authentication` describes this HTTP request; recovering a
decision originally made through the local operator profile does not rewrite
that decision's stored provenance.

Retry the identical form with its original principal and `Idempotency-Key`.
Changing either expectation under the same key returns `idempotency_key_reuse`.
A terminal retry remains the same after later default changes, administrator
rotation or deletion of the old target. A currently valid gateway grant is
still required. If the write grant was removed, use the independently granted
`POST /api/v1/outcomes` recovery surface with the original key. Token rotation
can preserve the same canonical principal namespace.

A broken connection, timeout, lost response or infrastructure failure does not
establish non-commit. The browser preserves the original request across these
conditions and offers unchanged retry, receipt export and outcome recovery.
Do not refresh expectations or mint a replacement key to resolve an uncertain
request. A successful receipt describes a canonical decision, not delivery
acknowledgement by another client.

## Implementation and regression coverage

The native HTTP profile is separate from
`admit_default_branch_trusted_local_in`; trusted-local bootstrap and provenance
restrictions remain unchanged. Canonical principal evidence records genuine
`HttpToken` authentication. No schema or transaction identity fork is introduced.
See [native default branches](NATIVE_DEFAULT_BRANCH.md) and normative contract
§16.6 for the shared semantic identity, HEAD delta and supported root layouts.

Focused coverage is in `default_branch_http.rs`, the default-branch admission
and node tests, the HTTP request/scope tests, and
`tests/browser/default-branch*.test.mjs`. It covers both native hash domains,
byte-only targets, absent/unborn reads, gateway/grant/admin separation, stale
expectations, incomplete framing, policy races, cancellation, reopen and original
terminal recovery. Test sources are not themselves a passing execution record;
use revision-bound results from the verification run.
