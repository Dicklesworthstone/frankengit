# Atomic multi-branch HTTP transactions

`POST {REPO_URL}/api/v1/source/branches/transaction` accepts 1..4,096 distinct
branch changes and invokes `OneNode::admit_branch_transaction_durable_in` once.
All changes publish together or none do. It is not a loop of independent writes.
The existing single-branch and atomic rename endpoints remain unchanged.

## Authorization and input

Use the existing repository source gateway with `--allow-source --allow-receive`
and an operator-managed `receive` credential. Authentication, deployment ceilings,
quota and an explicit `Idempotency-Key` are checked before body intake or
`100 Continue`. Read-only, review and merge grants do not imply receive permission.
No principal, force, atomic-mode or policy override may be supplied in the body.
This remains the existing loopback deployment/TLS-proxy profile, not hosted IAM.

The content type is `application/x-www-form-urlencoded`. Supply `object_format`
exactly once (`sha1` or `sha256`, matching the repository), and repeat these fields:

| Field | Value |
|---|---|
| `create` | `REF_HEX:NEW_COMMIT` |
| `update` | `REF_HEX:EXPECTED_COMMIT:NEW_COMMIT` |
| `delete` | `REF_HEX:EXPECTED_COMMIT` |

`REF_HEX` is lowercase hexadecimal encoding of the full `refs/heads/...` byte
name. This preserves non-UTF-8 names without lossy text conversion. Native commit
IDs are nonzero lowercase hex in the repository's exact hash domain. Updates
require explicit old tips; creation always requires absence. Repeated operation
fields are intentional, but duplicate target references and extra fields refuse.

```sh
curl --fail-with-body --header @/secure/branch-writer.headers \
  --header 'Idempotency-Key: coordinated-release-1' \
  --data-urlencode 'object_format=sha256' \
  --data-urlencode "update=$RELEASE_REF_HEX:$OLD_RELEASE:$NEW_COMMIT" \
  --data-urlencode "create=$COPY_REF_HEX:$NEW_COMMIT" \
  --data-urlencode "delete=$OBSOLETE_REF_HEX:$OLD_OBSOLETE" \
  "$REPO_URL/api/v1/source/branches/transaction"
```

One complete fixed-length or chunked form must arrive before any authority work.
The body is bounded to 256 KiB and 4,097 fields, including the one object format;
reference names are at most 4096 decoded bytes. The native command, wire, object,
ancestry, quota and request limits still apply. A limit refusal never truncates
an operation list into a smaller successful transaction. The byte envelope can
bind before the shared 4,096-command ceiling.

## Publication, outcomes and retry

The existing `branch_publication` response contains `operation:"transaction"`,
`atomic:true`, `terminal:true`, one TxId/decision, and all submitted updates.
HTTP 200 means canonically committed; HTTP 409 `outcome:"refused"` is a canonical
all-or-nothing refusal. Preflight errors remain `source_error`, not invented
terminal decisions. Transport or serialization failure after admission is an
unknown/lost receipt, never proof of rollback. Recover using the same principal
and key at `POST /api/v1/outcomes` with an `outcomes-read` grant.

Reordering distinct operations retains the native semantic request identity.
The response's updates retain caller order, so compare transaction and decision
identity rather than response-array order for such retries. Reusing the key with
different semantics refuses. Credential rotation with the same principal retains
that scope. Revocation affects subsequent authentication; it does not undo an
already authenticated transaction. A restarted exact retry returns the original
decision without reapplying the branch changes.

New tips must already be verified, visible commits. No objects are uploaded here.
Fast-forward, current mandatory protection, default-branch and hidden-ref checks
remain native. A stale member or competing transaction cannot leave a valid
prefix published. No PR metadata, default-branch configuration or forge transition
is manufactured by this route.

## Focused verification

`cargo test -p fgit-node --lib smart_http::server::source::refs --locked` exercises
the route/envelope and bounded operand grammar. `cargo test -p fgit-node --test
branch_transaction_http --test branch_http --locked` runs actual TCP listeners and
file-backed native nodes, including SHA-1/SHA-256 mixed changes, stale atomic
refusals, reordered and restarted retries, competing sets, credential revocation,
read-only recovery, deployment ceilings and incomplete bodies. The tests are
bounded integration evidence, not a general concurrency proof or release gate.
