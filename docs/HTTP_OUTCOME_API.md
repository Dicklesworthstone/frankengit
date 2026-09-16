# Read-only transaction outcome recovery

The bounded repository HTTP gateway can recover a lost mutation response using
its original client key. The lookup requires no command body, workspace, pack,
or previously returned transaction ID. It uses `OneNode::recover_transaction_in`
and the existing authority key/seal verifier and terminal-outcome resolver; it
never re-seals, re-submits, cancels, or publishes a transaction.

This describes an implemented interface, not a passing build or a completed
FG-048 REST/OpenAPI, identity, compatibility, or security acceptance campaign.
The listener remains loopback-only, with operator-managed grants and no TLS
termination or organization/team IAM. Recovery is not an administrator's
cross-principal transaction browser.

## Enable recovery independently

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /secure/http-grants --allow-outcomes
```

This does not enable Git pushes or issue endpoints. Those still require their
separate deployment flags and credential scopes. Old static-token, Git-only,
and Git-plus-issue node entry points leave outcome lookup disabled.

Use `--print-credentials-header` to obtain the exact tenant/repository/incarnation
header as described in [HTTP_ISSUE_API.md](HTTP_ISSUE_API.md). Each credential row
contains the SHA-256 digest of a 64-character lowercase-hex ASCII bearer token,
its principal ID, and explicit scopes. Add `outcomes-read` to grant recovery.
Combined scopes appear once in this order:

```text
read,receive,issues-read,issues-write,outcomes-read
```

No permission implies another. A token with only `outcomes-read` can inspect
that principal's own historical transactions without Git, issue-read, or
issue-write access. Rotating to a new token for the same principal retains the
same lookup namespace. A different principal is a different namespace, even
when the client key text is identical.

The private regular credential file is reloaded on each authentication. Missing,
corrupt, or foreign-incarnation configuration fails closed. Removing a token
revokes subsequent authentication; already authenticated bounded requests are
not retroactively cancelled. Static tokens receive no implicit recovery grant.

## Routes and request envelope

Let `REPO_URL` be the repository URL reported by `fg serve-http`. A normal
sealed transaction, including an issue mutation or atomic push, uses:

```text
POST {REPO_URL}/api/v1/outcomes
Authorization: Bearer <current-token-for-original-principal>
Idempotency-Key: <original-key>
Content-Length: 0
```

POST is a read-only query here. Its body must be empty. An absent Content-Length
is also accepted as empty. Nonempty or chunked bodies, `Expect: 100-continue`,
Git-Protocol headers, query parameters, duplicate keys, and buffered bytes past
the empty body are refused. The gateway never reads an original mutation body.
The HTTP key profile is the existing 1..128-byte visible-ASCII key profile;
keys are not placed in URLs or echoed in responses. Binary local keys remain
available through `fg outcome` below.

A private header file avoids placing literal credentials in a command line:

```sh
curl --fail-with-body --request POST \
  --header @/secure/recovery.headers \
  --header 'Idempotency-Key: issue-41-open-attempt-1' \
  --header 'Content-Length: 0' \
  "$REPO_URL/api/v1/outcomes"
```

The private header file contains `Authorization: Bearer ...`, not the server's
hashed grant table. Keep both files outside repository content.

### Non-atomic Git pushes

A non-atomic push has one transaction per original wire command. Select one
using the ORIGINAL session key and its zero-based wire index:

```text
POST {REPO_URL}/api/v1/outcomes/receive/0
POST {REPO_URL}/api/v1/outcomes/receive/1
```

The index is canonical decimal in 0..63. It is not sorted ref-name order, an
issue number, or a transaction sequence. The selector calls the admission
lowerer's existing child-key derivation; it does not invent a new identity.
Even a single-ref push without the `atomic` capability uses index 0. Atomic
pushes use the base route and original key, regardless of their command count.

The original non-atomic session key can be bound to the whole request without
itself owning a seal or terminal decision. A direct base-route lookup can
therefore report `seal_not_observed` for a completed non-atomic push. Use the
receive-command route to inspect its actual child transactions.

**One missing index does not prove the command count or session completion.**
Inspect the original command positions the client actually submitted. Multiple
lookups are independent observations, not one promised snapshot of the session.

## JSON observations

Successful lookup returns HTTP 200 with `type: "transaction_outcome"`, schema
version 1, repository/incarnation/principal scope, selector and optional command
index, plus the following state:

| `state` | Meaning |
|---|---|
| `key_not_observed` | No binding observed in this authenticated scope. |
| `seal_not_observed` | Binding observed, but no checked seal. The binding's unverified target is not disclosed. |
| `undecided` | A checked seal exists; the authoritative resolver observed no terminal decision. |
| `committed` | An authenticated committed decision exists. |
| `refused` | An authenticated canonical refusal exists. |

Only the last two set `terminal: true`. A checked transaction includes its
`tx_id`, `seal_id`, request schema and canonical request digest. Terminal
`decision` data includes the decision sequence and either repository commit ID
or refusal code, numeric code point and refusal-record ID. Otherwise decision
is null. Raw bearer tokens and original/derived key bytes are never returned.

Every observation states:

```json
{
  "read_only": true,
  "request_reexecuted": false,
  "absence_proves_non_commit": false,
  "session_completeness_established": false
}
```

A successfully read canonical refusal is HTTP 200, not a newly attempted
mutation's HTTP 409. Missing observations may change immediately: they do not
prove rollback, authorize replacing the key, or cancel an outstanding request.
Keep the original principal, command, expected version and key when resolving
an ambiguous attempt.

## Errors and limits

Lookup errors have `type: "outcome_error"`, a stable code, `retryable`, a
machine-readable `remediation`, and `outcome_unknown: true`. They do not invent
an absent key, undecided state, or canonical refusal when required evidence
cannot be read or verified. Authentication is 401, disabled/insufficient grants
403, malformed requests 400, unsupported method 405, limits 413 and throttling
429. Infrastructure/corrupt required evidence returns 503. Retryable failures
instruct the client to repeat the same lookup, not submit a new mutation.

Replies are capped at 16 KiB and the configured response envelope, with
Content-Length, no-store, nosniff, and authorization/key variance. Lookup has a
separate per-principal quota from mutation intake, but still shares the bounded
listener connection pool. Reads run on owned blocking children, propagate the
node request deadline, and close before returning. The recovery child does not
enter Serving or require mutation admission. A parent listener must still meet
its normal startup/service readiness contract.

After a final response starts, disconnect or cleanup failure never appends a
second HTTP response. Repeating a lookup after a lost lookup response has no
mutation side effect.

## Local recovery with the same selector

```sh
fg outcome "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local \
  --principal "$ORIGINAL_PRINCIPAL" --idempotency-key "$ORIGINAL_KEY" \
  --receive-command-index 1
```

`--key-stdin` and `--idempotency-key-hex` retain byte-exact binary-key support.
Omit the index for ordinary transactions and atomic pushes. Use
`--object-format sha256` for a SHA-256 repository. Receipt `key_digest` refers
to the selected child key when an index is supplied. Exit 0 means committed,
3 canonical refusal, 4 nonterminal observation, and 2 input/infrastructure/output
error. The command does not bring the node into mutation-serving state.

## Focused verification

```sh
cargo test -p fgit-admission --lib recovery_selector_tests
cargo test -p fgit-node --lib smart_http::server::outcomes
cargo test -p fgit-node --lib smart_http::server::credentials
cargo test -p fgit-node --test outcome_http
cargo test -p fgit-cli --bin fg transaction_outcome::tests
cargo test -p fgit-cli --bin fg smart_http_server::tests
```

These commands are verification entry points, not a claim that they passed.
Existing Smart HTTP and issue integration suites remain necessary regressions.
