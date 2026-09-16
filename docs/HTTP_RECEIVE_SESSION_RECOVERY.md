# Recover a complete non-atomic push from its original key

The opt-in outcome API now supports a complete non-atomic receive-session query:

```text
POST {REPO_URL}/api/v1/outcomes/receive
Authorization: Bearer <current-token-for-original-principal>
Idempotency-Key: <original-session-key>
Content-Length: 0
```

No command count, command list, ref names, transaction IDs, or PACK bytes are
required. This is a read-only query, not a retry of the original mutation. Use
`--allow-outcomes` and an explicit `outcomes-read` credential grant, as described
in [HTTP_OUTCOME_API.md](HTTP_OUTCOME_API.md). Git receive and issue permissions
are not required and do not imply recovery permission. The same repository,
incarnation, and authenticated original principal scope apply.

```sh
curl --fail-with-body --request POST \
  --header @/secure/recovery.headers \
  --header 'Idempotency-Key: original-push-attempt' \
  --header 'Content-Length: 0' \
  "$REPO_URL/api/v1/outcomes/receive"
```

Keep the bearer credential in the private header file, not in a URL. The
existing empty-body, strict-header, no-query-parameters, no-100-Continue,
independent recovery quota, bounded connection pool, and deadline policies apply.
No plaintext key or credential appears in a recovery response.

## What the response establishes

The JSON response has `type: "receive_session_outcome"` and schema version 1.
It reports the original wire-order command positions, each submitted ref name,
and each command's existing `transaction_outcome` observation. Those nested
observations retain the same seal, transaction ID, canonical request digest,
decision sequence, and committed/refused/nonterminal vocabulary as individual
lookup. Ref names come from the caller's verified submitted request, not from
current ref enumeration.

| Session state | Command count | Meaning |
|---|---|---|
| `session_not_observed` | `null`, not verified | No descriptor was observed. This includes legacy sessions. It does not establish an empty session, completion, or non-commit. |
| `partial` | Exact verified count | At least one listed command has no authenticated terminal outcome. Other commands may already be committed or refused. |
| `complete` | Exact verified count | Every listed command has an authenticated terminal decision. This does **not** mean every command committed. |

`command_count_verified` is true only after the descriptor and all original
whole-request/child bindings have been verified. `all_terminal` is null when
no descriptor was observed, false for a partial session, and true for a complete
session. `session_completeness_established` is true only in the complete case.

`session_identity` names the whole-request binding identity, **not an additional
sealed transaction or terminal decision**. `session_identity_is_transaction`
is false. Only the individual child transactions have canonical outcomes.

This is explicitly **not a single-snapshot read**: `single_snapshot` is false.
Children are observed sequentially and nonterminal observations may immediately
change. Completion is nevertheless meaningful because the command list is fixed
and verified, and each authenticated terminal decision is immutable. A cancelled
or failed lookup does not publish a decision or convert missing evidence into
an absent or refused result. Repeat the same lookup after a lost query response.

## Why a descriptor cannot invent completion

The continuing admission coordinator already binds the entire semantic request
and every child retry key before publishing any child. It now also stores a
bounded immutable descriptor at that point, before the first child is sealed.
This contains the existing canonical `SemanticRequest` and an exact permutation
from canonical ref-name order to original wire order. It contains no pack,
validation basis, secret, raw client key, or outcome.

The descriptor is an untrusted recovery carrier, not a new state authority.
Recovery checks its version, size, canonical byte encoding, semantic validity,
object format, and one-to-one command permutation. It re-derives the whole
request identity and compares the existing base-key binding, then re-derives
and checks every child binding. Any returned child seal must exactly match
that reconstructed child request. Terminal decisions still come exclusively
from the existing authoritative outcome resolver.

A structurally valid descriptor that omits a command, swaps command positions,
or substitutes another request fails the corresponding bindings. Corrupt or
unavailable required evidence returns an error, not a completed or empty
session. Descriptor conflicts stop new admission before any child is published.
Descriptor staging itself advances neither decision nor repository sequence.

The descriptor is bounded to 1 MiB and 64 commands. Responses are capped at
1 MiB and the configured server response ceiling. The full response is built
and bounded before the first success byte; an over-limit response is refused,
not truncated into an apparently complete session.

## Compatibility and non-claims

Atomic pushes still use `POST /api/v1/outcomes` with the original key. Existing
`POST /api/v1/outcomes/receive/{index}` lookups are unchanged and remain useful
for legacy sessions. A missing indexed outcome alone still cannot establish
command count or completion.

Whole-session descriptors are written by the continuing receive coordinator
used by Smart HTTP. Older sessions and the unchanged generic/raw git-daemon
paths may have no descriptor. An identical retry through the new coordinator
can populate one after its existing whole/child bindings pass, but a read-only
lookup never reconstructs missing metadata by writing it. Do not interpret
`session_not_observed` as permission to replace a mutation's original key.

The node API is `OneNode::recover_receive_session_in`. It requires an
independently authenticated session but does not require the child node to
enter Serving or admit writes. The listener itself still follows its normal
startup readiness contract. The existing CLI command-index selector is
unchanged; this change does not add a whole-session CLI flag.

This is the bounded loopback operator-managed gateway, not full REST/OpenAPI,
organization/team IAM, TLS termination, or a completed compatibility campaign.
The source and tests describe implementation behavior; they do not constitute
a passing build or production certification.

Focused verification:

```sh
cargo test -p fgit-admission --lib policy_bridge::receive_session::recovery
cargo test -p fgit-node --lib transaction_recovery::session_tests
cargo test -p fgit-node --lib interrupted_second_command_preserves_first_outcome
cargo test -p fgit-node --lib smart_http::server::outcomes
cargo test -p fgit-node --test receive_session_http --test outcome_http \
  --test smart_http_non_atomic --test smart_http_session_binding
```
