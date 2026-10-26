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
Each command's authoritative lowercase `ref_name_hex` preserves its exact native
reference bytes. `ref_name` retains UTF-8 text or is null for a non-UTF-8 name.

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
Child bindings and seals are observed sequentially, so nonterminal observations
may immediately change. The authority recovery path reads accelerator hints
before selecting one fresh authenticated head, then walks that immutable history
once for all sealed children. Each answer still passes the existing hint/stream
consistency check. This avoids replaying the full history separately for every
command without turning the accelerator into authority. Completion is meaningful
because the command list is fixed and verified, and each authenticated terminal
decision is immutable. A cancelled or failed lookup does not publish a decision
or convert missing evidence into an absent or refused result. Repeat the same
lookup after a lost query response.

Asynchronous single-key recovery uses the same authority resolver. Its fresh
head is selected after accelerator observations as well, so a legitimate
concurrent publication cannot produce a false hint/history disagreement. The
shared walk stops when every requested terminal is found. It still obeys the
existing replay bound for unresolved or sufficiently old transactions.

## Why a descriptor cannot invent completion

The continuing admission coordinator already binds the entire semantic request
and every child retry key before publishing any child. It now also stores a
bounded immutable descriptor at that point, before the first child is sealed.
Sessions through 4,096 commands retain the existing v1 canonical
`SemanticRequest` and exact wire-order permutation. Sessions from 4,097 through
16,384 commands use a v2 carrier containing two to four canonical request
chunks, each with at most 4,096 globally ref-sorted commands, and one exact
permutation from canonical to original wire order. Each child keeps its existing
key, receive schema and transaction identity. The unsealed v2 whole-session
binding commits to the chunk digests, total count and complete permutation using
the existing semantic-request identity derivation. Neither carrier contains a
pack, validation basis, secret, raw client key or outcome.

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

V1 descriptors remain bounded to 1 MiB and 4,096 commands; v2 descriptors are
bounded to 4 MiB and 16,384 commands. Long reference names and push options can
hit the byte ceiling first. Both carrier size and any narrower backend body
limit are checked before reserving a previously unused retry key. The existing
16 MiB option-replication work budget now charges the retained option header as
well as nonempty payload work, so empty options cannot evade the bound.
Responses are capped at 64 MiB and the configured server response ceiling,
whichever is smaller. Indexed recovery accepts wire indices 0 through 16,383.
The full response is built and bounded before the first success byte; an
over-limit response is refused, not truncated into an apparently complete
session. All original and child bindings must verify for either version.

## Bounded durable binding and sealing

Large sessions group immutable child-key and seal writes into at most 64 items
and 1 MiB of combined key/body bytes per storage call. The backend's independent
body and slot limits still apply. The embedded FrankenSQLite backend performs
each group in one owned SQL transaction, retaining its cancellation,
rollback/recovery and immutable-cache checks. Other authority backends retain a
portable ordered create-if-absent fallback. This reduces physical transactions
for new session metadata without changing any key, canonical body, transaction
identity or report position.

The original whole-session key settles separately before the first child group.
Every child binding settles before the descriptor is staged, and the descriptor
precedes the first child seal or decision. A changed original key therefore
cannot reserve a new set of child keys. Every seal group rechecks the same
bindings before writing any seal. Conflicts remain exact per-key results;
successful independent bindings can exist even if another key conflicts.

No group operation publishes repository state. Only the existing
exact-predecessor head CAS does that. A failed group returns no successful seal
vector: portable backends can have a completed prefix, and a native commit with
a lost response remains ambiguous. Repeating the same session key and request
recovers every existing binding and seal through identical retry. A missing
descriptor after interrupted binding remains `session_not_observed`, never
proof that no immutable key was reserved. CPU checkpoints surround finite groups;
the native backend also checks the caller's context during each item and
transaction finalization.

## Compatibility and non-claims

Atomic pushes still use `POST /api/v1/outcomes` with the original key. Existing
`POST /api/v1/outcomes/receive/{index}` lookups are unchanged and remain useful
for legacy sessions. A missing indexed outcome alone still cannot establish
command count or completion.

Whole-session descriptors are written by the continuing receive coordinator
used by Smart HTTP and the guarded native/SSH receive paths. Older sessions and
legacy compatibility entry points may have no descriptor. An identical retry through the new coordinator
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
