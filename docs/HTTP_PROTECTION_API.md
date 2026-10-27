# Review protection administration over HTTP

The native HTTP service can inspect and replace the repository's mandatory
exact-candidate review policy and bounded ref-fact/actor-ID DSL policy. It calls the existing
`read_review_protection_in` and `admit_review_protection_durable_in` node APIs.
The canonical policy supplies the current administrators. Credentials identify
principals and grant transport access; they do not make a principal an
administrator.

This remains the bounded, loopback-only, operator-managed HTTP profile.
TLS termination, public identity providers, organization/team IAM and policies
requiring actor kind, authentication strength, membership, ancestry, time or evidence facts remain outside this interface. The underlying
enforcement and writer-upgrade requirements are described in
[MANDATORY_REVIEW_PROTECTION.md](MANDATORY_REVIEW_PROTECTION.md).

## Bootstrap locally, then enable explicitly

First install ownership through trusted-local `fg protection set` or the
separate [MCP administration profile](MCP_REVIEW_PROTECTION.md). HTTP never
installs an absent policy: `expected_version=0` is refused before admission,
and an invented positive predecessor cannot create ownership at the native CAS.

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /secure/http-grants \
  --allow-protection --allow-outcomes
```

`--allow-protection` requires reloadable scoped credentials. Static tokens have
no protection grants. The outcome switch is optional and independent. No other
service switch enables policy administration. Readiness JSON reports
`protection_enabled`.

The complete canonical scope order is:

```text
read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write,reviews-read,reviews-write,merges-write,protection-read,protection-write
```

| Scope | Operation |
|---|---|
| `protection-read` | Inspect the complete current policy, selected head, version and epoch. |
| `protection-write` | Submit a complete replacement authorized by current canonical administrators. |
| `outcomes-read` | Independently recover this principal's original terminal decisions. |

No scope implies another. Push, PR merge, review voting, policy inspection and
policy replacement remain separate grants. Replacement can disable requirements
or rotate administrators; grant it deliberately. The proposed administrator list
cannot authorize itself.

Credential files retain exact tenant/repository/incarnation binding and reload
on every authentication. Revocation affects subsequent requests, while an
already authenticated bounded request retains its authenticated identity.
See [HTTP_PULL_REQUEST_API.md](HTTP_PULL_REQUEST_API.md) for provisioning and
[HTTP_OUTCOME_API.md](HTTP_OUTCOME_API.md) for independent recovery permissions.

## Read the current policy

```text
GET {REPO_URL}/api/v1/protection
GET {REPO_URL}/api/v1/protection?expected_head=HEAD_TOKEN
Authorization: Bearer <protection-read-token>
```

The `repository_review_protection` response contains schema version 1,
repository binding, `source_head`, decimal-string `policy_epoch` and `version`,
`installed`, `enabled`, and the complete `policy`. The returned `source_head`
is a round-trippable `alg:CODE:DIGEST` token accepted by `expected_head`.
A moved head returns HTTP 409; the query does not request a retained historical
policy.

A never-installed policy has `version: "0"`, `installed: false` and
`policy: null`. An explicitly disabled policy retains its version and
administrators, has an empty branch array, no DSL snapshot and reports `enabled: false`.
An installed DSL snapshot alone reports `enabled: true`. The optional
`policy.ref_policy` contains `snapshot_id`, a factual `profile`,
`mode: "enforce"`, and the complete canonical `frame_hex`; it is null when no
DSL component is installed. The frame permits exact replacement without
recompiling or reconstructing the original source.
The profile is `reference_facts_v1` for ref-only policies and
`reference_actor_id_v1` when the policy also reads `actor.id`. Actor-ID rules
use the principal bound to the authenticated request, never a principal
supplied in a policy form field. The latter profile has a distinct canonical
event/evidence version; older readers refuse it rather than losing the actor
restriction. Browser editors retain the exact observed profile and frame.
Policy administrators are lowercase principal IDs. Each branch contains
`reference_hex`, `required_reviewers` and `required_checks`; hex preserves exact
native branch bytes, including non-UTF-8 names. Each check contains
`source_ref_hex`, `publisher`, `graph_root` and the exact UTF-8 `job`. Empty check
arrays preserve review-only policies; check-only branches have empty reviewer
arrays. The [check profile](REQUIRED_WORKFLOW_CHECK_PROTECTION.md) defines their
explicit publisher authority and exact-candidate enforcement.

The read reports `complete: true`, `transaction_created: false` and
`published: false`. It accepts no body, Idempotency-Key, Git-Protocol header
or mutation fields.

## Replace, rotate or disable

```text
POST {REPO_URL}/api/v1/protection
Authorization: Bearer <protection-write-token>
Idempotency-Key: <original-client-selected-attempt-key>
Content-Type: application/x-www-form-urlencoded
```

Every request is a complete replacement:

| Form field | Required value |
|---|---|
| `expected_version` | Exact positive decimal predecessor policy-aggregate version. |
| `expected_epoch` | Exact positive decimal predecessor policy epoch. |
| Repeated `administrator` | One to 32 lowercase 32-hex-character principal IDs. |
| Repeated `required_reviewer` | `REFERENCE_BYTES_HEX:PRINCIPAL_ID`, with lowercase hex and an exact `refs/heads/*` reference. |
| Repeated `required_check` | `TARGET_REF_HEX:SOURCE_REF_HEX:PUBLISHER:GRAPH_HEX:JOB_UTF8_HEX`; refs name exact `refs/heads/*`, publisher is a 32-character principal ID, graph is 64 lowercase hex characters, and job is exact UTF-8 encoded as hex. |
| `ref_policy_source` | Optional UTF-8 policy source, at most 64 KiB, compiled and validated against the available reference facts and exact request `actor.id` before sealing. |
| `ref_policy_frame_hex` | Optional canonical compiled policy frame as lowercase hex, at most 64 KiB decoded. Mutually exclusive with `ref_policy_source`. |
| `clear` | Exactly `true` to disable branch and DSL requirements; mutually exclusive with reviewer, check and DSL entries. |

Supply reviewers, workflow checks, a DSL policy, or explicitly supply `clear=true`. Native
bounds are 64 branches, 32 reviewers and 32 checks per branch, 1,024 bytes per
reference and 1,024 UTF-8 bytes per job. Job names must be nonempty and contain
no control characters. Repeated sets are canonically sorted; duplicates refuse. Numeric strings cannot have leading
zeros, signs or overflow. Unknown fields, duplicate scalars, malformed escaping
and invalid references refuse. There is no actor/principal field, implicit
predecessor refresh or force option.

With actual selected predecessor values and a private file containing the
Authorization header, a replacement protecting `refs/heads/main` is:

```sh
curl --fail-with-body --header @/secure/admin.headers \
  --header 'Idempotency-Key: review-policy-rotation-1' \
  --data-urlencode "expected_version=$POLICY_VERSION" \
  --data-urlencode "expected_epoch=$POLICY_EPOCH" \
  --data-urlencode "administrator=$NEXT_ADMIN" \
  --data-urlencode "required_reviewer=726566732f68656164732f6d61696e:$REVIEWER" \
  "$REPO_URL/api/v1/protection"
```

To disable requirements, retain at least one administrator and replace all
reviewer and check entries with `--data-urlencode 'clear=true'`. Each committed replacement
increments the policy epoch. Old-epoch approvals cannot satisfy the new policy.
The policy transaction itself does not move Git refs. Preserve every intended
check selector when replacing administrators or reviewers. The browser and
operator helpers retain configured selectors; the form remains an explicit
complete replacement, so omitted requirements are removed.
This also applies to the DSL component: include `ref_policy_frame_hex` from the
selected policy when retaining it while changing administrators or branch rules.
Omitting both DSL fields removes it. Source and frame inputs select the same
canonical snapshot; neither can grant administration or bypass current review
and workflow requirements. The policy can constrain native reference names,
scopes and creation/deletion/update shape. It cannot require a fact the node
does not authenticate for this profile.

## Receipts and recovery

Publication replies have `type: "review_protection_publication"`, schema
version 1, repository binding, authenticated `principal_id`, exact
`expected_version` and `expected_epoch`, stable `tx_id`, `outcome`,
decimal-string `decision_sequence`, and canonical commit or refusal identity.
`resulting_epoch` is a decimal string for a committed outcome and null for
a refusal. HTTP 200 means committed. HTTP 409 with `outcome: "refused"` is
a recorded canonical refusal. `delivery_acknowledged` remains null.

The native driver recovers the original terminal decision before checking
eligibility for a new publication. An identical command and original key can
recover a committed rotation after the actor loses canonical ownership or
after restart. HTTP still requires a current valid credential with
`protection-write`. A replacement token for the same principal preserves
transaction identity; revoked tokens are rejected. A semantically changed
command under an existing key is a conflict.

The independently granted bodyless `POST /api/v1/outcomes` accepts the original
key for the same principal without policy-write authority. It does not reexecute
the operation. Do not refresh predecessors or invent a new key while the
original outcome is unknown. A known canonical refusal remains refused after
later policy changes.

Adapter errors use `protection_error` without echoing credentials or raw keys.
Failure after entering native admission is conservatively `outcome_unknown`,
not proof of rollback. Publication responses describe the authenticated
historical decision without rereading current policy.

## Resource and browser boundaries

Forms are capped at 256 KiB decoded. The shared form reader retains its stricter
wire limit, further narrowed by configured HTTP limits; the adapter also caps
chunk count at 1,024. Replies are capped at 1 MiB and the configured response
ceiling. Policy reads share the expensive-read quota; replacements share the
mutation quota and writer gate. Authentication and independent grants precede
`100 Continue`. Existing owned blocking-child, socket deadline, cleanup and
bounded listener rules remain in force.

Only explicit Bearer authorization is accepted. A valid browser-cached Basic
token is refused. Shared Origin/Sec-Fetch-Site checks reject cross-site mutations
before routing. An external TLS terminator must have its exact allowed origin
configured through the existing service option.

Focused verification entrypoints (test presence is not a passing-gate claim):

```sh
cargo test --locked -p fgit-node --lib smart_http::server::protection
cargo test --locked -p fgit-node --lib smart_http::server::credentials
cargo test --locked -p fgit-node --test protection_http
cargo test --locked -p fgit-cli --bin fg smart_http_server::tests
```

The real-TCP suite uses the persisted authority store in both Git hash formats.
It covers remote bootstrap refusal, independent grants and deployment ceilings,
current-admin authorization, stale versions/epochs, rotation and disable,
identical retries after admin removal, changed-command conflict, token
revocation/rotation, independent outcomes, node restart, cross-site/Basic
rejection and chunked form acceptance.

Native execution remains pending. The development runner exhausted shared
memory while compiling unchanged Asupersync, then disk capacity, and its
execution service disconnected. The final HTTP sources were reconstructed and
reviewed through the GitHub API; no final-tree Rust compilation, runtime,
formatting or release gate is asserted here.
