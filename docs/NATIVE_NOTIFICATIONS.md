# Native issue and discussion notifications

FrankenGit provides repository issue and discussion inboxes for an explicit principal, with
automatic participation, subscription, mute and read-prefix controls. The
browser, authenticated HTTP API, local `fg inbox` commands and MCP adapters use
the same canonical thread histories and principal-owned preference events.

Preferences are durable forge metadata. The inbox is a disposable projection of
one authenticated source snapshot. Rebuilding that projection cannot subscribe
someone, change a read cursor, edit an issue or publish a repository decision.
This profile covers issue and discussion notifications. Email delivery,
push delivery and PR notifications remain separate work.

## Discussion inboxes

Standalone discussions have the same subscription, mute, automatic participation,
read and unread controls as issues. The two thread namespaces are distinct:
issue 7 and discussion 7 have separate activity, preferences, read prefixes and
transaction seals for the same principal. Changing one never changes the other.

The discussion opener receives `author` and `participant` reasons. Commenters
receive `participant`; explicit followers receive `subscribed`. Discussion
metadata edits alone do not make their actor a participant. Discussions have no
assignee reason. Activity by another actor, including edits, lifecycle changes
and locks, can be unread. A principal's own activity never creates a notification
from another actor. Closing or locking does not discard subscriptions or read
state.

Select the namespace explicitly:

| Surface | Discussion selection |
| --- | --- |
| CLI | Add `--kind discussion` to any `fg inbox` command |
| MCP | Add `"kind":"discussion"` to any of the seven `frankengit_inbox_*` tools |
| Browser | Open `/{repository}/ui/discussion-notifications/` |
| HTTP list | `GET /api/v1/notifications/discussions` |
| HTTP thread | `GET /api/v1/notifications/discussions/{number}` |
| HTTP preference | `POST /api/v1/notifications/discussions/{number}/{action}` |

The actions are `subscribe`, `mute`, `automatic`, `read` and `unread`. Existing
issue routes and default CLI/MCP calls retain their issue-only behavior and
response fields. Discussion responses include `target_kind:"discussion"` and
use `discussion_version`; they never relabel that counter as `issue_version`.
HTTP response types are `discussion_notification_page`,
`discussion_notification_thread` and `discussion_notification_publication`.
CLI and MCP use `discussion_notification_inbox` for the list response.

HTTP discussion inboxes require the independently enabled discussion service
and `discussions-read`. Preference writes additionally require
`notifications-write`. They work when the issue service is disabled.
`issues-read`, `discussions-write`, or `notifications-write` alone cannot read
the discussion inbox. MCP similarly requires `--allow-discussions`, the
launch-bound principal and incarnation, plus `--allow-notification-writes` for
preferences. Every tool invocation checks its selected kind; discovering an
inbox tool through an issue grant does not authorize a discussion call.

For example, after observing discussion 7 at version 4 with no explicit
preference stream:

```sh
fg inbox read "$ROOT" "$TENANT" "$REPOSITORY" 7 \
  --kind discussion --trusted-local --principal "$PRINCIPAL" \
  --expected-incarnation "$INCARNATION" \
  --expected-version 0 --read-through 4 \
  --idempotency-key discussion-7-read-through-4
```

This acknowledges only the observed discussion prefix. A concurrent reply at
version 5 remains unread. Keep the original kind, number, preference version,
prefix, identity guards and key for recovery, including after a restart.

The discussion browser links to this inbox and provides unread/muted filters,
thread lookup, subscriptions, read acknowledgements and outcome recovery.
Actions capture the displayed discussion and preference versions. Interrupted
writes keep the exact original request for retry or receipt export; reconnecting
does not silently replace it. The discussion inbox uses its own retry-key digest
domain, `fgdn` prefix and receipt schema, so an issue receipt cannot be restored
as a discussion preference even when the number, action and form bytes coincide.
Receipt imports are bound to the connection that selected the file. Tokens stay
in memory, and repository titles are displayed as literal text.

Discussion preferences use required aggregate escape **12**,
`DiscussionNotificationPreference { principal, discussion }`, and canonical
stream `dnotify/{principal}/{discussion}`. They reuse notification payload kind
**23** and the existing sealed metadata admission path. The issue aggregate
escape **10** and its bytes remain unchanged. Readers must understand the new
required aggregate before accepting its canonical state. The complete derived
inbox marker also binds its thread kind; identical numeric IDs and authority
roots cannot make an issue projection stand in for a discussion projection.

## What appears in the inbox

The absent preference stream means automatic participation. Reasons are derived
from canonical issue state at the selected source:

| Reason | Selection rule |
| --- | --- |
| `author` | The principal opened the issue. |
| `participant` | The principal opened the issue or authored a comment. |
| `assignee` | The principal is assigned at the selected snapshot. |
| `subscribed` | The principal explicitly subscribed to the issue. |

Several reasons can describe one thread. For example, an issue's opener has
both author and participant reasons. The inbox still contains one row per issue.
Assignment is evaluated at the selected snapshot; it is not a permanent
subscription. Assignment and participation grant no additional repository access.

The three modes are `automatic`, `subscribed` and `muted` in the HTTP surface.
The canonical automatic mode is named `Participating`. Explicit subscription
selects a thread even without participation or assignment. Muting suppresses it
from the default list; `include_muted=true` includes it for inspection. Returning
to automatic removes the explicit subscription while preserving participation,
assignment and the independent read prefix.

An exact thread lookup also returns the implicit automatic preference for an
existing issue that is not currently in the caller's inbox. This lets a reader
subscribe by issue number. Missing issues return an explicit not-found result.
`unread_only=true` filters the already selected threads; it does not turn an
unrelated issue into a subscription.

## Read prefixes and exact preference versions

Each thread exposes its `issue_version` and independent `preference_version`.
The latter is `null` until this principal first changes a preference. Mutations
require `expected_version=0` for that absent stream, or the exact positive
preference version afterward. An issue comment advances the issue stream;
subscribing or marking read advances only the caller's preference stream.

`read` requires a positive `read_through` issue version. Admission refuses a
cursor beyond the current canonical issue version. The command marks precisely
the supplied prefix; it does not replace it with whatever version happens to be
current when the request arrives. For example:

1. A reader observes issue version 7 and preference version 2.
2. Another actor publishes a comment at issue version 8.
3. The reader submits `expected_version=2&read_through=7`.
4. A successful publication advances the preference to version 3. Activity at
   issue version 8 remains unread.

Unread state compares `latest_other_version` with `read_through`, using zero for
an absent cursor. The principal's own issue activity and preference changes do
not fabricate new activity from another actor. `unread` clears the read prefix;
it preserves the mode. Mode changes preserve the read prefix. An exact-version
conflict is a refusal, not an implicit merge of competing preference writes.

After an uncertain response, retain the original action, issue number, expected
preference version, read prefix, identity guards and idempotency key. Retry that
same request or use the ordinary principal-scoped outcome lookup. A recovered
terminal result describes the original decision even if newer issue or
preference events now exist. An outcome receipt does not acknowledge delivery to
an external recipient.

## Authenticated HTTP and browser

Routes are relative to the repository's existing HTTP route. Use the forge HTTP
entry point that enables issue APIs; the legacy Git-only HTTP entry point keeps
notification routes disabled.

| Method | Route | Result or action |
| --- | --- | --- |
| GET | `/api/v1/notifications` | The authenticated principal's inbox page |
| GET | `/api/v1/notifications/{number}` | Exact issue thread and caller preference |
| POST | `/api/v1/notifications/{number}/subscribe` | Set subscribed mode |
| POST | `/api/v1/notifications/{number}/mute` | Set muted mode |
| POST | `/api/v1/notifications/{number}/automatic` | Restore automatic participation |
| POST | `/api/v1/notifications/{number}/read` | Set the explicit observed read prefix |
| POST | `/api/v1/notifications/{number}/unread` | Clear the read prefix |

GET requires the existing `issues-read` credential scope. POST requires **both
`issues-read` and `notifications-write`**. `issues-write`, Git scopes, or
`notifications-write` alone do not satisfy that requirement. Outcome recovery
uses its independent `outcomes-read` scope. Current credential authorization is
checked on every request, including a retained-snapshot read or an identical
mutation retry.

Every POST uses `application/x-www-form-urlencoded`, an `Idempotency-Key` header,
and these mandatory fields:

| Field | Contract |
| --- | --- |
| `expected_version` | Exact preference predecessor; `0` means no stream yet. |
| `expected_principal` | The 32-hex principal returned by the authenticated read. |
| `expected_incarnation` | The 32-hex repository incarnation returned by that read. |
| `read_through` | Required only for `read`; the explicitly observed positive issue version. |

The principal and incarnation fields are equality guards. The actor still comes
from the authenticated credential; a form cannot choose another recipient. The
server compares both guards before canonical admission and refuses a mismatch
with `notification_identity_changed`. A saved request therefore cannot follow a
bearer that has been reassigned to another principal or a repository that has
been recreated under the same route. Missing, duplicate, unknown and
inapplicable fields refuse. Fields such as `principal` and `recipient` do not
provide an alternate actor-selection API.

For example, after reading this principal's thread and observing preference
version 2 and issue version 7:

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Idempotency-Key: issue-42-read-through-7' \
  --data-urlencode 'expected_version=2' \
  --data-urlencode "expected_principal=$PRINCIPAL" \
  --data-urlencode "expected_incarnation=$INCARNATION" \
  --data-urlencode 'read_through=7' \
  "$REPOSITORY_URL/api/v1/notifications/42/read"
```

The browser notification controls use the authenticated inbox identity and exact
observed versions for these same operations. A pending request belongs to that
original principal and incarnation; changing credentials is not permission to
rewrite or redispatch it as another user. Existing Origin, bearer credential,
body framing, cancellation and response-size rules continue to apply.

## Snapshot pages and source completeness

List queries accept `limit` (1–100, default 20), `after`, `expected_head`,
`unread_only` and `include_muted`. Rows are ordered by numeric issue number.
Follow `next_after` using the original `snapshot_token` as `expected_head` and
retain the same filter choices. A nonzero `after` without a snapshot token
refuses. Exact thread reads also accept `expected_head`.

The token selects an authenticated retained ancestor permitted by the current
configuration, policy and retention epoch. Intervening comments, new issues or
preference changes do not silently change that page's source. A requested source
that is unavailable or outside those retained-snapshot rules refuses with
`snapshot_moved`; it is not replaced by a fresh page. A token never supplies
another principal's identity or bypasses current disclosure grants.

Responses name the principal and repository incarnation, selected authority
head, authority generation, forge-position root and outbox root. Their
`source_positions.complete=true` means that the bounded source was fully
reconstructed at **that selected head**. It does not assert that the selected
head is still the latest head after another writer publishes. Read current state
explicitly when preparing a new action.

HTTP IDs and versions use integer tokens; clients must preserve full unsigned
64-bit precision. MCP issue numbers, versions and continuation positions use
decimal strings; its page `limit` is a bounded JSON integer from 1 through 100.
Do not round a version or continuation number through a lossy floating-point
representation. The browser currently accepts only exactly representable
JavaScript safe integers and refuses larger numeric IDs or versions.

## Local CLI and MCP parity

The local operator interface is `fg inbox list|show|subscribe|mute|automatic|read|unread`.
Every invocation requires `--trusted-local --principal <principal-id>`; the
principal is an explicit operator assertion, not a remote login mechanism.
`--expected-incarnation` can pin the local repository, and
`--object-format sha256` selects a SHA-256 repository.

```sh
fg inbox list "$ROOT" "$TENANT" "$REPOSITORY" \
  --trusted-local --principal "$PRINCIPAL" \
  --expected-incarnation "$INCARNATION" --limit 20 --unread-only

fg inbox show "$ROOT" "$TENANT" "$REPOSITORY" 42 \
  --trusted-local --principal "$PRINCIPAL" \
  --expected-incarnation "$INCARNATION"

fg inbox subscribe "$ROOT" "$TENANT" "$REPOSITORY" 42 \
  --trusted-local --principal "$PRINCIPAL" \
  --expected-incarnation "$INCARNATION" \
  --expected-version 0 --idempotency-key issue-42-subscribe

fg inbox read "$ROOT" "$TENANT" "$REPOSITORY" 42 \
  --trusted-local --principal "$PRINCIPAL" \
  --expected-incarnation "$INCARNATION" \
  --expected-version 1 --read-through 7 \
  --idempotency-key issue-42-read-through-7
```

Use the observed versions for the actual repository. List supports `--after`,
`--limit`, `--expected-head`, `--unread-only` and `--include-muted`; show supports
the selected snapshot. Mutations preserve the same exact preference-version and
original-key recovery semantics as HTTP. They do not edit issue content.

MCP exposes `frankengit_inbox_list`, `frankengit_inbox_show`,
`frankengit_inbox_subscribe`, `frankengit_inbox_mute`,
`frankengit_inbox_automatic`, `frankengit_inbox_read` and
`frankengit_inbox_unread`. Reads require the issue-read launch grant
`--allow-issues` and the launch-bound principal/incarnation. Preference writes
add the independent `--allow-notification-writes` grant; issue-write permission
does not imply it. Outcome recovery remains independently granted. Tool
arguments cannot select a recipient or widen the process's launch grants.

## Canonical durability, projection and privacy

The canonical preference aggregate is kind 10,
`NotificationPreference { principal, issue }`, with stream label
`notify/{principal}/{issue}`. Event kind 23 records the native actor and either a
mode change or an explicit optional read cursor. Canonical admission binds that
actor to the same principal, validates the exact predecessor and existing issue,
and publishes through the ordinary immutable seal and authority-head CAS. Old
formats retain their encodings; readers that do not support these required new
kinds must refuse them.

Inbox reads use an actual request-owned, in-memory FrankenSQLite/sqlmodel
session. Installation places the complete typed rows and source marker in one
transaction. Page reads verify that marker and rows in one transaction, and
display fields are hydrated from the same verified source. The binding contains
tenant, repository, incarnation, selected head/generation, forge root, outbox
root, principal and thread kind. The request awaits session close, including failure paths.
There is no independent persistent inbox database to become a second authority.
Restart recovery comes from canonical events, not a retained mutable projection.

Source construction is deliberately bounded:

| Resource | Current ceiling |
| --- | --- |
| Complete selected-kind repository threads / projection rows | 16,384 |
| Scanned events across unique canonical batches | 65,536 |
| Verified batch frames scanned | 128 MiB |
| Retained event bytes | 32 MiB |
| Returned rows per page | 100 |

Exceeding a complete-source bound refuses the read; it does not report a partial
inbox as complete. Smaller page sizes limit output but do not turn the current
implementation into an incremental background index. Request cancellation and
the existing adapter output/body budgets remain independent limits.

Recipient preferences are excluded from the scoped shared issue/PR event feed,
even when both event-family read grants are present. Repository webhooks refuse
a batch containing a private preference event, including wildcard subscriptions
and exact `kind:23` selectors. They do not remove private entries while claiming
to deliver the original immutable batch root. Existing public issue and PR
event delivery remains governed by its own subscription and disclosure rules.

## Validation scope and remaining work

Checked-in tests cover native event identity and source reconstruction,
projection bindings and filters, exact preference versions, later unread
activity, HTTP scopes and identity guards, stable retries, retained pagination,
credential rotation and reopened canonical state. Discussion cases additionally
cover same-number issue/discussion isolation, target-bound keys, independent
grants and operation with the issue service disabled. Privacy regressions cover the
shared event feed and every webhook filter family, with permitted public-event
twins. Browser tests exercise the request and recovery contract separately.

These tests are not all executed results. Native node/HTTP/projection runtime
tests were not executed in this development environment because full Asupersync
code generation exceeds its memory limit; compilation metadata checks and
separately executable adapter tests do not substitute for those runtime cases.
Use revision-bound validation reports for the exact checks that ran. This slice
does not close the broader notification work or claim email delivery, PR inboxes,
background delivery workers, or measured large-repository inbox performance.
