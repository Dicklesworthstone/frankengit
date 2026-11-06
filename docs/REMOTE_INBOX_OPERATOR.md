# Remote issue and discussion inbox operator

`node scripts/forge_inbox.mjs` reads an authenticated principal's inbox and
publishes subscription, mute and read-prefix changes through the existing native
HTTP notification API. It supports both issue and discussion inboxes, retained
snapshot pagination, and recovery from a saved original request after an
interruption or a process restart. It does not need access to the server's
storage directory.

The operator uses the shipped `NotificationClient` and
`DiscussionNotificationClient`. Their existing form encoding, request-key
domains, credential binding, response checks and outcome lookup remain in
charge. The HTTP server authenticates the actor on every request. The
`expected-principal` and `expected-incarnation` options are equality guards;
they cannot select another recipient.

## Connection and private files

Use Node 22.16 or newer and an operator-controlled Unix filesystem with file and
directory synchronization. Prepare a private directory outside your worktree
for token files and request custody. Token and record files must be owned by
the current user, be regular files with one hard link, and grant no permissions
to group or other users. Records require an already existing private parent
directory. Symbolic-link record and token files refuse.

The token file contains exactly 64 lowercase hexadecimal characters, optionally
followed by one newline. Pass its path through `--token-file`; the CLI has no
token argument and does not put the token in the request record or output.
Custody records still contain private recipient identity and preference intent,
so keep them private after completion too.

Select the target kind and its exact UI URL explicitly:

| `--kind` | `--url` suffix | Required read scope |
| --- | --- | --- |
| `issue` | `/REPOSITORY_ROUTE/ui/notifications/` | `issues-read` |
| `discussion` | `/REPOSITORY_ROUTE/ui/discussion-notifications/` | `discussions-read` |

The corresponding native service must be enabled. Preference writes additionally
require `notifications-write`; status and retry outcome lookup require the
independent `outcomes-read` scope. Existing service grants and current
authorization apply to historical reads and retries too. The operator does not
provision credentials or expand their grants.

URLs require HTTPS except for explicit loopback HTTP. The exact canonical route
must have its trailing slash, with no credentials, query or fragment. Redirects
are refused, cookies are omitted, and requests use the project's
`frankengit-agent` User-Agent. `--tenant-id` and `--repository-id` are mandatory
32-character lowercase hexadecimal identities, checked against every observed
response and saved request.

## Read and paginate

The examples assume `TOKEN_FILE`, `TENANT` and `REPOSITORY` identify the intended
connection. Start with a current read to observe the principal, incarnation,
thread version and preference version:

```sh
node scripts/forge_inbox.mjs list \
  --kind issue --url https://forge.example/repo/ui/notifications/ \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --token-file "$TOKEN_FILE" --unread-only --limit 20 --max-pages 5

node scripts/forge_inbox.mjs show \
  --kind discussion --url https://forge.example/repo/ui/discussion-notifications/ \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --token-file "$TOKEN_FILE" --number 7
```

`list` defaults to one page of 20 rows. `--limit` accepts 1–100 and
`--max-pages` accepts 1–100. `--unread-only` filters unread threads;
`--include-muted` includes muted threads in the selected list. `show` reads one
exact number, including an existing thread outside the current inbox so that
the caller can subscribe to it. Canonical absence is a successful, complete read
with `found:false`; a generic HTTP 404 is not treated as a valid absence.

Output is one JSON object containing `pages`, identity, the selected
`snapshot_token`, `complete`, and `stop_reason`. A multi-page invocation fixes
its first snapshot for every later page. Activity that arrives while it runs
cannot silently move the remaining pages to a new source. The shipped client
checks row ordering, filters, target kind, unread arithmetic, source completeness
and response identity before the operator returns any result. The operator also
requires every page at that snapshot to retain the same authority generation,
forge-position root and outbox root.

When the page budget ends with more rows available, the command exits **4** and
returns `complete:false` with a `continuation`. Copy all its connection, target,
identity, head, cursor and filter fields into the next invocation. For example,
if it returned `after:42`, use its exact observed head and identity:

```sh
node scripts/forge_inbox.mjs list \
  --kind issue --url https://forge.example/repo/ui/notifications/ \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --token-file "$TOKEN_FILE" --after 42 --expected-head "$SNAPSHOT" \
  --expected-principal "$PRINCIPAL" --expected-incarnation "$INCARNATION" \
  --limit 20 --max-pages 5 --unread-only
```

Preserve `--include-muted` too when the original read selected it. A nonzero
cursor requires its original head. Any explicit historical head, including for
`show`, also requires both observed identity guards. That prevents the first
page of a resumed process from being rebound to a reassigned credential or a
recreated repository. An expired snapshot or identity mismatch refuses; it does
not restart pagination at the current head.

Reads have no custody record. `--max-output-bytes` bounds the entire returned
JSON object, from 1 through 8,388,608 bytes, defaulting to that maximum. Exceeding
this bound or failing a later page returns an error without emitting an
apparently complete prefix. The operator exports only validated inbox fields,
not arbitrary additional fields from a server response, and escapes terminal
control characters without changing the parsed string values.

## Change a preference

Every new mutation requires a new `--record` path, the exact observed preference
version, and both observed identity guards. The preference version is independent
of the issue or discussion version. Use `--expected-version 0` when the returned
`preference_version` is `null`.

| Operation | Change |
| --- | --- |
| `subscribe` | Set explicit subscribed mode; preserve the read prefix. |
| `mute` | Set muted mode; preserve the read prefix. |
| `automatic` | Restore automatic participation; preserve the read prefix. |
| `read` | Set precisely `--read-through` to the positive observed thread version. |
| `unread` | Clear the read prefix; preserve the mode. |

For example, after observing issue 7 at issue version 4 and preference version 2:

```sh
node scripts/forge_inbox.mjs read \
  --kind issue --url https://forge.example/repo/ui/notifications/ \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --token-file "$TOKEN_FILE" --number 7 --expected-version 2 \
  --expected-principal "$PRINCIPAL" --expected-incarnation "$INCARNATION" \
  --read-through 4 --record "$PRIVATE_DIR/issue-7-read-through-4.json"
```

The operator rechecks the current authenticated thread before preparing custody.
It refuses a missing thread, moved preference version, changed identity, or read
prefix beyond the observed thread version. It never replaces the supplied
preference version or read prefix with newly observed values. The server still
performs canonical admission after that check: a racing preference write can
produce a terminal refusal, while a new comment at thread version 5 remains
unread after a successful acknowledgement through version 4.

Issue 7 and discussion 7 have independent state and request-key domains. Changing
the URL or kind cannot reinterpret an issue request as a discussion preference.

## Durable request custody and recovery

Before sending a mutation, the operator exports the shipped client's token-free
receipt into a new file opened exclusively with mode `0600`. It synchronizes
the file, verifies its exact contents and identity, synchronizes its private
parent directory, and closes the descriptors before proceeding. Every sender,
including a later retry, independently rereads and synchronizes the exact record
and its parent. A readable record alone does not establish that a previous
process completed its durability barriers.

Retain this file after success, refusal or interruption. Its bytes include the
original form, key, kind, connection, recipient binding and credential
fingerprint. The operator never overwrites it or changes its request to resolve
a newer conflict. A partial, corrupt or substituted file refuses recovery and
must be investigated; do not replace it with a newly generated retry key.

```sh
node scripts/forge_inbox.mjs status \
  --kind issue --url https://forge.example/repo/ui/notifications/ \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --token-file "$TOKEN_FILE" --record "$PRIVATE_DIR/issue-7-read-through-4.json"

node scripts/forge_inbox.mjs retry \
  --kind issue --url https://forge.example/repo/ui/notifications/ \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --token-file "$TOKEN_FILE" --record "$PRIVATE_DIR/issue-7-read-through-4.json"
```

`status` only looks up the original principal-scoped outcome. It never submits a
preference mutation. `retry` observes that same outcome first. If it observes a
terminal commit or refusal, it reports it without resending. For a valid
nonterminal observation, it may send the exact saved request and key once after
its own durability barriers. Outcome lookup failure stops retry. Neither mode
accepts a new number, version, read prefix or identity guard.

A missing seal or key is **not proof of non-commit**. Cancellation, disconnection,
a killed process, and an invalid reply can all leave an uncertain remote result.
No automatic mutation retry occurs. Terminal recovery reports the original
decision even if a later preference has changed; it does not undo the later
change. Current authentication and recipient/incarnation binding still apply.
The shipped receipt profile requires the original credential fingerprint, so
credential rotation across unresolved custody remains unsupported.

The local SHA-256 record digest detects accidental substitution when compared
with a separately retained value. It is not a server signature, repository
authority, or protection against a party that can rewrite every local file.
This filesystem profile assumes control of the parent paths and does not claim
containment against a hostile process with the same user identity.

## Limits, exit codes and validation

`--timeout-ms` bounds the whole invocation, with a 30-second default and a
300-second maximum. Cancellation aborts outstanding HTTP work; it does not roll
back a server transaction. Synchronous work and blocking host filesystem calls
cannot be preempted. A fully parsed terminal observation wins over later
cancellation. If output fails after completion, the CLI reports failure and
preserves the original request record for recovery.

The existing JavaScript client accepts exact safe-integer coordinates only.
The operator refuses numbers outside that range instead of rounding native
unsigned 64-bit IDs, versions or cursors. Each response is bounded by the shipped
client; receipt exports are at most 512 KiB and private custody files at most
1 MiB. All argument and file bounds are checked before use.

| Exit | Meaning |
| --- | --- |
| `0` | Complete read, or an observed committed original transaction. |
| `3` | Observed terminal refusal. |
| `4` | Valid bounded read prefix with an explicit continuation. |
| `2` | Nonterminal/unknown outcome, interruption, or validation/transport/IO error. |

Run the focused operator suite with:

```sh
node --test tests/operator/forge-inbox.test.mjs
```

The suite exercises the production operator and shipped clients through real
loopback HTTP, private files, synchronization failures and fresh CLI processes.
It covers both namespaces, all five preference actions, snapshot and identity
drift, bounded reads, racing activity, original-key retry, a lost reply,
`SIGKILL` restart, malformed terminal replies, tampering, cancellation and
unsafe file permissions. Its HTTP authority is deliberately simulated; these
tests are not a native Rust server campaign or evidence that every platform's
storage durability profile has been qualified. See
[native notifications](NATIVE_NOTIFICATIONS.md) for the server protocol and
remaining notification functionality, including PR inboxes and external
notification delivery.

The discovered `scripts/e2e/suites/operator/remote_issue.sh` campaign also runs
the shipped inbox CLI against `fg serve-http`, with separate `fg inbox` reads
checking canonical preferences and source positions. Its issue-only cases cover
the five preference actions, older read prefixes with newer unread activity,
retained pagination, original-key recovery after later preferences, stale/owner
refusals, independent notification-write grant restoration, and a disabled native
issue service. The receipt binds each selected entrypoint's client and native
binary digests and actual successful/expected-nonzero invocation counts.
`./scripts/verify.sh operator` selects this campaign with its one native build and
pinned Node runtime. A direct campaign run against a retained binary qualifies
only that named producer, not the current source, discussion inboxes, crash
durability, independent verification or the complete operator matrix.
