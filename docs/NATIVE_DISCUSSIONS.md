# Native repository discussions

Discussions provide a repository conversation independent of issues and pull
requests. The native lifecycle supports opening, editing the title or body,
authored comments, closing/reopening, and locking/unlocking comments. Every
accepted action becomes a canonical event with its original actor and exact
text. Closing a discussion preserves comments and permits further replies
unless it is locked. Locking stops new comments while allowing maintenance.

The byte, version, authority and retry contract is specified in
[NORMATIVE_PROTOCOL_CONTRACTS.md §20.2.7](NORMATIVE_PROTOCOL_CONTRACTS.md#2027-native-standalone-discussions).
Discussion replies and subscriptions participate in a separate
[native notification inbox](NATIVE_NOTIFICATIONS.md#discussion-inboxes).
Categories, accepted answers and cross-repository migration remain outside this
lifecycle profile.

## Use the CLI

The examples operate on an existing native node. Set the storage root, tenant,
repository and operator principal to the values used when creating that node.
`--trusted-local` explicitly acknowledges operator-asserted local identity.

```bash
fg discussion open "$STORAGE" "$TENANT" "$REPOSITORY" 7 \
  --trusted-local --principal "$PRINCIPAL" \
  --idempotency-key discussion-7-open --expected-version 0 \
  --title 'How should we document upgrades?' --body-file question.md

fg discussion show "$STORAGE" "$TENANT" "$REPOSITORY" 7 --trusted-local

fg discussion comment "$STORAGE" "$TENANT" "$REPOSITORY" 7 \
  --trusted-local --principal "$PRINCIPAL" \
  --idempotency-key discussion-7-comment-1 --expected-version 1 \
  --body 'Keep a tested example for each supported upgrade path.'

fg discussion list "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local
```

Opening requires an unused positive discussion number and version zero. Strict
subsequent changes, including `comment`, require the exact version returned by
the read. If another writer changes that discussion first, the stale command
receives a canonical refusal. Read the current discussion before preparing a
new command with a new idempotency key. A discussion and an issue may have the
same number; their identities and state remain separate.

Use `append-comment` when a reply should survive another writer adding a comment
or editing the discussion first:

```bash
fg discussion append-comment "$STORAGE" "$TENANT" "$REPOSITORY" 7 \
  --trusted-local --principal "$PRINCIPAL" \
  --idempotency-key discussion-7-independent-reply \
  --body 'Include the recovery steps alongside the upgrade example.'
```

This command rejects `--expected-version`. It seals the original number, actor,
body and retry identity, then selects a current publication position. A race
revalidates the same intent; it cannot change the submitted text or create a
second comment. Current locks and permissions still apply, including a lock
published by a competing writer. A closed, unlocked discussion accepts replies.
The receipt reports `expected_version: null` and action `append-comment`; its
history entry is an ordinary comment with its actual accepted version. Keep
using strict `comment` when publication must depend on the version you read.

`edit` accepts either or both `--title` and `--body`/`--body-file`. Omitted
fields survive. `--body ''` explicitly clears the description. Comments must
contain non-whitespace text. Titles are bounded to 256 UTF-8 bytes and bodies
to 64 KiB; body files must be regular UTF-8 files within that bound. For a
SHA-256 node, include `--object-format sha256` on every command.

`list` and `show` accept `--limit 1..100`. Continue a list with its returned
`next_after` as `--after`, or history with `next_after_version` as
`--after-version`. Supply the same response's `snapshot_token` as
`--expected-head` whenever continuing. Later writes do not change that selected
history. Missing snapshots, gaps or resource exhaustion refuse instead of
returning an apparently complete partial conversation.

Exit codes are 0 for a read or committed command, 3 for a canonical refusal,
4 for a missing discussion, and 2 for an input, infrastructure or output error.

## HTTP and browser access

Enable the endpoint with `fg serve-http ... --allow-discussions`, using the
existing scoped `--credentials-file` profile. The readiness document includes
`discussions_enabled`. Discussion reads require `discussions-read`; mutations
require `discussions-write`. Neither scope implies the other. Existing Git,
issue, source and PR grants do not expose discussions. Credential files remain
bound to the exact repository incarnation and are reloaded per request.

| Operation | HTTP endpoint |
| --- | --- |
| List | `GET /{repository}/api/v1/discussions` |
| State and history | `GET /{repository}/api/v1/discussions/{number}` |
| Lifecycle or comment | `POST /{repository}/api/v1/discussions/{number}/{action}` |
| Browser | `GET /{repository}/ui/discussions/` |

Actions are `open`, `edit`, `comment`, `append-comment`, `close`, `reopen`, `lock`,
and `unlock`. POST bodies are bounded `application/x-www-form-urlencoded` forms.
Strict actions contain `expected_version` and only their applicable fields;
`append-comment` contains only `body` and rejects `expected_version`. Send the
original printable `Idempotency-Key` header and bearer token; callers cannot
override the authenticated actor. Reads support `after` or `after_version`,
`limit`, `expected_head`, and optional `render=html_safe` or `render=api_json`.

The browser lets you list and open discussions, read the authored history,
prepare edits or replies, and close/reopen or lock/unlock a conversation. It
captures the version you read for strict commands and previews the exact request
before sending. Its explicit Append comment action prepares a version-independent
reply; Comment retains the strict version requirement.
Titles and raw text remain inert. Optional Markdown presentations use the
existing bounded, allowlisted renderer and retain the original text.

For outcome recovery, also enable the existing outcome endpoint and grant
`outcomes-read`. In credential files, scopes must follow the canonical order
shown by `fg serve-http --help`; the discussion scopes follow the notification
scopes. For example, the subset containing outcome and discussion access is
`outcomes-read,discussions-read,discussions-write`.

## MCP access

`fg-mcp` enables reads with `--allow-discussions` and mutations with
`--allow-discussion-writes`, independently of the issue grants. Mutations use
the launch-bound principal. Discovery exposes the ten tools
`frankengit_discussion_list`, `show`, `open`, `edit`, `comment`, `append_comment`, `close`,
`reopen`, `lock`, and `unlock` under the same prefix.

Identifiers, versions and cursors use canonical decimal strings, retaining
the full native `u64` domain. An example comment call is:

```json
{
  "name": "frankengit_discussion_comment",
  "arguments": {
    "number": "7",
    "expected_version": "1",
    "idempotency_key": "discussion-7-comment-1",
    "body": "Keep a tested upgrade example."
  }
}
```

For a version-independent reply, select `frankengit_discussion_append_comment`
with `number`, `idempotency_key` and `body` only. The same independent
discussion-write grant is required; supplying `expected_version` refuses.

MCP pages retain the existing smaller adapter limits: default five rows,
maximum twenty. MCP text input is bounded to 16 KiB; native CLI and HTTP bodies
retain the 64 KiB canonical ceiling. Optional rendered output is derived from
the same exact text. Browser numbers are limited to exactly representable
JavaScript integers; use the CLI or MCP decimal-string interface for larger IDs.

## Recover an uncertain result

A lost connection does not establish whether publication happened. Retry the
identical command with the original key, or query `fg outcome` / the enabled
outcome API. A known committed or refused result remains the original result
after restart or later edits. Changing text, action, number or version while
reusing the key refuses; recovery never silently submits a different request.

The browser retains an unresolved request when disconnected. Save its recovery
receipt before closing the tab, then restore it using the same repository and
credential. A receipt contains the private draft and original retry identity,
not the bearer token. An absent or undecided outcome keeps the request pending.
Disconnect, credential expiry and page hiding clear displayed private editor
data while preserving that recovery request. The page requests a navigation
warning while a request remains unresolved; keep a saved receipt before leaving.
Receipt files are bounded UTF-8, decoded without replacement characters. A file
selected before disconnect or reconnect cannot restore into the later session.
Explicit retries resend the original bytes, and terminal replies are checked
against the discussion request family before clearing recovery responsibility.

## Verification coverage

The source includes native core, admission, node, HTTP and MCP regression tests
for lifecycle, exact predecessors, append replanning after real competing
publication, locked-comment refusals, both hash formats,
retained pagination, independent disclosure grants, restart and original-key
recovery. Browser tests cover response validation, safe display, captured
versions, disconnect races and immutable retry receipts. The discoverable
`scripts/e2e/suites/forge/discussions.sh` campaign drives a prebuilt `FG_BIN`
through fresh process boundaries in both hash formats; it never substitutes a
fixture authority or another Git implementation. These are runnable coverage
definitions, not a claim that every suite has executed on every revision.
