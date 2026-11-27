# Remote discussion operator

`node scripts/forge_discussions.mjs` exposes the native standalone discussion
lifecycle to remote terminal operators: open, edit, comment, append-comment,
close, reopen, lock and unlock. It also lists discussions, reads canonical
discussion history and recovers the outcome of an interrupted mutation.
The native HTTP service authenticates the actor and makes every decision.

The operator reuses the shipped browser `DiscussionClient` and the private-file
custody path used by the [issue operator](REMOTE_ISSUE_OPERATOR.md). It does not
open node storage, select a local principal or implement another mutation codec.
The native behavior is described in [NATIVE_DISCUSSIONS.md](NATIVE_DISCUSSIONS.md)
and [the normative discussion contract](NORMATIVE_PROTOCOL_CONTRACTS.md#2027-native-standalone-discussions).

## Connection and authority

Use the exact discussion UI URL, such as
`https://forge.example/team/project.git/ui/discussions/`, and the expected
32-character lowercase hexadecimal tenant and repository IDs. The client
derives the repository's authenticated API routes from that URL. HTTPS is
required except on loopback; redirects, URL credentials and URL normalization
are rejected.

The private token file contains the original 64-character lowercase hexadecimal
repository bearer token, optionally followed by one LF. Discussion reads require
the independent `discussions-read` grant; lifecycle mutations require
`discussions-write`; status and retry require the shared outcome-read grant.
Issue and PR grants do not supply discussion authority. The client currently
accepts repository tokens for discussions, not sponsored `fgagent` credentials.

Use the same token for recovery: records bind its fingerprint without containing
the token. This operator does not substitute a rotated credential. The service
checks current authority on each request, so a stored record does not bypass
revocation.

Token and body files must be owner-private, regular files with a single link.
The new recovery record's parent directory must already exist and be
owner-private. Symlinks, hard links, an existing destination and a destination
that is the token file are refused. This custody profile requires Unix file
ownership and permissions.

## Open and reply

Prepare the private directory, token and optional UTF-8 body file before running
these examples. Replace the example URL and IDs with the known repository
binding. Choose a fresh record path for each new intent and retain it afterward.

```bash
node scripts/forge_discussions.mjs open \
  --url https://forge.example/team/project.git/ui/discussions/ \
  --tenant-id 11111111111111111111111111111111 \
  --repository-id 22222222222222222222222222222222 \
  --token-file /srv/fg-operator/token \
  --record /srv/fg-operator/discussion-17-open.json \
  --number 17 --expected-version 0 \
  --title 'Release coordination' --body-file /srv/fg-operator/open.txt

node scripts/forge_discussions.mjs append-comment \
  --url https://forge.example/team/project.git/ui/discussions/ \
  --tenant-id 11111111111111111111111111111111 \
  --repository-id 22222222222222222222222222222222 \
  --token-file /srv/fg-operator/token \
  --record /srv/fg-operator/discussion-17-reply.json \
  --number 17 --body-file /srv/fg-operator/reply.txt
```

`open` requires `--expected-version 0`. `edit`, `comment`, `close`, `reopen`,
`lock` and `unlock` require the exact observed `--expected-version`. An edit
must supply a title or body. Strict commands preserve that predecessor through
recovery; a stale command never refreshes its version or silently changes mode.

`append-comment` is an explicit independent reply and rejects
`--expected-version`. It checks that the discussion exists before recording the
intent. The server may place it after concurrent edits or other replies while
retaining the original actor, literal body, command identity and key. Retrying
the same record cannot create a second comment. Two separately staged records
with the same text are two separate comment intents.

Closed, unlocked discussions accept comments. Locked discussions refuse strict
comments and appends while still permitting edits and state maintenance. The
operator never unlocks or reopens a discussion implicitly.

## Recover the original command

Before a mutation can reach the network, the operator exclusively creates,
syncs and reads back its token-free request record, then syncs the parent
directory. It verifies the expected repository and either the strict predecessor
or, for append, existence before staging that record. Each record retains the
exact request, original command key and credential fingerprint.

```bash
node scripts/forge_discussions.mjs status \
  --url https://forge.example/team/project.git/ui/discussions/ \
  --tenant-id 11111111111111111111111111111111 \
  --repository-id 22222222222222222222222222222222 \
  --token-file /srv/fg-operator/token \
  --record /srv/fg-operator/discussion-17-reply.json
```

`status` only observes the original command's outcome. `retry` performs that same
lookup first and may then submit the exact original request and key once if the
outcome remains unknown. Both take only connection options and the original
record: do not resupply the number, fields or predecessor. A missing outcome,
disconnect, deadline, revoked grant or failed stdout delivery does not establish
that the mutation did not commit. Preserve the record and recover it instead of
opening a new intent. Malformed, mismatched or cross-family receipts are refused.

SIGINT, SIGTERM and deadlines cancel owned network and output work. Cancellation
after record synchronization retains the same recoverable intent. Cancellation
after submission does not turn an uncertain publication into a refusal.

## Snapshot-pinned list and history

`list` reads discussion summaries. `show --number N` reads the discussion's
current state and canonical authored history at one immutable snapshot. Reads
need no recovery record and never submit a mutation.

```bash
node scripts/forge_discussions.mjs show \
  --url https://forge.example/team/project.git/ui/discussions/ \
  --tenant-id 11111111111111111111111111111111 \
  --repository-id 22222222222222222222222222222222 \
  --token-file /srv/fg-operator/token \
  --number 17 --limit 20 --max-pages 5
```

Reads default to one page of 20 entries. `--limit` accepts 1–100 and
`--max-pages` accepts 1–100. A bounded prefix returns `complete: false` and a
`continuation` carrying the original snapshot, next cursor, limit and discussion
number when applicable. Resume with its `--after` and `--expected-head`; a
nonzero cursor without a snapshot is refused. Concurrent later writes do not
change an existing snapshot traversal. A malformed later page, changed snapshot
or revoked grant fails the read instead of reporting its earlier prefix as
complete. A valid missing-discussion response is a complete empty read.

JSON output includes only fields validated by the native browser client. It
preserves original text while escaping terminal controls and bidirectional
formatting characters. Unknown server extensions and rendered HTML are omitted.
These are authenticated observations of the selected server, not independent
cryptographic authority proofs. For a complete bounded archive with preserved
bytes, use [the native discussion archive](NATIVE_DISCUSSION_ARCHIVE.md).

## Bounds and exit status

Titles are limited to 256 UTF-8 bytes and must be nonblank with no controls.
Bodies are limited to 65,536 UTF-8 bytes and cannot contain NUL; comment bodies
must be nonblank. Body files are decoded strictly as UTF-8 with literal text
preserved. `--body` and `--body-file` are mutually exclusive. The whole operation
deadline defaults to 30 seconds and accepts `--timeout-ms 1..300000`, including
file custody, HTTP requests and stdout delivery. `--max-output-bytes` bounds
read output to at most 8 MiB, including its envelope.

| Exit | Meaning |
| --- | --- |
| 0 | A committed terminal outcome, or a complete read. |
| 2 | An error or unresolved outcome; retain any synchronized record. |
| 3 | An observed native terminal refusal. |
| 4 | A valid bounded read prefix with a snapshot-pinned continuation. |

No operator command creates categories, accepted answers, cross-references,
migrations, labels or assignees. Those fields are outside this native discussion
profile. Unknown options and duplicate options are rejected before HTTP work.

## Focused validation

```bash
node --test tests/operator/forge-discussions.test.mjs \
  tests/operator/forge-discussions-read.test.mjs \
  tests/operator/forge-issues.test.mjs \
  tests/operator/forge-issues-read.test.mjs \
  tests/operator/forge_milestone_operator.test.mjs \
  tests/operator/sponsored_metadata_credentials.test.mjs
```

The discussion tests run the shipped browser client, real loopback HTTP sockets,
private filesystem custody and CLI subprocesses against an explicitly simulated
native authority. They exercise lifecycle, strict versus independent concurrency,
lost acknowledgments, exact-key recovery, locked and revoked refusals, credential
and repository mismatch, private files, deadlines, snapshot paging, malformed
tails and process exit status. This test class does not execute the Rust node or
replace the native discussion protocol suites.
